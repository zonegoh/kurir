//! One connection type per protocol behind a common set of file operations.

use crate::model::{Auth, Bookmark, Protocol};
use crate::store::Store;
use serde::Serialize;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

type R<T> = Result<T, String>;

fn err<E: std::fmt::Display>(ctx: &'static str) -> impl Fn(E) -> String {
    move |e| format!("{ctx}: {}", friendly(&e.to_string()))
}

fn between<'a>(s: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = s.find(open)? + open.len();
    Some(&s[start..start + s[start..].find(close)?])
}

/// Turns raw S3 XML error bodies into "Code: message" plus a hint.
fn friendly(raw: &str) -> String {
    let Some(code) = between(raw, "<Code>", "</Code>") else { return raw.to_string() };
    let message = between(raw, "<Message>", "</Message>").unwrap_or("");
    let hint = match code {
        "SignatureDoesNotMatch" => "Check the Secret Access Key (no extra spaces) and the Region in the bookmark.",
        "InvalidAccessKeyId" => "The Access Key ID is not known to this server.",
        "AccessDenied" => "This key has no permission for this action or bucket.",
        "NoSuchBucket" => "The bucket does not exist (check the name and endpoint).",
        "AuthorizationHeaderMalformed" => "The Region in the bookmark is probably wrong.",
        _ => "",
    };
    format!("{code} — {message}{}", if hint.is_empty() { String::new() } else { format!("\n\n{hint}") })
}

#[derive(Serialize, Clone, Debug)]
pub struct Entry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    /// Unix seconds
    pub modified: Option<i64>,
    /// Unix permission bits (SFTP only)
    pub perms: Option<u32>,
}

pub enum Conn {
    Sftp { _session: ssh2::Session, sftp: ssh2::Sftp },
    Ftp(suppaftp::NativeTlsFtpStream),
    S3 { region: s3::Region, creds: s3::creds::Credentials },
}

pub struct Connected {
    pub conn: Conn,
    pub home: String,
    pub notice: Option<String>,
}

pub fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') { format!("{dir}{name}") } else { format!("{dir}/{name}") }
}

fn tcp(host: &str, port: u16) -> R<TcpStream> {
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(err("DNS lookup failed"))?
        .next()
        .ok_or("Host not found")?;
    let s = TcpStream::connect_timeout(&addr, Duration::from_secs(15)).map_err(err("Connect failed"))?;
    s.set_read_timeout(Some(Duration::from_secs(60))).ok();
    Ok(s)
}

pub fn connect(b: &Bookmark, password: &str, store: &Store) -> R<Connected> {
    match b.protocol {
        Protocol::Sftp => connect_sftp(b, password, store),
        Protocol::Ftp | Protocol::Ftps | Protocol::Ftpes => connect_ftp(b, password),
        Protocol::S3 => connect_s3(b, password),
    }
}

fn connect_sftp(b: &Bookmark, password: &str, store: &Store) -> R<Connected> {
    let mut sess = ssh2::Session::new().map_err(err("SSH"))?;
    sess.set_tcp_stream(tcp(&b.host, b.port)?);
    sess.set_timeout(60_000);
    sess.handshake().map_err(err("SSH handshake failed"))?;

    let hash = sess.host_key_hash(ssh2::HashType::Sha256).ok_or("Server sent no host key")?;
    let fp = format!("SHA256:{}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, hash));
    let new_key = store.check_host_key(&format!("{}:{}", b.host, b.port), &fp)?;

    let user = if b.username.is_empty() { "root" } else { &b.username };
    match b.auth {
        Auth::Key => {
            let key = expand_home(&b.key_path);
            let pass = (!password.is_empty()).then_some(password);
            let text = std::fs::read(&key)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .map_err(|e| format!("Cannot read private key {key}: {e}"))?;
            if crate::ppk::is_ppk(&text) {
                // libssh2 can't read PuTTY keys: convert to OpenSSH in memory.
                let pem = crate::ppk::to_openssh(&text, password)?;
                sess.userauth_pubkey_memory(user, None, &pem, None)
                    .map_err(err("Key authentication failed"))?;
            } else {
                sess.userauth_pubkey_file(user, None, Path::new(&key), pass)
                    .map_err(err("Key authentication failed"))?;
            }
        }
        _ => {
            if password.is_empty() {
                // No password given: try the running ssh-agent.
                sess.userauth_agent(user).map_err(err("Agent authentication failed"))?;
            } else {
                sess.userauth_password(user, password).map_err(err("Password authentication failed"))?;
            }
        }
    }
    let sftp = sess.sftp().map_err(err("SFTP subsystem"))?;
    let home = if b.remote_path.is_empty() {
        sftp.realpath(Path::new(".")).map(|p| p.to_string_lossy().into_owned()).unwrap_or("/".into())
    } else {
        b.remote_path.clone()
    };
    Ok(Connected {
        conn: Conn::Sftp { _session: sess, sftp },
        home,
        notice: new_key.then(|| format!("New host key trusted for {}: {fp}", b.host)),
    })
}

fn connect_ftp(b: &Bookmark, password: &str) -> R<Connected> {
    use suppaftp::native_tls::TlsConnector;
    use suppaftp::{NativeTlsConnector, NativeTlsFtpStream};
    let addr = format!("{}:{}", b.host, b.port);
    let tls = || -> R<NativeTlsConnector> {
        Ok(NativeTlsConnector::from(TlsConnector::new().map_err(err("TLS"))?))
    };
    let mut ftp = match b.protocol {
        Protocol::Ftps => NativeTlsFtpStream::connect_secure_implicit(&addr, tls()?, &b.host)
            .map_err(err("FTPS (implicit) connect failed"))?,
        Protocol::Ftpes => NativeTlsFtpStream::connect(&addr)
            .map_err(err("FTP connect failed"))?
            .into_secure(tls()?, &b.host)
            .map_err(err("AUTH TLS failed"))?,
        _ => NativeTlsFtpStream::connect(&addr).map_err(err("FTP connect failed"))?,
    };
    let (user, pass) = match b.auth {
        Auth::Anonymous => ("anonymous", "kurir@"),
        _ => (b.username.as_str(), password),
    };
    ftp.login(user, pass).map_err(err("FTP login failed"))?;
    ftp.transfer_type(suppaftp::types::FileType::Binary).map_err(err("FTP"))?;
    let home = if b.remote_path.is_empty() { ftp.pwd().unwrap_or("/".into()) } else { b.remote_path.clone() };
    Ok(Connected { conn: Conn::Ftp(ftp), home, notice: None })
}

fn connect_s3(b: &Bookmark, secret: &str) -> R<Connected> {
    let region_name = if b.region.is_empty() { "us-east-1".to_string() } else { b.region.clone() };
    // A host given with a scheme (e.g. http://localhost:9000 for MinIO) is used verbatim.
    let endpoint = if b.host.starts_with("http://") || b.host.starts_with("https://") {
        b.host.trim_end_matches('/').to_string()
    } else if b.port == 443 || b.port == 0 {
        format!("https://{}", b.host)
    } else {
        format!("https://{}:{}", b.host, b.port)
    };
    let region = s3::Region::Custom { region: region_name, endpoint };
    // Pasted keys often carry stray whitespace, which breaks the signature.
    let creds = s3::creds::Credentials::new(Some(b.username.trim()), Some(secret.trim()), None, None, None)
        .map_err(err("S3 credentials"))?;
    let conn = Conn::S3 { region, creds };
    let home = if b.remote_path.is_empty() { "/".into() } else { b.remote_path.clone() };
    Ok(Connected { conn, home, notice: None })
}

fn expand_home(p: &str) -> String {
    match (p.strip_prefix("~/"), dirs::home_dir()) {
        (Some(rest), Some(h)) => h.join(rest).to_string_lossy().into_owned(),
        _ => p.to_string(),
    }
}

/// "/bucket/a/b" -> ("bucket", "a/b")
fn s3_split(path: &str) -> (String, String) {
    let t = path.trim_start_matches('/');
    match t.split_once('/') {
        Some((b, k)) => (b.to_string(), k.to_string()),
        None => (t.to_string(), String::new()),
    }
}

impl Conn {
    fn bucket(&self, name: &str) -> R<Box<s3::Bucket>> {
        let Conn::S3 { region, creds } = self else { unreachable!() };
        if name.is_empty() {
            return Err("Choose a bucket first".into());
        }
        Ok(s3::Bucket::new(name, region.clone(), creds.clone()).map_err(err("S3"))?.with_path_style())
    }

    pub fn list(&mut self, path: &str) -> R<Vec<Entry>> {
        let mut out = match self {
            Conn::Sftp { sftp, .. } => sftp
                .readdir(Path::new(path))
                .map_err(err("List failed"))?
                .into_iter()
                .map(|(p, st)| Entry {
                    name: p.file_name().unwrap_or_default().to_string_lossy().into_owned(),
                    is_dir: st.is_dir(),
                    size: st.size.unwrap_or(0),
                    modified: st.mtime.map(|m| m as i64),
                    perms: st.perm.map(|p| p & 0o7777),
                })
                .collect(),
            Conn::Ftp(ftp) => ftp
                .list(Some(path))
                .map_err(err("List failed"))?
                .iter()
                .filter_map(|line| suppaftp::list::File::try_from(line.as_str()).ok())
                .map(|f| Entry {
                    name: f.name().to_string(),
                    is_dir: f.is_directory(),
                    size: f.size() as u64,
                    modified: f.modified().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs() as i64),
                    perms: None,
                })
                .collect(),
            Conn::S3 { region, creds } => {
                let (bucket, key) = s3_split(path);
                if bucket.is_empty() {
                    let resp = s3::Bucket::list_buckets(region.clone(), creds.clone()).map_err(err("List buckets failed"))?;
                    resp.bucket_names()
                        .map(|name| Entry { name, is_dir: true, size: 0, modified: None, perms: None })
                        .collect()
                } else {
                    let prefix = if key.is_empty() { String::new() } else { format!("{}/", key.trim_end_matches('/')) };
                    let mut v = Vec::new();
                    for page in self.bucket(&bucket)?.list(prefix.clone(), Some("/".into())).map_err(err("List failed"))? {
                        for cp in page.common_prefixes.unwrap_or_default() {
                            let name = cp.prefix[prefix.len()..].trim_end_matches('/').to_string();
                            v.push(Entry { name, is_dir: true, size: 0, modified: None, perms: None });
                        }
                        for o in page.contents {
                            let name = o.key[prefix.len()..].to_string();
                            if name.is_empty() {
                                continue; // the folder marker itself
                            }
                            v.push(Entry { name, is_dir: false, size: o.size, modified: None, perms: None });
                        }
                    }
                    v
                }
            }
        };
        out.retain(|e| e.name != "." && e.name != "..");
        out.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        Ok(out)
    }

    pub fn get(&mut self, remote: &str, local: &Path) -> R<()> {
        let mut file = File::create(local).map_err(err("Create local file"))?;
        match self {
            Conn::Sftp { sftp, .. } => {
                let mut r = sftp.open(Path::new(remote)).map_err(err("Open remote file"))?;
                std::io::copy(&mut r, &mut file).map_err(err("Download"))?;
            }
            Conn::Ftp(ftp) => {
                ftp.retr(remote, |r| {
                    std::io::copy(r, &mut file).map_err(suppaftp::FtpError::ConnectionError)
                })
                .map_err(err("Download"))?;
            }
            Conn::S3 { .. } => {
                let (bucket, key) = s3_split(remote);
                self.bucket(&bucket)?.get_object_to_writer(&key, &mut file).map_err(err("Download"))?;
            }
        }
        file.flush().map_err(err("Write"))
    }

    pub fn put(&mut self, local: &Path, remote: &str) -> R<()> {
        let mut file = File::open(local).map_err(err("Open local file"))?;
        match self {
            Conn::Sftp { sftp, .. } => {
                let mut w = sftp.create(Path::new(remote)).map_err(err("Create remote file"))?;
                std::io::copy(&mut file, &mut w).map_err(err("Upload"))?;
            }
            Conn::Ftp(ftp) => {
                ftp.put_file(remote, &mut file).map_err(err("Upload"))?;
            }
            Conn::S3 { .. } => {
                let (bucket, key) = s3_split(remote);
                if key.is_empty() {
                    return Err("Open a bucket before uploading".into());
                }
                let mut buf = Vec::new();
                file.read_to_end(&mut buf).map_err(err("Read"))?;
                self.bucket(&bucket)?.put_object(&key, &buf).map_err(err("Upload"))?;
            }
        }
        Ok(())
    }

    pub fn mkdir(&mut self, path: &str) -> R<()> {
        match self {
            Conn::Sftp { sftp, .. } => sftp.mkdir(Path::new(path), 0o755).map_err(err("Create folder")),
            Conn::Ftp(ftp) => ftp.mkdir(path).map_err(err("Create folder")),
            Conn::S3 { .. } => {
                let (bucket, key) = s3_split(path);
                if key.is_empty() {
                    return Err("Creating buckets is not supported — create it in your provider's console".into());
                }
                self.bucket(&bucket)?.put_object(format!("{}/", key.trim_end_matches('/')), &[]).map(|_| ()).map_err(err("Create folder"))
            }
        }
    }

    pub fn remove_file(&mut self, path: &str) -> R<()> {
        match self {
            Conn::Sftp { sftp, .. } => sftp.unlink(Path::new(path)).map_err(err("Delete")),
            Conn::Ftp(ftp) => ftp.rm(path).map_err(err("Delete")),
            Conn::S3 { .. } => {
                let (bucket, key) = s3_split(path);
                self.bucket(&bucket)?.delete_object(&key).map(|_| ()).map_err(err("Delete"))
            }
        }
    }

    /// Removes an (already emptied) directory.
    pub fn remove_dir(&mut self, path: &str) -> R<()> {
        match self {
            Conn::Sftp { sftp, .. } => sftp.rmdir(Path::new(path)).map_err(err("Delete folder")),
            Conn::Ftp(ftp) => ftp.rmdir(path).map_err(err("Delete folder")),
            Conn::S3 { .. } => {
                let (bucket, key) = s3_split(path);
                if key.is_empty() {
                    return Err("Deleting buckets is not supported".into());
                }
                // Folder markers are optional in S3; ignore failures.
                let _ = self.bucket(&bucket)?.delete_object(format!("{}/", key.trim_end_matches('/')));
                Ok(())
            }
        }
    }

    pub fn rename(&mut self, from: &str, to: &str) -> R<()> {
        match self {
            Conn::Sftp { sftp, .. } => sftp.rename(Path::new(from), Path::new(to), None).map_err(err("Rename")),
            Conn::Ftp(ftp) => ftp.rename(from, to).map_err(err("Rename")),
            Conn::S3 { .. } => {
                let ((b1, k1), (b2, k2)) = (s3_split(from), s3_split(to));
                if b1 != b2 || k1.is_empty() {
                    return Err("S3 can only rename files inside one bucket".into());
                }
                let bucket = self.bucket(&b1)?;
                bucket.copy_object_internal(&k1, &k2).map_err(err("Rename (copy)"))?;
                bucket.delete_object(&k1).map(|_| ()).map_err(err("Rename (delete)"))
            }
        }
    }

    pub fn chmod(&mut self, path: &str, mode: u32) -> R<()> {
        match self {
            Conn::Sftp { sftp, .. } => sftp
                .setstat(Path::new(path), ssh2::FileStat { size: None, uid: None, gid: None, perm: Some(mode), atime: None, mtime: None })
                .map_err(err("Change permissions")),
            Conn::Ftp(ftp) => ftp.site(format!("CHMOD {mode:o} {path}")).map(|_| ()).map_err(err("Change permissions")),
            Conn::S3 { .. } => Err("S3 has no file permissions".into()),
        }
    }

    pub fn close(self) {
        match self {
            Conn::Sftp { _session, .. } => {
                let _ = _session.disconnect(None, "bye", None);
            }
            Conn::Ftp(mut ftp) => {
                let _ = ftp.quit();
            }
            Conn::S3 { .. } => {}
        }
    }

    // ---- recursive helpers -------------------------------------------------

    pub fn download_tree(&mut self, remote: &str, is_dir: bool, local_dir: &Path) -> R<usize> {
        let name = remote.trim_end_matches('/').rsplit('/').next().unwrap_or("download");
        let target = local_dir.join(name);
        if !is_dir {
            self.get(remote, &target)?;
            return Ok(1);
        }
        std::fs::create_dir_all(&target).map_err(err("Create local folder"))?;
        let mut n = 0;
        for e in self.list(remote)? {
            n += self.download_tree(&join(remote, &e.name), e.is_dir, &target)?;
        }
        Ok(n)
    }

    pub fn upload_tree(&mut self, local: &Path, remote_dir: &str) -> R<usize> {
        let name = local.file_name().ok_or("Invalid local path")?.to_string_lossy().into_owned();
        let target = join(remote_dir, &name);
        if !local.is_dir() {
            self.put(local, &target)?;
            return Ok(1);
        }
        // Ignore "already exists".
        let _ = self.mkdir(&target);
        let mut n = 0;
        for e in std::fs::read_dir(local).map_err(err("Read local folder"))? {
            let p = e.map_err(err("Read local folder"))?.path();
            n += self.upload_tree(&p, &target)?;
        }
        Ok(n)
    }

    pub fn remove_tree(&mut self, path: &str, is_dir: bool) -> R<()> {
        if !is_dir {
            return self.remove_file(path);
        }
        for e in self.list(path)? {
            self.remove_tree(&join(path, &e.name), e.is_dir)?;
        }
        self.remove_dir(path)
    }
}

#[cfg(test)]
mod live {
    //! Needs local test servers; see README "Testing". Run with: cargo test live -- --ignored --test-threads=1
    use super::*;

    fn roundtrip(b: &Bookmark, pw: &str, base: &str) {
        let dir = std::env::temp_dir().join(format!("kurir-live-{:?}", b.protocol));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("up/sub")).unwrap();
        std::fs::write(dir.join("up/a.txt"), b"hello").unwrap();
        std::fs::write(dir.join("up/sub/b.bin"), vec![7u8; 300_000]).unwrap();
        let store = Store::new(dir.join("store"));
        let mut c = connect(b, pw, &store).expect("connect").conn;
        assert_eq!(c.upload_tree(&dir.join("up"), base).expect("upload"), 2);
        let listed = c.list(&join(base, "up")).expect("list");
        assert_eq!(listed.iter().map(|e| (e.name.as_str(), e.is_dir)).collect::<Vec<_>>(), vec![("sub", true), ("a.txt", false)]);
        c.rename(&join(base, "up/a.txt"), &join(base, "up/c.txt")).expect("rename");
        std::fs::create_dir_all(dir.join("down")).unwrap();
        assert_eq!(c.download_tree(&join(base, "up"), true, &dir.join("down")).expect("download"), 2);
        assert_eq!(std::fs::read(dir.join("down/up/c.txt")).unwrap(), b"hello");
        assert_eq!(std::fs::read(dir.join("down/up/sub/b.bin")).unwrap().len(), 300_000);
        c.remove_tree(&join(base, "up"), true).expect("remove");
        assert!(c.list(base).unwrap().iter().all(|e| e.name != "up"));
        c.close();
    }

    fn bm(p: Protocol, host: &str, port: u16, user: &str) -> Bookmark {
        Bookmark { host: host.into(), port, username: user.into(), ..Bookmark::new(p) }
    }

    #[test]
    #[ignore]
    fn sftp() {
        roundtrip(&bm(Protocol::Sftp, "127.0.0.1", 2222, "test"), "test", ".");
    }

    #[test]
    #[ignore]
    fn ftp() {
        roundtrip(&bm(Protocol::Ftp, "127.0.0.1", 2121, "test"), "test", "/");
    }

    #[test]
    #[ignore]
    fn s3() {
        let b = bm(Protocol::S3, "http://127.0.0.1:5055", 443, "AKIDTEST");
        let store = Store::new(std::env::temp_dir().join("kurir-live-s3store"));
        let Conn::S3 { region, creds } = connect(&b, "secret", &store).unwrap().conn else { panic!() };
        let _ = s3::Bucket::create_with_path_style("testbucket", region, creds, s3::BucketConfiguration::default());
        let mut c = connect(&b, "secret", &store).unwrap().conn;
        assert!(c.put(Path::new("Cargo.toml"), "/no-such-bucket/x").is_err(), "S3 errors must not be swallowed");
        roundtrip(&b, "secret", "/testbucket");
    }

    /// Server that validates SigV4 (moto with INITIAL_NO_AUTH_ACTION_COUNT); creds via env.
    #[test]
    #[ignore]
    fn s3_signed() {
        let (Ok(key), Ok(secret)) = (std::env::var("KURIR_S3_KEY"), std::env::var("KURIR_S3_SECRET")) else { return };
        let b = bm(Protocol::S3, "http://127.0.0.1:5056", 443, &key);
        let store = Store::new(std::env::temp_dir().join("kurir-live-s3signed"));
        let mut c = connect(&b, &secret, &store).expect("connect").conn;
        let buckets = c.list("/").expect("list buckets");
        assert!(buckets.iter().any(|e| e.name == "authbucket"), "{buckets:?}");
        let tmp = std::env::temp_dir().join("kurir signed (1) & x+y.txt");
        std::fs::write(&tmp, b"signed").unwrap();
        c.mkdir("/authbucket/my folder").expect("mkdir");
        assert_eq!(c.upload_tree(&tmp, "/authbucket/my folder").expect("upload"), 1);
        let names: Vec<String> = c.list("/authbucket/my folder").expect("list").into_iter().map(|e| e.name).collect();
        assert_eq!(names, vec!["kurir signed (1) & x+y.txt"]);
        c.rename("/authbucket/my folder/kurir signed (1) & x+y.txt", "/authbucket/my folder/b c.txt").expect("rename");
        c.remove_tree("/authbucket/my folder", true).expect("remove");
        let wrong = connect(&b, "wrong-secret", &store).unwrap().conn.list("/").unwrap_err();
        println!("wrong secret error: {wrong}");
    }

    /// Strict server accepting only <dir>/*.pub keys on 127.0.0.1:2223; see README "Testing".
    #[test]
    #[ignore]
    fn sftp_ppk_keys() {
        let Ok(dir) = std::env::var("KURIR_PPK_DIR") else { return };
        let pass = std::fs::read_to_string(format!("{dir}/pass")).unwrap();
        let store = Store::new(std::env::temp_dir().join("kurir-live-ppk"));
        let mut n = 0;
        for e in std::fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_none_or(|x| x != "ppk") {
                continue;
            }
            let mut b = bm(Protocol::Sftp, "127.0.0.1", 2223, "test");
            b.auth = Auth::Key;
            b.key_path = p.to_string_lossy().into_owned();
            let pw = if b.key_path.contains("-enc") { pass.as_str() } else { "" };
            let mut c = connect(&b, pw, &store).unwrap_or_else(|e| panic!("{}: {e}", b.key_path)).conn;
            c.list(".").expect("list");
            c.close();
            n += 1;
        }
        assert_eq!(n, 16);
        if let Ok(stranger) = std::env::var("KURIR_STRANGER_KEY") {
            let mut b = bm(Protocol::Sftp, "127.0.0.1", 2223, "test");
            b.auth = Auth::Key;
            b.key_path = stranger;
            assert!(connect(&b, "", &store).is_err(), "server must reject unknown keys");
        }
    }
}
