//! WinSCP `WinSCP.ini` (Tools → Export/Backup Configuration, or the portable ini).
//!
//! Sessions live in `[Sessions\Folder/Name]` sections, names URL-encoded.
//! FSProtocol: 0 SCP, 1 SFTP only, 2 SFTP (SCP fallback, default), 5 FTP, 6 WebDAV, 7 S3.
//! Ftps: 0 none, 1 implicit, 2/3 explicit.
//! Passwords use WinSCP's reversible obfuscation (not encryption) unless a master password is set.

use crate::model::{Auth, Bookmark, ImportResult, Protocol};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};
use std::collections::HashMap;

const MAGIC: u8 = 0xA3;
const FLAG: u8 = 0xFF;

// WinSCP escapes everything except alphanumerics and a few safe chars.
const ENC: &AsciiSet = &CONTROLS
    .add(b' ').add(b'%').add(b'"').add(b'#').add(b'<').add(b'>').add(b'?')
    .add(b'[').add(b']').add(b'\\').add(b'=').add(b';').add(b'&').add(b'+');

fn dec(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

fn enc(s: &str) -> String {
    utf8_percent_encode(s, ENC).to_string()
}

pub fn parse(ini: &str) -> Result<ImportResult, String> {
    let mut out = ImportResult::default();
    let mut sections: Vec<(String, HashMap<String, String>)> = Vec::new();
    let mut master_password = false;
    let mut current: Option<usize> = None;
    let mut in_security = false;
    for raw in ini.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let name = &line[1..line.len() - 1];
            in_security = name.eq_ignore_ascii_case("Configuration\\Security");
            current = name.strip_prefix("Sessions\\").map(|s| {
                sections.push((dec(s), HashMap::new()));
                sections.len() - 1
            });
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        if in_security && k.eq_ignore_ascii_case("UseMasterPassword") && v.trim() == "1" {
            master_password = true;
        }
        if let Some(i) = current {
            sections[i].1.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    if sections.is_empty() {
        return Err("No [Sessions\\...] sections found — is this a WinSCP.ini?".into());
    }
    if master_password {
        out.warnings.push("WinSCP master password is enabled: passwords were not imported".into());
    }
    for (full_name, kv) in sections {
        if full_name == "Default Settings" {
            continue;
        }
        let get = |k: &str| kv.get(k).map(|v| dec(v)).unwrap_or_default();
        let (folder, name) = match full_name.rsplit_once('/') {
            Some((f, n)) => (f.to_string(), n.to_string()),
            None => (String::new(), full_name.clone()),
        };
        let ftps: i32 = get("ftps").parse().unwrap_or(0);
        let protocol = match get("fsprotocol").parse::<i32>().unwrap_or(2) {
            0 | 1 | 2 => Protocol::Sftp,
            5 => match ftps {
                1 => Protocol::Ftps,
                2 | 3 => Protocol::Ftpes,
                _ => Protocol::Ftp,
            },
            7 => Protocol::S3,
            other => {
                out.warnings.push(format!("'{name}': WinSCP protocol {other} (WebDAV?) is not supported, skipped"));
                continue;
            }
        };
        let mut b = Bookmark::new(protocol);
        b.name = name;
        b.folder = folder;
        b.host = get("hostname");
        b.port = get("portnumber").parse().unwrap_or(protocol.default_port());
        b.username = get("username");
        b.remote_path = get("remotedirectory");
        b.local_path = get("localdirectory");
        b.key_path = get("publickeyfile");
        b.auth = if !b.key_path.is_empty() { Auth::Key } else { Auth::Password };
        if protocol == Protocol::S3 {
            b.region = get("s3defaultregion");
        }
        if !master_password {
            if let Some(p) = kv.get("password").filter(|p| !p.is_empty()) {
                match decrypt_password(&b.host, &b.username, p) {
                    Some(pw) => b.password = Some(pw),
                    None => out.warnings.push(format!("'{}': could not decode password", b.name)),
                }
            }
        }
        if b.auth == Auth::Password && b.password.is_none() {
            b.auth = Auth::Ask;
        }
        if b.host.is_empty() {
            out.warnings.push(format!("'{}': no host, skipped", b.name));
            continue;
        }
        out.bookmarks.push(b);
    }
    Ok(out)
}

pub fn decrypt_password(host: &str, user: &str, hex: &str) -> Option<String> {
    let nibbles: Vec<u8> = hex
        .chars()
        .map(|c| c.to_digit(16).map(|d| d as u8))
        .collect::<Option<_>>()?;
    let mut pos = 0;
    let mut next = || -> Option<u8> {
        let (a, b) = (*nibbles.get(pos)?, *nibbles.get(pos + 1)?);
        pos += 2;
        Some(!(((a << 4) + b) ^ MAGIC))
    };
    let flag = next()?;
    let len = if flag == FLAG {
        next()?;
        next()?
    } else {
        flag
    };
    let skip = next()? as usize;
    for _ in 0..skip {
        next()?;
    }
    let bytes: Vec<u8> = (0..len).map(|_| next()).collect::<Option<_>>()?;
    let mut s = String::from_utf8_lossy(&bytes).into_owned();
    if flag == FLAG {
        let key = format!("{user}{host}");
        s = s.strip_prefix(&key)?.to_string();
    }
    Some(s)
}

pub fn encrypt_password(host: &str, user: &str, password: &str) -> String {
    let plain = format!("{user}{host}{password}");
    let bytes = plain.as_bytes();
    let mut out = String::new();
    let mut push = |c: u8| out.push_str(&format!("{:02X}", (!c) ^ MAGIC));
    push(FLAG);
    push(0);
    push(bytes.len() as u8);
    push(0); // no random padding
    for &c in bytes {
        push(c);
    }
    out
}

pub fn export(bookmarks: &[Bookmark], include_passwords: bool) -> String {
    let mut x = String::from("; WinSCP sessions exported by Kurir\n\n");
    for b in bookmarks {
        let full = if b.folder.is_empty() { b.display_name() } else { format!("{}/{}", b.folder, b.display_name()) };
        x.push_str(&format!("[Sessions\\{}]\n", enc(&full)));
        x.push_str(&format!("HostName={}\n", b.host));
        x.push_str(&format!("PortNumber={}\n", b.port));
        x.push_str(&format!("UserName={}\n", enc(&b.username)));
        let (fs, ftps) = match b.protocol {
            Protocol::Sftp => (2, 0),
            Protocol::Ftp => (5, 0),
            Protocol::Ftps => (5, 1),
            Protocol::Ftpes => (5, 3),
            Protocol::S3 => (7, 0),
        };
        x.push_str(&format!("FSProtocol={fs}\n"));
        if ftps != 0 {
            x.push_str(&format!("Ftps={ftps}\n"));
        }
        if !b.remote_path.is_empty() {
            x.push_str(&format!("RemoteDirectory={}\n", enc(&b.remote_path)));
        }
        if !b.local_path.is_empty() {
            x.push_str(&format!("LocalDirectory={}\n", enc(&b.local_path)));
        }
        if b.auth == Auth::Key && !b.key_path.is_empty() {
            x.push_str(&format!("PublicKeyFile={}\n", enc(&b.key_path)));
        }
        if b.protocol == Protocol::S3 && !b.region.is_empty() {
            x.push_str(&format!("S3DefaultRegion={}\n", b.region));
        }
        if include_passwords && b.auth == Auth::Password {
            if let Some(p) = &b.password {
                x.push_str(&format!("Password={}\n", encrypt_password(&b.host, &b.username, p)));
            }
        }
        x.push('\n');
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip() {
        let e = encrypt_password("example.com", "root", "p@ss w0rd!");
        assert_eq!(decrypt_password("example.com", "root", &e).as_deref(), Some("p@ss w0rd!"));
    }

    #[test]
    fn parse_and_export() {
        let pw = encrypt_password("h.example", "me", "hunter2");
        let ini = format!(
            "[Configuration\\Interface]\nFoo=1\n\n[Sessions\\Work/My%20Server]\nHostName=h.example\nUserName=me\nPortNumber=2222\nPassword={pw}\nRemoteDirectory=/var/www\n\n[Sessions\\ftp%20site]\nHostName=f.example\nFSProtocol=5\nFtps=3\nPublicKeyFile=C:%5Ckeys%5Cid.ppk\n"
        );
        let r = parse(&ini).unwrap();
        assert_eq!(r.bookmarks.len(), 2);
        let a = &r.bookmarks[0];
        assert_eq!((a.folder.as_str(), a.name.as_str(), a.port), ("Work", "My Server", 2222));
        assert_eq!(a.password.as_deref(), Some("hunter2"));
        let b = &r.bookmarks[1];
        assert_eq!((b.protocol, b.auth, b.key_path.as_str()), (Protocol::Ftpes, Auth::Key, "C:\\keys\\id.ppk"));
        let again = parse(&export(&r.bookmarks, true)).unwrap();
        assert_eq!(again.bookmarks[0].password.as_deref(), Some("hunter2"));
        assert_eq!(again.bookmarks[0].name, "My Server");
        assert_eq!(again.bookmarks[1].key_path, "C:\\keys\\id.ppk");
    }
}
