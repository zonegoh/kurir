//! Cyberduck `.duck` bookmark files (one property list per bookmark, XML or binary).
//!
//! Keys come from Cyberduck's `HostDictionary`: Protocol, Provider, Hostname, Port, Username,
//! Nickname, UUID, Path, Comment, Labels, Private Key File, Download Folder Dictionary, Custom.
//! Passwords are kept in the macOS Keychain by Cyberduck, so they are never in the file.

use crate::model::{Auth, Bookmark, ImportResult, Protocol};
use plist::{Dictionary, Value};
use std::path::Path;

/// Cyberduck's built-in connection profiles are registered under this provider.
const PROVIDER: &str = "iterate GmbH";

pub fn default_dir() -> Option<std::path::PathBuf> {
    let home = dirs::home_dir()?;
    let candidates = [
        "Library/Group Containers/G69SCX94XU.duck/Library/Application Support/duck/Bookmarks",
        "Library/Application Support/Cyberduck/Bookmarks",
        "AppData/Roaming/Cyberduck/Bookmarks",
    ];
    candidates.iter().map(|c| home.join(c)).find(|p| p.is_dir())
}

/// Parse a single .duck file, or every .duck file in a directory.
pub fn parse_path(path: &Path) -> Result<ImportResult, String> {
    let mut out = ImportResult::default();
    let files: Vec<std::path::PathBuf> = if path.is_dir() {
        let mut v: Vec<_> = std::fs::read_dir(path)
            .map_err(|e| e.to_string())?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|e| e == "duck"))
            .collect();
        v.sort();
        v
    } else {
        vec![path.to_path_buf()]
    };
    if files.is_empty() {
        return Err("No .duck files found in that folder".into());
    }
    for f in files {
        let fname = f.file_name().unwrap_or_default().to_string_lossy().to_string();
        match Value::from_file(&f) {
            Ok(Value::Dictionary(d)) => match from_dict(&d) {
                Ok(b) => out.bookmarks.push(b),
                Err(w) => out.warnings.push(format!("{fname}: {w}")),
            },
            Ok(_) => out.warnings.push(format!("{fname}: not a bookmark dictionary")),
            Err(e) => out.warnings.push(format!("{fname}: {e}")),
        }
    }
    Ok(out)
}

fn s(d: &Dictionary, k: &str) -> String {
    match d.get(k) {
        Some(Value::String(v)) => v.clone(),
        Some(Value::Integer(i)) => i.to_string(),
        _ => String::new(),
    }
}

fn sub_path(d: &Dictionary, k: &str) -> String {
    d.get(k)
        .and_then(Value::as_dictionary)
        .map(|sd| s(sd, "Path"))
        .unwrap_or_default()
}

pub fn from_dict(d: &Dictionary) -> Result<Bookmark, String> {
    let proto = s(d, "Protocol");
    let protocol = match proto.as_str() {
        "sftp" | "scp" => Protocol::Sftp,
        "ftp" => Protocol::Ftp,
        // Cyberduck's "ftps" is FTP-SSL with explicit AUTH TLS.
        "ftps" => Protocol::Ftpes,
        "s3" => Protocol::S3,
        other => return Err(format!("protocol '{other}' is not supported (only SFTP, FTP/S, S3), skipped")),
    };
    let mut b = Bookmark::new(protocol);
    let uuid = s(d, "UUID");
    if !uuid.is_empty() {
        b.id = uuid;
    }
    b.name = s(d, "Nickname");
    b.host = s(d, "Hostname");
    b.port = s(d, "Port").parse().unwrap_or(protocol.default_port());
    b.username = s(d, "Username");
    b.remote_path = s(d, "Path");
    b.comment = s(d, "Comment");
    b.local_path = sub_path(d, "Download Folder Dictionary");
    if b.local_path.is_empty() {
        b.local_path = s(d, "Download Folder");
    }
    b.key_path = sub_path(d, "Private Key File Dictionary");
    if b.key_path.is_empty() {
        b.key_path = s(d, "Private Key File");
    }
    if let Some(Value::Array(labels)) = d.get("Labels") {
        if let Some(Value::String(l)) = labels.first() {
            b.folder = l.clone();
        }
    }
    if let Some(custom) = d.get("Custom").and_then(Value::as_dictionary) {
        b.region = s(custom, "s3.location");
    }
    b.auth = if !b.key_path.is_empty() {
        Auth::Key
    } else if b.username == "anonymous" {
        Auth::Anonymous
    } else {
        Auth::Ask
    };
    if b.host.is_empty() {
        return Err("no hostname, skipped".into());
    }
    Ok(b)
}

pub fn to_dict(b: &Bookmark) -> Dictionary {
    let mut d = Dictionary::new();
    let mut put = |k: &str, v: &str| {
        if !v.is_empty() {
            d.insert(k.into(), Value::String(v.into()));
        }
    };
    put("Protocol", match b.protocol {
        Protocol::Sftp => "sftp",
        Protocol::Ftp => "ftp",
        Protocol::Ftps | Protocol::Ftpes => "ftps",
        Protocol::S3 => "s3",
    });
    put("Provider", PROVIDER);
    put("Nickname", &b.display_name());
    put("UUID", &b.id);
    put("Hostname", &b.host);
    put("Port", &b.port.to_string());
    put("Username", &b.username);
    put("Path", &b.remote_path);
    put("Comment", &b.comment);
    if b.auth == Auth::Key && !b.key_path.is_empty() {
        put("Private Key File", &b.key_path);
        let mut kd = Dictionary::new();
        kd.insert("Path".into(), Value::String(b.key_path.clone()));
        d.insert("Private Key File Dictionary".into(), Value::Dictionary(kd));
    }
    if !b.local_path.is_empty() {
        let mut ld = Dictionary::new();
        ld.insert("Path".into(), Value::String(b.local_path.clone()));
        d.insert("Download Folder Dictionary".into(), Value::Dictionary(ld));
    }
    let labels = if b.folder.is_empty() { vec![] } else { vec![Value::String(b.folder.clone())] };
    d.insert("Labels".into(), Value::Array(labels));
    if b.protocol == Protocol::S3 && !b.region.is_empty() {
        let mut c = Dictionary::new();
        c.insert("s3.location".into(), Value::String(b.region.clone()));
        d.insert("Custom".into(), Value::Dictionary(c));
    }
    d
}

/// Writes one `<uuid>.duck` per bookmark into `dir`. Returns the number of files written.
pub fn export_dir(bookmarks: &[Bookmark], dir: &Path) -> Result<usize, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    for b in bookmarks {
        let file = dir.join(format!("{}.duck", b.id));
        Value::Dictionary(to_dict(b))
            .to_file_xml(&file)
            .map_err(|e| format!("{}: {e}", file.display()))?;
    }
    Ok(bookmarks.len())
}

/// Cyberduck keeps passwords, S3 secret keys and key passphrases in the macOS login keychain.
/// Lookup keys were taken from Cyberduck 9.5 (`DefaultHostPasswordStore`, `KeychainPasswordStore`):
/// - login password / S3 secret: internet password (server = hostname, account = username,
///   port = bookmark port, protocol = scheme: ftp→'ftp ', ftps→'ftps', sftp→'ssh ', https→'htps'
///   (S3), auth type 'dflt')
/// - key passphrase: generic password (service = hostname, account = "~/…" key path),
///   falling back to (service = "SSH", account = absolute key path)
///
/// Every item read may show a macOS prompt ("Allow" / "Always Allow"). Returns how many were found.
#[cfg(target_os = "macos")]
pub fn fill_passwords_from_keychain(list: &mut [Bookmark], warnings: &mut Vec<String>) -> usize {
    use security_framework::os::macos::passwords::{find_generic_password, find_internet_password, SecAuthenticationType, SecProtocolType};
    let home = dirs::home_dir().map(|h| h.to_string_lossy().into_owned()).unwrap_or_default();
    let mut found = 0;
    for b in list.iter_mut() {
        if b.username.is_empty() || b.auth == Auth::Anonymous {
            continue;
        }
        let pw = if b.auth == Auth::Key {
            let abs = if let Some(rest) = b.key_path.strip_prefix("~/") { format!("{home}/{rest}") } else { b.key_path.clone() };
            let abbreviated = abs.strip_prefix(&home).map(|r| format!("~{r}")).unwrap_or_else(|| abs.clone());
            find_generic_password(None, &b.host, &abbreviated)
                .or_else(|_| find_generic_password(None, "SSH", &abs))
                .ok()
                .map(|(p, _)| p.to_vec())
        } else {
            let protocol = match b.protocol {
                Protocol::Sftp => SecProtocolType::SSH,
                Protocol::Ftp => SecProtocolType::FTP,
                Protocol::Ftps | Protocol::Ftpes => SecProtocolType::FTPS,
                Protocol::S3 => SecProtocolType::HTTPS,
            };
            find_internet_password(None, &b.host, None, &b.username, "", Some(b.port), protocol, SecAuthenticationType::Default)
                .ok()
                .map(|(p, _)| p.to_vec())
        };
        match pw.and_then(|p| String::from_utf8(p).ok()).filter(|p| !p.is_empty()) {
            Some(p) => {
                b.password = Some(p);
                if b.auth == Auth::Ask {
                    b.auth = Auth::Password;
                }
                found += 1;
            }
            None if b.auth != Auth::Key => warnings.push(format!(
                "{}: no {} found in the keychain (or access was denied)",
                b.display_name(),
                if b.protocol == Protocol::S3 { "secret key" } else { "password" }
            )),
            None => {}
        }
    }
    found
}

#[cfg(not(target_os = "macos"))]
pub fn fill_passwords_from_keychain(_list: &mut [Bookmark], _warnings: &mut Vec<String>) -> usize {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut b = Bookmark::new(Protocol::S3);
        b.name = "Cloudian".into();
        b.host = "s3.example.id".into();
        b.username = "AKIA".into();
        b.region = "us-east-1".into();
        b.folder = "Storage".into();
        let back = from_dict(&to_dict(&b)).unwrap();
        assert_eq!((back.id, back.name, back.region, back.folder, back.port), (b.id, b.name, b.region, b.folder, 443));
        let mut ftp = Bookmark::new(Protocol::Ftpes);
        ftp.host = "f".into();
        assert_eq!(from_dict(&to_dict(&ftp)).unwrap().protocol, Protocol::Ftpes);
    }

    #[test]
    fn rejects_unsupported() {
        let mut d = Dictionary::new();
        d.insert("Protocol".into(), Value::String("onedrive".into()));
        d.insert("Hostname".into(), Value::String("graph.microsoft.com".into()));
        assert!(from_dict(&d).is_err());
    }
}
