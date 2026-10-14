//! FileZilla `sitemanager.xml` (also the format of Site Manager → Export).
//!
//! Protocol codes: 0 FTP, 1 SFTP, 3 FTPS (implicit), 4 FTPES (explicit), 6 insecure FTP, 7 S3 (Pro).
//! Logontype: 0 anonymous, 1 normal, 2 ask, 3 interactive, 4 account, 5 key file.
//! RemoteDir is length-prefixed: "1 0 3 var 3 www" = unix type, no prefix, /var/www.

use crate::model::{xml_escape, Auth, Bookmark, ImportResult, Protocol};
use base64::{engine::general_purpose::STANDARD as B64, Engine};

pub fn parse(xml: &str) -> Result<ImportResult, String> {
    let doc = roxmltree::Document::parse(xml).map_err(|e| format!("Invalid XML: {e}"))?;
    let mut out = ImportResult::default();
    let root = doc.root_element();
    // <FileZilla3><Servers>...</Servers></FileZilla3>; tolerate a bare <Servers> too.
    let servers = if root.has_tag_name("Servers") {
        Some(root)
    } else {
        root.children().find(|n| n.has_tag_name("Servers"))
    };
    let Some(servers) = servers else {
        return Err("No <Servers> element found — is this a FileZilla sitemanager.xml?".into());
    };
    walk(servers, &mut Vec::new(), &mut out);
    Ok(out)
}

fn walk(node: roxmltree::Node, path: &mut Vec<String>, out: &mut ImportResult) {
    for child in node.children().filter(|n| n.is_element()) {
        if child.has_tag_name("Folder") {
            let name = child
                .children()
                .filter(|n| n.is_text())
                .filter_map(|n| n.text())
                .map(str::trim)
                .find(|t| !t.is_empty())
                .unwrap_or("Folder")
                .to_string();
            path.push(name);
            walk(child, path, out);
            path.pop();
        } else if child.has_tag_name("Server") {
            match server(child) {
                Ok(mut b) => {
                    b.folder = path.join("/");
                    out.bookmarks.push(b);
                }
                Err(w) => out.warnings.push(w),
            }
        }
    }
}

fn text<'a>(node: roxmltree::Node<'a, 'a>, tag: &str) -> Option<(&'a str, roxmltree::Node<'a, 'a>)> {
    node.children()
        .find(|n| n.has_tag_name(tag))
        .map(|n| (n.text().unwrap_or(""), n))
}

fn server(node: roxmltree::Node) -> Result<Bookmark, String> {
    let get = |tag: &str| text(node, tag).map(|(t, _)| t.trim().to_string()).unwrap_or_default();
    let name = get("Name");
    let code: i32 = get("Protocol").parse().unwrap_or(0);
    let protocol = match code {
        0 | 6 => Protocol::Ftp,
        1 => Protocol::Sftp,
        3 => Protocol::Ftps,
        4 => Protocol::Ftpes,
        7 => Protocol::S3,
        other => return Err(format!("'{name}': FileZilla protocol {other} is not supported, skipped")),
    };
    let mut b = Bookmark::new(protocol);
    b.name = name;
    b.host = get("Host");
    b.port = get("Port").parse().unwrap_or(protocol.default_port());
    b.username = get("User");
    b.comment = get("Comments");
    b.local_path = get("LocalDir");
    b.remote_path = decode_remote_dir(&get("RemoteDir"));
    b.auth = match get("Logontype").parse::<i32>().unwrap_or(1) {
        0 => Auth::Anonymous,
        2 | 3 => Auth::Ask,
        5 => Auth::Key,
        _ => Auth::Password,
    };
    if b.auth == Auth::Key {
        b.key_path = get("Keyfile");
    }
    if let Some((pass, n)) = text(node, "Pass") {
        let pass = pass.trim();
        if !pass.is_empty() {
            match n.attribute("encoding") {
                Some("base64") => {
                    if let Ok(bytes) = B64.decode(pass) {
                        b.password = Some(String::from_utf8_lossy(&bytes).into_owned());
                    }
                }
                // "crypt" = protected by FileZilla's master password: can't be read.
                Some(_) => {}
                None => b.password = Some(pass.to_string()),
            }
        }
    }
    if b.host.is_empty() {
        return Err(format!("'{}': no host, skipped", b.name));
    }
    Ok(b)
}

pub fn decode_remote_dir(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    let num = |i: &mut usize| -> Option<usize> {
        while *i < chars.len() && chars[*i] == ' ' {
            *i += 1;
        }
        let start = *i;
        while *i < chars.len() && chars[*i].is_ascii_digit() {
            *i += 1;
        }
        chars[start..*i].iter().collect::<String>().parse().ok()
    };
    let Some(_server_type) = num(&mut i) else { return String::new() };
    let prefix_len = num(&mut i).unwrap_or(0);
    if prefix_len > 0 {
        i += 1 + prefix_len;
    }
    let mut segs = Vec::new();
    while let Some(len) = num(&mut i) {
        i += 1; // single separating space
        let end = (i + len).min(chars.len());
        segs.push(chars[i..end].iter().collect::<String>());
        i = end;
    }
    if segs.is_empty() {
        if s.trim().is_empty() { String::new() } else { "/".into() }
    } else {
        format!("/{}", segs.join("/"))
    }
}

pub fn encode_remote_dir(path: &str) -> String {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if path.is_empty() {
        return String::new();
    }
    let mut out = String::from("1 0");
    for s in segs {
        out.push_str(&format!(" {} {}", s.chars().count(), s));
    }
    out
}

pub fn export(bookmarks: &[Bookmark], include_passwords: bool) -> String {
    use std::collections::BTreeMap;
    // folder path -> servers; nested folders flattened by their full path.
    let mut groups: BTreeMap<String, Vec<&Bookmark>> = BTreeMap::new();
    for b in bookmarks {
        groups.entry(b.folder.clone()).or_default().push(b);
    }
    let mut x = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<FileZilla3 version=\"3.70.0\" platform=\"*nix\">\n\t<Servers>\n");
    for (folder, list) in groups {
        let indent = if folder.is_empty() { "\t\t" } else { "\t\t\t" };
        if !folder.is_empty() {
            x.push_str(&format!("\t\t<Folder expanded=\"1\">{}\n", xml_escape(&folder.replace('/', " - "))));
        }
        for b in list {
            server_xml(&mut x, b, indent, include_passwords);
        }
        if !folder.is_empty() {
            x.push_str("\t\t</Folder>\n");
        }
    }
    x.push_str("\t</Servers>\n</FileZilla3>\n");
    x
}

fn server_xml(x: &mut String, b: &Bookmark, ind: &str, include_passwords: bool) {
    let proto = match b.protocol {
        Protocol::Ftp => 0,
        Protocol::Sftp => 1,
        Protocol::Ftps => 3,
        Protocol::Ftpes => 4,
        Protocol::S3 => 7,
    };
    let logon = match b.auth {
        Auth::Anonymous => 0,
        Auth::Ask => 2,
        Auth::Key => 5,
        Auth::Password if include_passwords && b.password.is_some() => 1,
        Auth::Password => 2,
    };
    let tag = |x: &mut String, k: &str, v: &str| x.push_str(&format!("{ind}\t<{k}>{}</{k}>\n", xml_escape(v)));
    x.push_str(&format!("{ind}<Server>\n"));
    tag(x, "Host", &b.host);
    tag(x, "Port", &b.port.to_string());
    tag(x, "Protocol", &proto.to_string());
    tag(x, "Type", "0");
    tag(x, "User", &b.username);
    if logon == 1 {
        let p = B64.encode(b.password.as_deref().unwrap_or("").as_bytes());
        x.push_str(&format!("{ind}\t<Pass encoding=\"base64\">{p}</Pass>\n"));
    }
    if b.auth == Auth::Key {
        tag(x, "Keyfile", &b.key_path);
    }
    tag(x, "Logontype", &logon.to_string());
    tag(x, "EncodingType", "Auto");
    tag(x, "BypassProxy", "0");
    tag(x, "Name", &b.display_name());
    tag(x, "Comments", &b.comment);
    tag(x, "LocalDir", &b.local_path);
    tag(x, "RemoteDir", &encode_remote_dir(&b.remote_path));
    tag(x, "SyncBrowsing", "0");
    tag(x, "DirectoryComparison", "0");
    x.push_str(&format!("{ind}</Server>\n"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_dir_roundtrip() {
        assert_eq!(decode_remote_dir("1 0 3 var 3 www"), "/var/www");
        assert_eq!(decode_remote_dir("1 0 8 my files 4 html"), "/my files/html");
        assert_eq!(decode_remote_dir(""), "");
        assert_eq!(encode_remote_dir("/var/www"), "1 0 3 var 3 www");
        assert_eq!(decode_remote_dir(&encode_remote_dir("/a b/ç")), "/a b/ç");
    }

    #[test]
    fn parse_sample() {
        let xml = r#"<?xml version="1.0"?>
<FileZilla3><Servers>
  <Server><Host>1.2.3.4</Host><Port>22</Port><Protocol>1</Protocol><User>ubuntu</User>
    <Keyfile>/k.pem</Keyfile><Logontype>5</Logontype><Name>AWS</Name><RemoteDir>1 0 3 var 3 www</RemoteDir></Server>
  <Folder expanded="1">Clients
    <Server><Host>ftp.x.com</Host><Port>21</Port><Protocol>4</Protocol><User>bob</User>
      <Pass encoding="base64">c2VjcmV0</Pass><Logontype>1</Logontype><Name>X &amp; Y</Name></Server>
  </Folder>
</Servers></FileZilla3>"#;
        let r = parse(xml).unwrap();
        assert_eq!(r.bookmarks.len(), 2);
        let a = &r.bookmarks[0];
        assert_eq!((a.protocol, a.auth, a.key_path.as_str(), a.remote_path.as_str()), (Protocol::Sftp, Auth::Key, "/k.pem", "/var/www"));
        let b = &r.bookmarks[1];
        assert_eq!((b.protocol, b.folder.as_str(), b.name.as_str()), (Protocol::Ftpes, "Clients", "X & Y"));
        assert_eq!(b.password.as_deref(), Some("secret"));

        let again = parse(&export(&r.bookmarks, true)).unwrap();
        assert_eq!(again.bookmarks.len(), 2);
        assert_eq!(again.bookmarks[1].password.as_deref(), Some("secret"));
        assert_eq!(again.bookmarks[0].remote_path, "/var/www");
    }
}
