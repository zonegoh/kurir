use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Sftp,
    /// Plain FTP
    Ftp,
    /// FTP over implicit TLS (port 990)
    Ftps,
    /// FTP with explicit TLS (AUTH TLS)
    Ftpes,
    /// S3 or S3-compatible storage
    S3,
}

impl Protocol {
    pub fn default_port(self) -> u16 {
        match self {
            Protocol::Sftp => 22,
            Protocol::Ftp | Protocol::Ftpes => 21,
            Protocol::Ftps => 990,
            Protocol::S3 => 443,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Auth {
    #[default]
    Password,
    Key,
    Anonymous,
    /// Ask for the password on every connect
    Ask,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct Bookmark {
    pub id: String,
    pub name: String,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: Auth,
    pub key_path: String,
    pub remote_path: String,
    pub local_path: String,
    /// S3 region (e.g. us-east-1)
    pub region: String,
    pub comment: String,
    /// Group shown in the sidebar ("" = no group)
    pub folder: String,
    /// A password / secret key is saved in the keychain. Kept here so listing bookmarks
    /// never has to touch the keychain (each read can trigger a macOS permission prompt).
    pub has_password: bool,
    /// Only used in transit (import preview / export); never written to bookmarks.json.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl Bookmark {
    pub fn new(protocol: Protocol) -> Self {
        Bookmark {
            id: uuid::Uuid::new_v4().to_string(),
            protocol,
            port: protocol.default_port(),
            ..Default::default()
        }
    }

    pub fn display_name(&self) -> String {
        if !self.name.is_empty() {
            self.name.clone()
        } else if !self.username.is_empty() {
            format!("{}@{}", self.username, self.host)
        } else {
            self.host.clone()
        }
    }
}

/// Result of parsing a third-party bookmark file.
#[derive(Serialize, Debug, Default)]
pub struct ImportResult {
    pub bookmarks: Vec<Bookmark>,
    pub warnings: Vec<String>,
}

pub fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
