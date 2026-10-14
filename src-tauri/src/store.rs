use crate::model::Bookmark;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Mutex;

const KEYRING_SERVICE: &str = "Kurir";
/// The app was called DuckLite before; its keychain items are migrated on first use.
const LEGACY_SERVICE: &str = "DuckLite";
/// All secrets live in ONE keychain item (JSON map bookmark id -> password), so macOS asks
/// for keychain access at most once per launch instead of once per bookmark.
const VAULT_ACCOUNT: &str = "vault";

pub struct Store {
    dir: PathBuf,
    vault: Mutex<Option<HashMap<String, String>>>,
}

fn vault_entry() -> Result<keyring::Entry, String> {
    keyring::Entry::new(KEYRING_SERVICE, VAULT_ACCOUNT).map_err(|e| format!("Keychain: {e}"))
}

impl Store {
    pub fn new(dir: PathBuf) -> Self {
        let _ = std::fs::create_dir_all(&dir);
        Store { dir, vault: Mutex::new(None) }
    }

    /// Runs `f` on the vault, reading it from the keychain on first use.
    fn with_vault<T>(&self, f: impl FnOnce(&mut HashMap<String, String>) -> T) -> Result<T, String> {
        let mut guard = self.vault.lock().unwrap();
        if guard.is_none() {
            let map = match vault_entry()?.get_password() {
                Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
                Err(keyring::Error::NoEntry) => match Self::take_legacy_vault() {
                    Some(json) => {
                        let _ = vault_entry()?.set_password(&json);
                        serde_json::from_str(&json).unwrap_or_default()
                    }
                    None => HashMap::new(),
                },
                // Access denied etc.: don't cache, so the next explicit action can ask again.
                Err(e) => return Err(format!("Keychain: {e}")),
            };
            *guard = Some(map);
        }
        Ok(f(guard.as_mut().unwrap()))
    }

    /// Moves the vault written by DuckLite (the previous app name), if any.
    fn take_legacy_vault() -> Option<String> {
        let old = keyring::Entry::new(LEGACY_SERVICE, VAULT_ACCOUNT).ok()?;
        let json = old.get_password().ok()?;
        let _ = old.delete_credential();
        Some(json)
    }

    fn write_vault(&self, map: &HashMap<String, String>) -> Result<(), String> {
        let json = serde_json::to_string(map).map_err(|e| e.to_string())?;
        vault_entry()?.set_password(&json).map_err(|e| format!("Keychain: {e}"))
    }

    fn bookmarks_file(&self) -> PathBuf {
        self.dir.join("bookmarks.json")
    }

    fn known_hosts_file(&self) -> PathBuf {
        self.dir.join("known_hosts.json")
    }

    pub fn load(&self) -> Vec<Bookmark> {
        std::fs::read_to_string(self.bookmarks_file())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, list: &[Bookmark]) -> Result<(), String> {
        // Passwords never go to disk in plain text — they live in the OS keychain.
        let clean: Vec<Bookmark> = list.iter().cloned().map(|mut b| { b.password = None; b }).collect();
        let json = serde_json::to_string_pretty(&clean).map_err(|e| e.to_string())?;
        let tmp = self.bookmarks_file().with_extension("json.tmp");
        std::fs::write(&tmp, json).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, self.bookmarks_file()).map_err(|e| e.to_string())
    }

    pub fn get(&self, id: &str) -> Option<Bookmark> {
        self.load().into_iter().find(|b| b.id == id)
    }

    pub fn password(&self, id: &str) -> Option<String> {
        if let Some(p) = self.with_vault(|v| v.get(id).cloned()).ok().flatten() {
            return Some(p);
        }
        // DuckLite 0.1 stored one keychain item per bookmark: move it into the vault.
        let legacy = keyring::Entry::new(LEGACY_SERVICE, id).ok()?;
        let p = legacy.get_password().ok()?;
        if self.set_password(id, &p).is_ok() {
            let _ = legacy.delete_credential();
        }
        Some(p)
    }

    /// Sets (or with "" removes) a password. Writes the keychain only when something changed.
    pub fn set_password(&self, id: &str, password: &str) -> Result<(), String> {
        let changed = self.with_vault(|v| {
            let before = v.get(id).cloned();
            if password.is_empty() { v.remove(id); } else { v.insert(id.to_string(), password.to_string()); }
            (before.as_deref() != (!password.is_empty()).then_some(password)).then(|| v.clone())
        })?;
        match changed {
            Some(map) => self.write_vault(&map),
            None => Ok(()),
        }
    }

    pub fn delete_password(&self, id: &str) {
        let _ = self.set_password(id, "");
    }

    /// Removes several passwords with a single keychain write.
    pub fn delete_passwords(&self, ids: &[String]) -> Result<(), String> {
        let changed = self.with_vault(|v| {
            let before = v.len();
            ids.iter().for_each(|id| { v.remove(id); });
            (v.len() != before).then(|| v.clone())
        })?;
        match changed {
            Some(map) => self.write_vault(&map),
            None => Ok(()),
        }
    }

    /// Trust-on-first-use host key check. Returns Ok(true) if the key was newly stored.
    pub fn check_host_key(&self, host_port: &str, fingerprint: &str) -> Result<bool, String> {
        let file = self.known_hosts_file();
        let mut map: BTreeMap<String, String> = std::fs::read_to_string(&file)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        match map.get(host_port) {
            Some(known) if known == fingerprint => Ok(false),
            Some(known) => Err(format!(
                "HOST KEY CHANGED for {host_port}!\nKnown: {known}\nNow:   {fingerprint}\n\
                 This may be a man-in-the-middle attack. If the server was reinstalled, \
                 remove the entry from {}",
                file.display()
            )),
            None => {
                map.insert(host_port.to_string(), fingerprint.to_string());
                let json = serde_json::to_string_pretty(&map).map_err(|e| e.to_string())?;
                std::fs::write(&file, json).map_err(|e| e.to_string())?;
                Ok(true)
            }
        }
    }
}
