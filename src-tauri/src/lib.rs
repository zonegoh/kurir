mod formats {
    pub mod cyberduck;
    pub mod filezilla;
    pub mod winscp;
}
mod model;
mod ppk;
mod remote;
mod store;

use formats::{cyberduck, filezilla, winscp};
use model::{Auth, Bookmark, ImportResult};
use remote::{Conn, Entry};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use store::Store;
use tauri::{AppHandle, Emitter, Manager, State};

type R<T> = Result<T, String>;

struct AppState {
    store: Store,
    sessions: Mutex<HashMap<String, Arc<Mutex<Conn>>>>,
}

impl AppState {
    fn session(&self, id: &str) -> R<Arc<Mutex<Conn>>> {
        self.sessions
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| "Not connected (session closed)".to_string())
    }
}

// ---- bookmarks ---------------------------------------------------------------

/// Never touches the keychain: `has_password` is stored with the bookmark.
#[tauri::command(async)]
fn list_bookmarks(state: State<AppState>) -> Vec<Bookmark> {
    state.store.load()
}

#[tauri::command(async)]
fn save_bookmark(state: State<AppState>, mut bookmark: Bookmark) -> R<Bookmark> {
    if bookmark.host.trim().is_empty() {
        return Err("Host is required".into());
    }
    if bookmark.id.is_empty() {
        bookmark.id = uuid::Uuid::new_v4().to_string();
    }
    let mut list = state.store.load();
    // The stored flag is authoritative unless a new password was typed.
    bookmark.has_password = list.iter().find(|b| b.id == bookmark.id).is_some_and(|b| b.has_password);
    if let Some(p) = bookmark.password.take() {
        state.store.set_password(&bookmark.id, &p)?;
        bookmark.has_password = !p.is_empty();
    }
    match list.iter_mut().find(|b| b.id == bookmark.id) {
        Some(existing) => *existing = bookmark.clone(),
        None => list.push(bookmark.clone()),
    }
    state.store.save(&list)?;
    Ok(bookmark)
}

#[tauri::command(async)]
fn delete_bookmark(state: State<AppState>, id: String) -> R<()> {
    let (gone, list): (Vec<Bookmark>, Vec<Bookmark>) = state.store.load().into_iter().partition(|b| b.id == id);
    if gone.iter().any(|b| b.has_password) {
        state.store.delete_password(&id);
    }
    state.store.save(&list)
}

#[tauri::command(async)]
fn delete_bookmarks(state: State<AppState>, ids: Vec<String>) -> R<usize> {
    let (gone, keep): (Vec<Bookmark>, Vec<Bookmark>) = state.store.load().into_iter().partition(|b| ids.contains(&b.id));
    let with_pw: Vec<String> = gone.iter().filter(|b| b.has_password).map(|b| b.id.clone()).collect();
    if !with_pw.is_empty() {
        // Not fatal: the bookmark is removed even if the keychain refuses access.
        let _ = state.store.delete_passwords(&with_pw);
    }
    state.store.save(&keep)?;
    Ok(gone.len())
}

// ---- import / export ---------------------------------------------------------

#[tauri::command(async)]
fn default_import_path(kind: String) -> Option<String> {
    let home = dirs::home_dir()?;
    let p: PathBuf = match kind.as_str() {
        "filezilla" => [home.join(".config/filezilla/sitemanager.xml"), home.join("AppData/Roaming/FileZilla/sitemanager.xml")]
            .into_iter()
            .find(|p| p.exists())?,
        "winscp" => [home.join("AppData/Roaming/WinSCP.ini"), home.join("WinSCP.ini")].into_iter().find(|p| p.exists())?,
        "cyberduck" => cyberduck::default_dir()?,
        _ => return None,
    };
    Some(p.to_string_lossy().into_owned())
}

#[tauri::command(async)]
fn import_preview(kind: String, path: String) -> R<ImportResult> {
    let p = Path::new(&path);
    match kind.as_str() {
        "cyberduck" => {
            let mut r = cyberduck::parse_path(p)?;
            cyberduck::fill_passwords_from_keychain(&mut r.bookmarks, &mut r.warnings);
            Ok(r)
        }
        "filezilla" | "winscp" => {
            let bytes = std::fs::read(p).map_err(|e| format!("Cannot read {path}: {e}"))?;
            // WinSCP.ini written by Windows may be UTF-8 with BOM.
            let text = String::from_utf8_lossy(&bytes).trim_start_matches('\u{feff}').to_string();
            if kind == "filezilla" { filezilla::parse(&text) } else { winscp::parse(&text) }
        }
        _ => Err(format!("Unknown format {kind}")),
    }
}

/// Saves the selected imported bookmarks. Bookmarks with an id that already exists replace it.
#[tauri::command(async)]
fn import_commit(state: State<AppState>, bookmarks: Vec<Bookmark>) -> R<usize> {
    let mut list = state.store.load();
    let n = bookmarks.len();
    for mut b in bookmarks {
        let password = b.password.take().filter(|p| !p.is_empty());
        if password.is_some() {
            b.has_password = true;
            if b.auth == Auth::Ask {
                b.auth = Auth::Password;
            }
        }
        // Same id, or the same server + login, updates the existing bookmark in place.
        let same = |x: &Bookmark| {
            x.id == b.id || (x.protocol == b.protocol && x.host == b.host && x.port == b.port && x.username == b.username)
        };
        match list.iter_mut().find(|x| same(x)) {
            Some(existing) => {
                b.id = existing.id.clone();
                b.has_password |= existing.has_password;
                if let Some(p) = &password {
                    state.store.set_password(&b.id, p)?;
                }
                *existing = b;
            }
            None => {
                if let Some(p) = &password {
                    state.store.set_password(&b.id, p)?;
                }
                list.push(b);
            }
        }
    }
    state.store.save(&list)?;
    Ok(n)
}

#[tauri::command(async)]
fn export_bookmarks(state: State<AppState>, kind: String, ids: Vec<String>, path: String, include_passwords: bool) -> R<String> {
    let mut list: Vec<Bookmark> = state.store.load().into_iter().filter(|b| ids.contains(&b.id)).collect();
    if list.is_empty() {
        return Err("No bookmarks selected".into());
    }
    if include_passwords {
        for b in &mut list {
            if b.has_password {
                b.password = state.store.password(&b.id);
            }
        }
    }
    let n = list.len();
    match kind.as_str() {
        "filezilla" => std::fs::write(&path, filezilla::export(&list, include_passwords)).map_err(|e| e.to_string())?,
        "winscp" => std::fs::write(&path, winscp::export(&list, include_passwords)).map_err(|e| e.to_string())?,
        "cyberduck" => {
            cyberduck::export_dir(&list, Path::new(&path))?;
        }
        _ => return Err(format!("Unknown format {kind}")),
    }
    Ok(format!("Exported {n} bookmark(s) to {path}"))
}

// ---- remote sessions ---------------------------------------------------------

#[derive(Serialize)]
struct ConnectInfo {
    session_id: String,
    home: String,
    notice: Option<String>,
}

#[tauri::command(async)]
fn connect(state: State<AppState>, id: String, password: Option<String>, remember: bool) -> R<ConnectInfo> {
    let b = state.store.get(&id).ok_or("Bookmark not found")?;
    let pw = match &password {
        Some(p) => p.clone(),
        None if b.has_password => state.store.password(&id).unwrap_or_default(),
        None => String::new(),
    };
    let c = remote::connect(&b, &pw, &state.store)?;
    if remember {
        if let Some(p) = &password {
            state.store.set_password(&id, p)?;
            let mut list = state.store.load();
            if let Some(x) = list.iter_mut().find(|x| x.id == id) {
                x.has_password = !p.is_empty();
            }
            state.store.save(&list)?;
        }
    }
    let session_id = uuid::Uuid::new_v4().to_string();
    state.sessions.lock().unwrap().insert(session_id.clone(), Arc::new(Mutex::new(c.conn)));
    Ok(ConnectInfo { session_id, home: c.home, notice: c.notice })
}

#[tauri::command(async)]
fn disconnect(state: State<AppState>, session_id: String) {
    if let Some(s) = state.sessions.lock().unwrap().remove(&session_id) {
        if let Ok(m) = Arc::try_unwrap(s) {
            m.into_inner().unwrap().close();
        }
    }
}

#[tauri::command(async)]
fn list_dir(state: State<AppState>, session_id: String, path: String) -> R<Vec<Entry>> {
    state.session(&session_id)?.lock().unwrap().list(&path)
}

#[derive(Deserialize)]
struct RemoteItem {
    path: String,
    is_dir: bool,
}

#[tauri::command(async)]
fn download(state: State<AppState>, session_id: String, items: Vec<RemoteItem>, local_dir: String) -> R<usize> {
    let s = state.session(&session_id)?;
    let mut c = s.lock().unwrap();
    let mut n = 0;
    for it in items {
        n += c.download_tree(&it.path, it.is_dir, Path::new(&local_dir))?;
    }
    Ok(n)
}

#[tauri::command(async)]
fn upload(state: State<AppState>, session_id: String, local_paths: Vec<String>, remote_dir: String) -> R<usize> {
    let s = state.session(&session_id)?;
    let mut c = s.lock().unwrap();
    let mut n = 0;
    for p in local_paths {
        n += c.upload_tree(Path::new(&p), &remote_dir)?;
    }
    Ok(n)
}

#[tauri::command(async)]
fn make_dir(state: State<AppState>, session_id: String, path: String) -> R<()> {
    state.session(&session_id)?.lock().unwrap().mkdir(&path)
}

#[tauri::command(async)]
fn remove(state: State<AppState>, session_id: String, items: Vec<RemoteItem>) -> R<()> {
    let s = state.session(&session_id)?;
    let mut c = s.lock().unwrap();
    for it in items {
        c.remove_tree(&it.path, it.is_dir)?;
    }
    Ok(())
}

#[tauri::command(async)]
fn rename(state: State<AppState>, session_id: String, from: String, to: String) -> R<()> {
    state.session(&session_id)?.lock().unwrap().rename(&from, &to)
}

#[tauri::command(async)]
fn chmod(state: State<AppState>, session_id: String, paths: Vec<String>, mode: u32) -> R<()> {
    let s = state.session(&session_id)?;
    let mut c = s.lock().unwrap();
    for p in paths {
        c.chmod(&p, mode)?;
    }
    Ok(())
}

#[tauri::command(async)]
fn create_file(state: State<AppState>, session_id: String, path: String) -> R<()> {
    let empty = std::env::temp_dir().join(format!("kurir-empty-{}", uuid::Uuid::new_v4()));
    std::fs::write(&empty, b"").map_err(|e| e.to_string())?;
    let r = state.session(&session_id)?.lock().unwrap().put(&empty, &path);
    let _ = std::fs::remove_file(&empty);
    r
}

#[tauri::command(async)]
fn upload_file(state: State<AppState>, session_id: String, local: String, remote: String) -> R<()> {
    state.session(&session_id)?.lock().unwrap().put(Path::new(&local), &remote)
}

#[derive(Serialize, Clone)]
struct FileChanged {
    session_id: String,
    local: String,
    remote: String,
}

/// Downloads a remote file to a temp folder and opens it (`edit` = in the text editor, otherwise
/// the default app). Like FileZilla, the copy is watched and every save emits `file-changed`
/// so the UI can offer to upload it back.
#[tauri::command(async)]
fn open_remote_file(app: AppHandle, state: State<AppState>, session_id: String, remote: String, edit: bool) -> R<()> {
    let name = remote.rsplit('/').next().filter(|n| !n.is_empty()).ok_or("Invalid file")?;
    let dir = std::env::temp_dir().join("kurir-edit").join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let local = dir.join(name);
    state.session(&session_id)?.lock().unwrap().get(&remote, &local)?;
    open_local(&local, edit)?;

    let mtime = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    let mut last = mtime(&local);
    std::thread::spawn(move || {
        // Watch for 8 hours or until the session is closed.
        for _ in 0..(8 * 3600) {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let alive = app.state::<AppState>().sessions.lock().unwrap().contains_key(&session_id);
            if !alive {
                break;
            }
            let now = mtime(&local);
            if now.is_some() && now != last {
                last = now;
                let _ = app.emit("file-changed", FileChanged {
                    session_id: session_id.clone(),
                    local: local.to_string_lossy().into_owned(),
                    remote: remote.clone(),
                });
            }
        }
    });
    Ok(())
}

fn open_local(path: &Path, edit: bool) -> R<()> {
    use std::process::Command;
    let mut cmd = if cfg!(target_os = "macos") {
        let mut c = Command::new("open");
        if edit {
            c.arg("-t");
        }
        c
    } else if cfg!(windows) {
        if edit {
            Command::new("notepad")
        } else {
            let mut c = Command::new("cmd");
            c.args(["/C", "start", ""]);
            c
        }
    } else {
        Command::new("xdg-open")
    };
    cmd.arg(path).spawn().map(|_| ()).map_err(|e| format!("Cannot open file: {e}"))
}

/// The app used to be called DuckLite (data in `com.ptscbd.ducklite`): copy its bookmarks once.
fn migrate_from_ducklite(dir: &Path) {
    let Some(old) = dir.parent().map(|p| p.join("com.ptscbd.ducklite")) else { return };
    if dir.join("bookmarks.json").exists() || !old.join("bookmarks.json").exists() {
        return;
    }
    let _ = std::fs::create_dir_all(dir);
    for f in ["bookmarks.json", "known_hosts.json"] {
        let _ = std::fs::copy(old.join(f), dir.join(f));
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            migrate_from_ducklite(&dir);
            app.manage(AppState { store: Store::new(dir), sessions: Mutex::new(HashMap::new()) });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_bookmarks,
            save_bookmark,
            delete_bookmark,
            delete_bookmarks,
            default_import_path,
            import_preview,
            import_commit,
            export_bookmarks,
            connect,
            disconnect,
            list_dir,
            download,
            upload,
            make_dir,
            remove,
            rename,
            chmod,
            create_file,
            upload_file,
            open_remote_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running Kurir");
}

#[cfg(test)]
mod real_files {
    use super::*;

    /// KURIR_FZ=... KURIR_CD=... cargo test real_files -- --ignored --nocapture
    #[test]
    #[ignore]
    fn summarize() {
        let show = |label: &str, r: R<ImportResult>| match r {
            Ok(r) => {
                println!("{label}: {} bookmarks, warnings: {:?}", r.bookmarks.len(), r.warnings);
                for b in r.bookmarks.iter().take(4) {
                    println!("  {:?} {:?} {}:{} user={} auth={:?} path={:?} folder={:?} pw={}",
                        b.name, b.protocol, b.host, b.port, b.username, b.auth, b.remote_path, b.folder, b.password.is_some());
                }
            }
            Err(e) => println!("{label}: ERROR {e}"),
        };
        if let Ok(p) = std::env::var("KURIR_FZ") { show("filezilla", import_preview("filezilla".into(), p)); }
        if let Ok(p) = std::env::var("KURIR_CD") { show("cyberduck", import_preview("cyberduck".into(), p)); }
    }
}
