# Kurir

**Kurir** — one simple SFTP / FTP(S) / S3 client that combines what you use FileZilla, WinSCP and Cyberduck for. Built with Tauri v2 (Rust + plain HTML/JS).
It imports and exports bookmarks from **FileZilla**, **WinSCP** and **Cyberduck**.

**Download:** [latest release](https://github.com/zonegoh/kurir/releases/latest). The macOS (Apple Silicon) build is not signed yet: right-click Kurir.app → **Open** on first launch.

## Features
- Bookmarks with groups and search; passwords and S3 secret keys are kept in the OS keychain (macOS Keychain / Windows Credential Manager), never in `bookmarks.json`.
- SFTP (password, private key + passphrase, or ssh-agent), FTP, FTPES (explicit TLS), FTPS (implicit TLS), S3 and S3-compatible storage (Cloudian, MinIO, Wasabi…; for a local `http://` endpoint, put the full URL in Host).
- Browse, upload (button or drag & drop from Finder/Explorer), download, new folder, rename, delete. Folders are uploaded, downloaded and deleted recursively.
- Right-click menu like FileZilla: Download, Enter directory, View, Edit (saving the local copy offers to upload it back), Create directory (and enter it), Create new file, Refresh, Delete, Rename (F2), Copy URL(s), File permissions (SFTP/FTP).
- Sidebar grouped by type (SFTP / FTP / S3) or by your own groups; groups can be collapsed.
- Errors are shown in a dialog; S3 XML errors are shortened to the error code, its message and a hint.
- SSH host keys: trust on first use (TOFU), with a hard error if the key changes.

### Note: vendored rust-s3
`src-tauri/vendor/rust-s3` is rust-s3 0.35.1 with one fix: list queries form-encoded spaces as `+`, while the request was signed with `%20`, so listing an S3 folder whose name has a space failed with `SignatureDoesNotMatch` (seen on Cloudian). rust-s3 0.38 still has this bug.

## Import / export formats
| App | Import | Export | Passwords |
|---|---|---|---|
| FileZilla | `sitemanager.xml` (default `~/.config/filezilla/`, `%APPDATA%\FileZilla\`) or a Site Manager export | `sitemanager.xml`; open it with FileZilla → File → Import | base64 `<Pass>` is read. Not read when FileZilla's master password is enabled (`encoding="crypt"`) |
| WinSCP | `WinSCP.ini` (Tools → Export/Backup configuration) | `WinSCP.ini` (Tools → Import/Restore) | WinSCP obfuscation is decoded and encoded. Not read when the master password is enabled |
| Cyberduck | a folder of `.duck` files (default: Cyberduck's Bookmarks folder) or a single file | one `.duck` per bookmark; double-click them or drag them into Cyberduck | Cyberduck keeps passwords in the Keychain, so `.duck` files never contain them |

Protocol mappings come from reverse engineering Cyberduck 9.5.0 (`importer-9.5.0.jar`: `FilezillaBookmarkCollection`, `WinScpBookmarkCollection`; `core-9.5.0.jar`: `HostDictionary`):
- FileZilla `Protocol`: 0 FTP, 1 SFTP, 3 FTPS, 4 FTPES, 6 insecure FTP, 7 S3. `Logontype` 5 means a key file (Cyberduck's own importer ignores `Keyfile`; Kurir keeps it).
- WinSCP `FSProtocol`: 0/1/2 SFTP (SCP is treated as SFTP), 5 FTP (+`Ftps`), 7 S3.
- Cyberduck `ftps` = FTP with explicit TLS. Protocols such as OneDrive, WebDAV and Google Drive are skipped with a warning.

PuTTY `.ppk` keys (format 2 and 3; RSA, Ed25519, ECDSA; with or without passphrase) work directly: libssh2 can't read them, so Kurir converts them to OpenSSH format in memory (`src-tauri/src/ppk.rs`). The decrypted key is never written to disk. WinSCP itself needs `.ppk` keys: after exporting an SFTP bookmark that uses a `.pem` key to WinSCP, convert the key with PuTTYgen.

## Development
```bash
npm install
npm run dev        # run in development
npm run build      # build Kurir.app / .dmg (Windows: .exe installer)
```
Tests:
```bash
cd src-tauri
cargo test                                            # format converters
cargo test live -- --ignored --test-threads=1         # needs local servers (below)
```
Local test servers for `live` (Python venv): `pip install pyftpdlib "moto[server]" sftpserver`, then
`python -m pyftpdlib -i 127.0.0.1 -p 2121 -w -u test -P test`, `sftpserver -k hostkey --host 127.0.0.1 -p 2222`,
`moto_server -H 127.0.0.1 -p 5055` and `curl -X PUT http://127.0.0.1:5055/testbucket`.

Data: `~/Library/Application Support/com.ptscbd.kurir/` (`bookmarks.json`, `known_hosts.json`).

## Not in v1 yet
Transfer queue with progress bar, parallel transfers, resume, editing files in place, folder sync, WebDAV/OneDrive/Google Drive.

## License
MIT — see [LICENSE](LICENSE). `src-tauri/vendor/rust-s3` is [rust-s3](https://github.com/durch/rust-s3) (MIT), with the small patch described above.

Kurir is not affiliated with FileZilla, WinSCP or Cyberduck; it only reads and writes their bookmark formats.
