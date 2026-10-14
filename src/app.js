const { invoke } = window.__TAURI__.core;
const dialog = window.__TAURI__.dialog;

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const LABEL = { sftp: "SFTP", ftp: "FTP", ftps: "FTPS", ftpes: "FTPES", s3: "S3" };
const PORT = { sftp: 22, ftp: 21, ftpes: 21, ftps: 990, s3: 443 };

const state = {
  bookmarks: [],
  activeId: null,
  session: null, // { id, bookmark, path }
  entries: [],
  selected: new Set(),
  lastClicked: null,
};

// ---------- status ----------
function status(msg, kind = "") {
  const el = $("#status");
  el.textContent = msg;
  el.className = "status " + kind;
}
async function busy(msg, fn) {
  status(msg, "busy");
  try {
    const r = await fn();
    status("Ready");
    return r;
  } catch (e) {
    status(msg.replace(/…$/, "") + " failed", "error");
    showError(e);
    throw e;
  }
}

function showError(e, title = "Something went wrong") {
  const raw = String(e?.message ?? e);
  // Backend errors look like "Context: detail"; show the context as the title.
  const m = raw.match(/^([A-Z][\w ()]{2,40}): ([\s\S]+)$/);
  $("#err-title").textContent = m ? m[1] : title;
  const msg = m ? m[2] : raw;
  $("#err-msg").textContent = msg.length > 600 ? msg.slice(0, 600) + "…" : msg;
  $("#err-raw").textContent = raw;
  $("#err-details").hidden = msg.length <= 600;
  $("#err-copy").onclick = () => navigator.clipboard?.writeText(raw);
  const dlg = $("#dlg-error");
  if (!dlg.open) dlg.showModal();
}

/** Text input dialog; resolves to the trimmed value or null. */
function inputDialog(title, value = "", okLabel = "OK") {
  return new Promise((resolve) => {
    const dlg = $("#dlg-input"), input = $("#in-value");
    $("#in-title").textContent = title;
    $("#in-ok").textContent = okLabel;
    input.value = value;
    dlg.returnValue = "";
    dlg.onclose = () => resolve(dlg.returnValue === "ok" && input.value.trim() ? input.value.trim() : null);
    dlg.showModal();
    input.focus();
    // Select the name without its extension, like Finder.
    const dot = value.lastIndexOf(".");
    input.setSelectionRange(0, dot > 0 ? dot : value.length);
  });
}

// ---------- bookmarks sidebar ----------
async function loadBookmarks() {
  state.bookmarks = await invoke("list_bookmarks");
  renderBookmarks();
}

const TYPE_GROUPS = [
  ["sftp", "SFTP / SSH", ["sftp"]],
  ["ftp", "FTP / FTPS", ["ftp", "ftps", "ftpes"]],
  ["s3", "S3 / Object storage", ["s3"]],
];
const typeGroup = (b) => (TYPE_GROUPS.find(([, , ps]) => ps.includes(b.protocol)) || ["other", "Other"]);
const prefs = (() => {
  try { return JSON.parse(localStorage.getItem("kurir.prefs")) || {}; } catch { return {}; }
})();
prefs.groupBy ??= "type";
prefs.collapsed ??= [];
const savePrefs = () => { try { localStorage.setItem("kurir.prefs", JSON.stringify(prefs)); } catch {} };

document.querySelectorAll("#group-by button").forEach((btn) => {
  btn.classList.toggle("on", btn.dataset.group === prefs.groupBy);
  btn.onclick = () => {
    prefs.groupBy = btn.dataset.group;
    document.querySelectorAll("#group-by button").forEach((x) => x.classList.toggle("on", x === btn));
    savePrefs();
    renderBookmarks();
  };
});

function renderBookmarks() {
  const q = $("#search").value.toLowerCase();
  const byType = prefs.groupBy === "type";
  const order = (b) => (byType ? TYPE_GROUPS.findIndex(([k]) => k === typeGroup(b)[0]) + 1 || 99 : 0);
  const key = (b) => (byType ? typeGroup(b)[0] : b.folder || "");
  const label = (b) => (byType ? typeGroup(b)[1] : b.folder || "Ungrouped");
  const list = state.bookmarks
    .filter((b) => !q || [b.name, b.host, b.username, b.folder, b.protocol].join(" ").toLowerCase().includes(q))
    .sort((a, b) => order(a) - order(b) || key(a).localeCompare(key(b)) || displayName(a).localeCompare(displayName(b)));
  const counts = {};
  list.forEach((b) => (counts[key(b)] = (counts[key(b)] || 0) + 1));
  const ul = $("#bookmarks");
  ul.innerHTML = "";
  let group = null;
  for (const b of list) {
    const k = key(b);
    const ck = prefs.groupBy + ":" + k;
    const collapsed = !q && prefs.collapsed.includes(ck);
    if (k !== group) {
      group = k;
      const gl = document.createElement("li");
      gl.className = "group" + (collapsed ? " collapsed" : "");
      gl.innerHTML = `<span class="chev">▾</span>${esc(label(b))}<span class="count">${counts[k]}</span>`;
      gl.onclick = () => {
        const i = prefs.collapsed.indexOf(ck);
        i >= 0 ? prefs.collapsed.splice(i, 1) : prefs.collapsed.push(ck);
        savePrefs();
        renderBookmarks();
      };
      ul.appendChild(gl);
    }
    if (collapsed) continue;
    const li = document.createElement("li");
    li.className = "bm" + (b.id === state.activeId ? " active" : "");
    li.innerHTML = `<span class="badge ${b.protocol}">${LABEL[b.protocol]}</span>
      <div class="info"><div>${esc(displayName(b))}</div>
      <div class="muted small">${esc(b.username ? b.username + "@" : "")}${esc(b.host)}${b.port !== PORT[b.protocol] ? ":" + b.port : ""}</div>
      ${byType && b.folder ? `<div class="sub">${esc(b.folder)}</div>` : ""}</div>
      <button class="edit" title="Edit">✎</button>`;
    li.onclick = () => { state.activeId = b.id; renderBookmarks(); };
    li.ondblclick = () => connect(b);
    li.oncontextmenu = (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      state.activeId = b.id;
      renderBookmarks();
      showBookmarkMenu(b, ev.clientX, ev.clientY);
    };
    li.querySelector(".edit").onclick = (e) => { e.stopPropagation(); editBookmark(b); };
    ul.appendChild(li);
  }
  if (!list.length) ul.innerHTML = `<li class="muted small" style="padding:8px">No bookmarks yet.</li>`;
  $("#folders").innerHTML = [...new Set(state.bookmarks.map((b) => b.folder).filter(Boolean))]
    .map((f) => `<option value="${esc(f)}">`).join("");
}
const displayName = (b) => b.name || (b.username ? `${b.username}@${b.host}` : b.host);

// ---------- bookmark editor ----------
const form = $("#form-bookmark");
function syncFormVisibility() {
  const proto = form.protocol.value, auth = form.auth.value;
  const s3 = proto === "s3";
  form.querySelectorAll("[data-show=key]").forEach((el) => (el.hidden = auth !== "key"));
  form.querySelectorAll("[data-show=s3]").forEach((el) => (el.hidden = !s3));
  form.querySelectorAll("[data-s3]").forEach((el) => {
    el.dataset.plain ??= el.textContent;
    el.textContent = s3 ? el.dataset.s3 : el.dataset.plain;
  });
  form.auth.querySelector("[value=key]").disabled = proto !== "sftp";
}
form.protocol.onchange = () => {
  const old = Number(form.port.value);
  if (!old || Object.values(PORT).includes(old)) form.port.value = PORT[form.protocol.value];
  if (form.protocol.value !== "sftp" && form.auth.value === "key") form.auth.value = "password";
  syncFormVisibility();
};
form.auth.onchange = syncFormVisibility;
$("#pick-key").onclick = async () => {
  const p = await dialog.open({ title: "Choose private key", defaultPath: form.key_path.value || undefined });
  if (p) form.key_path.value = p;
};

function editBookmark(b) {
  const isNew = !b;
  b = b || { id: "", protocol: "sftp", port: 22, auth: "password" };
  $("#bm-title").textContent = isNew ? "New bookmark" : "Edit bookmark";
  for (const k of ["name", "protocol", "host", "port", "username", "auth", "key_path", "region", "remote_path", "local_path", "folder", "comment"]) {
    form[k].value = b[k] ?? "";
  }
  form.password.value = "";
  form.password.placeholder = b.has_password ? "•••••• (saved — leave blank to keep)" : "";
  $("#bm-delete").hidden = isNew;
  $("#bm-delete").onclick = async () => {
    if (!(await dialog.confirm(`Delete bookmark "${displayName(b)}"?`, { kind: "warning" }))) return;
    await invoke("delete_bookmark", { id: b.id });
    $("#dlg-bookmark").close("deleted");
    await loadBookmarks();
  };
  syncFormVisibility();
  const dlg = $("#dlg-bookmark");
  dlg.onclose = async () => {
    if (dlg.returnValue !== "save") return;
    const out = { ...b };
    delete out.has_password;
    for (const el of form.elements) if (el.name && el.name !== "password") out[el.name] = el.value.trim();
    out.port = Number(out.port) || PORT[out.protocol];
    if (form.password.value) out.password = form.password.value;
    try {
      const saved = await invoke("save_bookmark", { bookmark: out });
      state.activeId = saved.id;
      await loadBookmarks();
      status(`Saved "${displayName(saved)}"`);
    } catch (e) { showError(e, "Could not save bookmark"); }
  };
  dlg.returnValue = "";
  dlg.showModal();
  form.host.focus();
}
$("#btn-new").onclick = () => editBookmark(null);

// ---------- password prompt ----------
function askPassword(b) {
  return new Promise((resolve) => {
    const dlg = $("#dlg-password");
    $("#pw-title").textContent = b.protocol === "s3" ? `Secret key for ${displayName(b)}` :
      b.auth === "key" ? `Key passphrase for ${displayName(b)} (blank if none)` : `Password for ${displayName(b)}`;
    $("#pw-input").value = "";
    $("#pw-remember").checked = false;
    $("#pw-remember").parentElement.hidden = b.auth === "ask";
    dlg.returnValue = "";
    dlg.onclose = () => resolve(dlg.returnValue === "ok" ? { password: $("#pw-input").value, remember: $("#pw-remember").checked } : null);
    dlg.showModal();
  });
}

// ---------- connection ----------
async function connect(b) {
  if (state.session) await disconnect();
  let password = null, remember = false;
  const needsPrompt =
    b.auth === "ask" ||
    (b.auth === "password" && !b.has_password) ||
    (b.protocol === "s3" && !b.has_password);
  if (needsPrompt) {
    const r = await askPassword(b);
    if (!r) return;
    ({ password, remember } = r);
  }
  let info;
  for (let attempt = 0; ; attempt++) {
    try {
      status(`Connecting to ${b.host}…`, "busy");
      info = await invoke("connect", { id: b.id, password, remember });
      status("Ready");
      break;
    } catch (e) {
      // Encrypted private key (.ppk or OpenSSH) without / with a wrong passphrase: ask for it.
      if (b.auth === "key" && attempt < 3 && /passphrase/i.test(String(e))) {
        if (attempt > 0) status("Wrong passphrase, try again", "error");
        const r = await askPassword(b);
        if (!r) { status("Cancelled"); return; }
        ({ password, remember } = r);
        continue;
      }
      status("Connection failed", "error");
      showError(e);
      return;
    }
  }
  try {
    state.session = { id: info.session_id, bookmark: b, path: info.home || "/" };
    state.activeId = b.id;
    if (remember) await loadBookmarks(); else renderBookmarks();
    $("#empty").hidden = true;
    $("#browser").hidden = false;
    $("#conn-label").textContent = `${LABEL[b.protocol]} · ${b.username ? b.username + "@" : ""}${b.host}`;
    await openDir(state.session.path);
    if (info.notice) status(info.notice);
  } catch (_) { /* status already shows the error */ }
}

async function disconnect() {
  if (!state.session) return;
  await invoke("disconnect", { sessionId: state.session.id });
  state.session = null;
  $("#browser").hidden = true;
  $("#empty").hidden = false;
  $("#conn-label").textContent = "";
  status("Disconnected");
}

const join = (dir, name) => (dir.endsWith("/") ? dir + name : dir + "/" + name);
const parent = (p) => {
  const t = p.replace(/\/+$/, "");
  const i = t.lastIndexOf("/");
  return i <= 0 ? "/" : t.slice(0, i);
};

async function openDir(path) {
  const s = state.session;
  try {
    const entries = await busy(`Listing ${path}…`, () => invoke("list_dir", { sessionId: s.id, path }));
    s.path = path;
    state.entries = entries;
    state.selected.clear();
    $("#path").value = path;
    renderFiles();
    status(`${entries.length} item(s) in ${path}`);
  } catch (_) {}
}

function fmtSize(n) {
  if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB", "TB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n < 10 ? 1 : 0) + " " + u[i];
}
const fmtDate = (t) => (t ? new Date(t * 1000).toLocaleString() : "");

function fmtPerms(p) {
  if (p == null) return "";
  const rwx = (n) => (n & 4 ? "r" : "-") + (n & 2 ? "w" : "-") + (n & 1 ? "x" : "-");
  return rwx(p >> 6) + rwx(p >> 3) + rwx(p) + ` (${(p & 0o777).toString(8)})`;
}

function renderFiles() {
  const tb = $("#files");
  tb.innerHTML = "";
  if (state.session.path !== "/") {
    const up = document.createElement("tr");
    up.className = "updir";
    up.innerHTML = `<td>📁 ..</td><td></td><td></td><td></td>`;
    up.ondblclick = () => openDir(parent(state.session.path));
    up.onclick = () => { state.selected.clear(); renderFiles(); };
    tb.appendChild(up);
  }
  state.entries.forEach((e, i) => {
    const tr = document.createElement("tr");
    if (state.selected.has(i)) tr.className = "sel";
    tr.innerHTML = `<td>${e.is_dir ? "📁" : "📄"} ${esc(e.name)}</td><td class="num">${e.is_dir ? "" : fmtSize(e.size)}</td><td>${fmtDate(e.modified)}</td><td><span class="perm">${fmtPerms(e.perms)}</span></td>`;
    tr.onclick = (ev) => select(i, ev);
    tr.ondblclick = () => (e.is_dir ? openDir(join(state.session.path, e.name)) : openRemote(e, false));
    tr.oncontextmenu = (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      if (!state.selected.has(i)) { state.selected = new Set([i]); state.lastClicked = i; renderFiles(); }
      showContextMenu(ev.clientX, ev.clientY);
    };
    tb.appendChild(tr);
  });
  const none = state.selected.size === 0;
  for (const id of ["#btn-download", "#btn-delete"]) $(id).disabled = none;
  $("#btn-rename").disabled = state.selected.size !== 1;
}

function select(i, ev) {
  if (ev.shiftKey && state.lastClicked != null) {
    const [a, b] = [state.lastClicked, i].sort((x, y) => x - y);
    for (let k = a; k <= b; k++) state.selected.add(k);
  } else if (ev.metaKey || ev.ctrlKey) {
    state.selected.has(i) ? state.selected.delete(i) : state.selected.add(i);
    state.lastClicked = i;
  } else {
    state.selected = new Set([i]);
    state.lastClicked = i;
  }
  renderFiles();
}
const selectedEntries = () => [...state.selected].map((i) => state.entries[i]);

async function downloadSelected(entries = selectedEntries()) {
  if (!entries.length) return;
  const b = state.session.bookmark;
  const dir = await dialog.open({ directory: true, title: "Download to…", defaultPath: b.local_path || undefined });
  if (!dir) return;
  const items = entries.map((e) => ({ path: join(state.session.path, e.name), is_dir: e.is_dir }));
  try {
    const n = await busy(`Downloading ${items.length} item(s)…`, () =>
      invoke("download", { sessionId: state.session.id, items, localDir: dir }));
    status(`Downloaded ${n} file(s) to ${dir}`);
  } catch (_) {}
}

async function uploadPaths(paths) {
  if (!paths?.length || !state.session) return;
  try {
    const n = await busy(`Uploading ${paths.length} item(s)…`, () =>
      invoke("upload", { sessionId: state.session.id, localPaths: paths, remoteDir: state.session.path }));
    await openDir(state.session.path);
    status(`Uploaded ${n} file(s)`);
  } catch (_) {}
}

$("#btn-upload").onclick = async () => {
  const paths = await dialog.open({ multiple: true, title: "Upload files" });
  uploadPaths(Array.isArray(paths) ? paths : paths ? [paths] : []);
};
$("#btn-download").onclick = () => downloadSelected();
$("#btn-up").onclick = () => openDir(parent(state.session.path));
$("#btn-refresh").onclick = () => openDir(state.session.path);
$("#btn-disconnect").onclick = disconnect;
$("#path").onkeydown = (e) => { if (e.key === "Enter") openDir($("#path").value.trim() || "/"); };

async function createDir(enter = false) {
  const name = await inputDialog("Create directory", "", "Create");
  if (!name) return;
  const path = join(state.session.path, name);
  try {
    await busy("Creating folder…", () => invoke("make_dir", { sessionId: state.session.id, path }));
    await openDir(enter ? path : state.session.path);
  } catch (_) {}
}

async function createFile() {
  const name = await inputDialog("Create new file", "", "Create");
  if (!name) return;
  try {
    await busy("Creating file…", () => invoke("create_file", { sessionId: state.session.id, path: join(state.session.path, name) }));
    await openDir(state.session.path);
  } catch (_) {}
}

/** Opens a remote file locally. Saving an edited copy offers to upload it back. */
async function openRemote(e, edit) {
  try {
    await busy(`Opening ${e.name}…`, () =>
      invoke("open_remote_file", { sessionId: state.session.id, remote: join(state.session.path, e.name), edit }));
    status(edit ? `Editing ${e.name} — save it to upload the changes` : `Opened ${e.name}`);
  } catch (_) {}
}

const pendingUploads = new Set();
window.__TAURI__.event.listen("file-changed", async ({ payload: p }) => {
  if (pendingUploads.has(p.remote) || p.session_id !== state.session?.id) return;
  pendingUploads.add(p.remote);
  try {
    const name = p.remote.split("/").pop();
    const yes = await dialog.ask(`"${name}" was changed locally.\n\nUpload it back to the server?\n${p.remote}`,
      { title: "File changed", okLabel: "Upload", cancelLabel: "Not now" });
    if (yes) {
      await busy(`Uploading ${name}…`, () => invoke("upload_file", { sessionId: p.session_id, local: p.local, remote: p.remote }));
      status(`Uploaded ${name}`);
      if (parent(p.remote) === state.session?.path) openDir(state.session.path);
    }
  } catch (_) {
  } finally {
    pendingUploads.delete(p.remote);
  }
});

function remoteUrl(e) {
  const b = state.session.bookmark;
  const path = join(state.session.path, e.name) + (e.is_dir ? "/" : "");
  if (b.protocol === "s3") return "s3:/" + path;
  const scheme = { sftp: "sftp", ftp: "ftp", ftpes: "ftpes", ftps: "ftps" }[b.protocol];
  const port = b.port !== PORT[b.protocol] ? ":" + b.port : "";
  const user = b.username ? encodeURIComponent(b.username) + "@" : "";
  return `${scheme}://${user}${b.host}${port}${encodeURI(path)}`;
}

function editPermissions() {
  const es = selectedEntries();
  if (!es.length) return;
  const dlg = $("#dlg-perms");
  const boxes = [...dlg.querySelectorAll("input[data-bit]")];
  const octal = $("#perm-octal");
  const setFrom = (mode) => {
    boxes.forEach((c) => (c.checked = (mode & Number(c.dataset.bit)) !== 0));
    octal.value = (mode & 0o777).toString(8).padStart(3, "0");
  };
  setFrom(es[0].perms ?? (es[0].is_dir ? 0o755 : 0o644));
  boxes.forEach((c) => (c.onchange = () => setFrom(boxes.reduce((m, x) => m | (x.checked ? Number(x.dataset.bit) : 0), 0))));
  octal.oninput = () => { if (/^[0-7]{3,4}$/.test(octal.value)) boxes.forEach((c) => (c.checked = (parseInt(octal.value, 8) & Number(c.dataset.bit)) !== 0)); };
  $("#perm-title").textContent = es.length === 1 ? `Permissions of "${es[0].name}"` : `Permissions of ${es.length} items`;
  dlg.returnValue = "";
  dlg.onclose = async () => {
    if (dlg.returnValue !== "ok" || !/^[0-7]{3,4}$/.test(octal.value)) return;
    const mode = parseInt(octal.value, 8);
    try {
      await busy("Changing permissions…", () =>
        invoke("chmod", { sessionId: state.session.id, paths: es.map((e) => join(state.session.path, e.name)), mode }));
      await openDir(state.session.path);
    } catch (_) {}
  };
  dlg.showModal();
}

// ---------- context menu (FileZilla style) ----------
function showContextMenu(x, y) {
  const es = selectedEntries();
  const one = es.length === 1 ? es[0] : null;
  const proto = state.session.bookmark.protocol;
  const items = [
    ["⬇", "Download", es.length > 0, () => downloadSelected()],
    ["↵", "Enter directory", one?.is_dir, () => openDir(join(state.session.path, one.name))],
    ["👁", "View", one && !one.is_dir, () => openRemote(one, false)],
    ["✎", "Edit", one && !one.is_dir, () => openRemote(one, true)],
    "-",
    ["📁", "Create directory", true, () => createDir(false)],
    ["📂", "Create directory and enter it", true, () => createDir(true)],
    ["📄", "Create new file", true, createFile],
    ["⟳", "Refresh", true, () => openDir(state.session.path)],
    "-",
    ["🗑", "Delete", es.length > 0, () => $("#btn-delete").click(), "⌫"],
    ["✏️", "Rename", !!one, () => $("#btn-rename").click(), "F2"],
    ["🔗", "Copy URL(s) to clipboard", es.length > 0, () => {
      navigator.clipboard.writeText(es.map(remoteUrl).join("\n"));
      status(`Copied ${es.length} URL(s)`);
    }],
    ["🔒", "File permissions…", es.length > 0 && proto !== "s3", editPermissions],
  ];
  const menu = $("#ctx");
  menu.innerHTML = "";
  for (const it of items) {
    if (it === "-") { menu.appendChild(document.createElement("hr")); continue; }
    const [ic, label, enabled, fn, key] = it;
    const b = document.createElement("button");
    b.innerHTML = `<span class="ic">${ic}</span>${label}${key ? `<span class="key">${key}</span>` : ""}`;
    b.disabled = !enabled;
    b.onclick = () => { hideContextMenu(); fn(); };
    menu.appendChild(b);
  }
  menu.hidden = false;
  const r = menu.getBoundingClientRect();
  menu.style.left = Math.min(x, innerWidth - r.width - 8) + "px";
  menu.style.top = Math.min(y, innerHeight - r.height - 8) + "px";
}
const hideContextMenu = () => ($("#ctx").hidden = true);
document.addEventListener("click", (e) => { if (!e.target.closest("#ctx")) hideContextMenu(); });
document.addEventListener("contextmenu", (e) => { if (!e.target.closest("#drop-zone, #bookmarks")) hideContextMenu(); });
window.addEventListener("blur", hideContextMenu);
$("#drop-zone").oncontextmenu = (ev) => {
  // Right-click on empty space: clear the selection, show the folder actions.
  ev.preventDefault();
  if (!state.session) return;
  state.selected.clear();
  renderFiles();
  showContextMenu(ev.clientX, ev.clientY);
};

$("#btn-mkdir").onclick = () => createDir(false);
$("#btn-newfile").onclick = createFile;
$("#btn-rename").onclick = async () => {
  const [e] = selectedEntries();
  const name = await inputDialog("Rename", e.name, "Rename");
  if (!name || name === e.name) return;
  const dir = state.session.path;
  try {
    await busy("Renaming…", () => invoke("rename", { sessionId: state.session.id, from: join(dir, e.name), to: join(dir, name) }));
    await openDir(dir);
  } catch (_) {}
};
$("#btn-delete").onclick = async () => {
  const es = selectedEntries();
  const label = es.length === 1 ? `"${es[0].name}"` : `${es.length} items`;
  const dirs = es.some((e) => e.is_dir) ? " Folders are deleted with everything inside." : "";
  if (!(await dialog.confirm(`Delete ${label} on the server?${dirs} This cannot be undone.`, { kind: "warning", okLabel: "Delete" }))) return;
  const items = es.map((e) => ({ path: join(state.session.path, e.name), is_dir: e.is_dir }));
  try {
    await busy("Deleting…", () => invoke("remove", { sessionId: state.session.id, items }));
    await openDir(state.session.path);
  } catch (_) {}
};

// Drag files from Finder / Explorer onto the file list to upload.
window.__TAURI__.webview.getCurrentWebview().onDragDropEvent((ev) => {
  const zone = $("#drop-zone");
  const t = ev.payload.type;
  if (t === "enter" || t === "over") zone.classList.toggle("dragover", !!state.session);
  else zone.classList.remove("dragover");
  if (t === "drop") uploadPaths(ev.payload.paths);
});

// ---------- import ----------
const KIND_NAME = { filezilla: "FileZilla", winscp: "WinSCP", cyberduck: "Cyberduck" };

document.querySelectorAll("[data-import]").forEach((btn) => (btn.onclick = () => startImport(btn.dataset.import)));

async function startImport(kind) {
  document.activeElement?.blur();
  const def = await invoke("default_import_path", { kind });
  let path;
  if (kind === "cyberduck") {
    const useDefault = def && (await dialog.ask(`Import all Cyberduck bookmarks from\n${def}?\n\nChoose "No" to pick a folder or .duck file yourself.`, { title: "Cyberduck", okLabel: "Yes", cancelLabel: "No" }));
    path = useDefault ? def : await dialog.open({ title: "Choose Cyberduck Bookmarks folder", directory: true });
  } else {
    const filters = kind === "filezilla" ? [{ name: "FileZilla XML", extensions: ["xml"] }] : [{ name: "WinSCP INI", extensions: ["ini"] }];
    path = await dialog.open({ title: `Choose ${KIND_NAME[kind]} file`, defaultPath: def || undefined, filters });
  }
  if (!path) return;
  let res;
  try {
    res = await busy("Reading bookmarks…", () => invoke("import_preview", { kind, path }));
  } catch (_) { return; }
  showImportPreview(kind, path, res);
}

function showImportPreview(kind, path, res) {
  const existing = new Map(state.bookmarks.map((b) => [`${b.protocol}|${b.host}|${b.port}|${b.username}`, b]));
  $("#imp-title").textContent = `Import from ${KIND_NAME[kind]} — ${res.bookmarks.length} found`;
  $("#imp-source").textContent = path;
  $("#imp-warnings").innerHTML = res.warnings.map((w) => `<li>⚠️ ${esc(w)}</li>`).join("");
  const ul = $("#imp-list");
  ul.innerHTML = res.bookmarks.map((b, i) => {
    const ex = existing.get(`${b.protocol}|${b.host}|${b.port}|${b.username}`) || state.bookmarks.find((x) => x.id === b.id);
    // An existing bookmark is pre-selected only when the import adds a missing password/secret.
    const adds = ex && b.password && !ex.has_password;
    const dup = ex && !adds;
    return `<li><input type="checkbox" data-i="${i}" ${dup ? "" : "checked"} />
      <span class="badge ${b.protocol}">${LABEL[b.protocol]}</span>
      <span class="info">${esc(b.folder ? b.folder + " / " : "")}<b>${esc(displayName(b))}</b>
      <span class="muted">${esc(b.username ? b.username + "@" : "")}${esc(b.host)}:${b.port}</span></span>
      <span class="muted small">${b.password ? (b.protocol === "s3" ? "🔑 key + secret" : "🔑 password") : b.auth === "key" ? "🗝 key" : ""}${adds ? " · updates existing" : dup ? " · already exists" : ""}</span></li>`;
  }).join("") || `<li class="muted">Nothing importable.</li>`;
  $("#imp-all").onchange = (e) => ul.querySelectorAll("input").forEach((c) => (c.checked = e.target.checked));
  const dlg = $("#dlg-import");
  dlg.returnValue = "";
  dlg.onclose = async () => {
    if (dlg.returnValue !== "ok") return;
    const chosen = [...ul.querySelectorAll("input:checked")].map((c) => res.bookmarks[c.dataset.i]);
    if (!chosen.length) return;
    try {
      const n = await busy("Importing…", () => invoke("import_commit", { bookmarks: chosen }));
      await loadBookmarks();
      status(`Imported ${n} bookmark(s) from ${KIND_NAME[kind]}`);
    } catch (_) {}
  };
  dlg.showModal();
}

// ---------- delete several bookmarks ----------
async function deleteBookmarks(ids) {
  if (!ids.length) return;
  const label = ids.length === 1
    ? `"${displayName(state.bookmarks.find((b) => b.id === ids[0]))}"`
    : `${ids.length} bookmarks`;
  if (!(await dialog.confirm(`Delete ${label}? Saved passwords are removed too.`, { kind: "warning", okLabel: "Delete" }))) return false;
  try {
    const n = await busy("Deleting bookmarks…", () => invoke("delete_bookmarks", { ids }));
    if (ids.includes(state.activeId)) state.activeId = null;
    await loadBookmarks();
    status(`Deleted ${n} bookmark(s)`);
    return true;
  } catch (_) { return false; }
}

$("#btn-bulk-delete").onclick = () => openDeleteDialog();

function openDeleteDialog(preselect = []) {
  const dlg = $("#dlg-delete"), ul = $("#del-list"), search = $("#del-search");
  const checked = new Set(preselect);
  const sorted = [...state.bookmarks].sort((a, b) =>
    typeGroup(a)[0].localeCompare(typeGroup(b)[0]) || displayName(a).localeCompare(displayName(b)));
  const visible = () => {
    const q = search.value.toLowerCase();
    return sorted.filter((b) => !q || [b.name, b.host, b.username, b.folder, b.protocol].join(" ").toLowerCase().includes(q));
  };
  const sync = () => {
    const vis = visible();
    $("#del-all").checked = vis.length > 0 && vis.every((b) => checked.has(b.id));
    $("#del-all").indeterminate = !$("#del-all").checked && vis.some((b) => checked.has(b.id));
    $("#del-count").textContent = `${checked.size} of ${state.bookmarks.length} selected`;
    $("#del-ok").disabled = checked.size === 0;
    $("#del-ok").textContent = checked.size ? `Delete ${checked.size}` : "Delete";
  };
  const render = () => {
    ul.innerHTML = visible().map((b) => `<li><input type="checkbox" value="${esc(b.id)}" ${checked.has(b.id) ? "checked" : ""} />
      <span class="badge ${b.protocol}">${LABEL[b.protocol]}</span>
      <span class="info">${esc(b.folder ? b.folder + " / " : "")}<b>${esc(displayName(b))}</b> <span class="muted">${esc(b.host)}</span></span></li>`).join("")
      || `<li class="muted">No bookmarks.</li>`;
    ul.querySelectorAll("input").forEach((c) => (c.onchange = () => { c.checked ? checked.add(c.value) : checked.delete(c.value); sync(); }));
    sync();
  };
  search.value = "";
  search.oninput = render;
  $("#del-all").onchange = (e) => { visible().forEach((b) => (e.target.checked ? checked.add(b.id) : checked.delete(b.id))); render(); };
  dlg.querySelectorAll("[data-deltype]").forEach((btn) => (btn.onclick = () => {
    const of = sorted.filter((b) => typeGroup(b)[0] === btn.dataset.deltype);
    const all = of.every((b) => checked.has(b.id));
    of.forEach((b) => (all ? checked.delete(b.id) : checked.add(b.id)));
    render();
  }));
  dlg.returnValue = "";
  dlg.onclose = () => { if (dlg.returnValue === "ok") deleteBookmarks([...checked]); };
  render();
  dlg.showModal();
}

// Right-click on a bookmark in the sidebar.
function showBookmarkMenu(b, x, y) {
  const menu = $("#ctx");
  menu.innerHTML = "";
  const items = [
    ["🔌", "Connect", () => connect(b)],
    ["✎", "Edit…", () => editBookmark(b)],
    "-",
    ["🗑", "Delete", () => deleteBookmarks([b.id])],
    ["☑️", "Delete several…", () => openDeleteDialog([b.id])],
  ];
  for (const it of items) {
    if (it === "-") { menu.appendChild(document.createElement("hr")); continue; }
    const btn = document.createElement("button");
    btn.innerHTML = `<span class="ic">${it[0]}</span>${it[1]}`;
    btn.onclick = () => { hideContextMenu(); it[2](); };
    menu.appendChild(btn);
  }
  menu.hidden = false;
  const r = menu.getBoundingClientRect();
  menu.style.left = Math.min(x, innerWidth - r.width - 8) + "px";
  menu.style.top = Math.min(y, innerHeight - r.height - 8) + "px";
}

// ---------- export ----------
$("#btn-export").onclick = () => {
  const ul = $("#exp-list");
  ul.innerHTML = state.bookmarks.map((b) => `<li><input type="checkbox" value="${esc(b.id)}" checked />
    <span class="badge ${b.protocol}">${LABEL[b.protocol]}</span>
    <span class="info">${esc(b.folder ? b.folder + " / " : "")}<b>${esc(displayName(b))}</b> <span class="muted">${esc(b.host)}</span></span></li>`).join("")
    || `<li class="muted">No bookmarks to export.</li>`;
  $("#exp-all").checked = true;
  $("#exp-all").onchange = (e) => ul.querySelectorAll("input").forEach((c) => (c.checked = e.target.checked));
  const dlg = $("#dlg-export");
  dlg.returnValue = "";
  dlg.onclose = async () => {
    if (dlg.returnValue !== "ok") return;
    const ids = [...ul.querySelectorAll("input:checked")].map((c) => c.value);
    if (!ids.length) return;
    const kind = $("#exp-kind").value;
    const path = kind === "cyberduck"
      ? await dialog.open({ directory: true, title: "Choose a folder for the .duck files (double-click them to add to Cyberduck)" })
      : await dialog.save(kind === "filezilla"
        ? { defaultPath: "kurir-sitemanager.xml", filters: [{ name: "FileZilla XML", extensions: ["xml"] }] }
        : { defaultPath: "WinSCP.ini", filters: [{ name: "WinSCP INI", extensions: ["ini"] }] });
    if (!path) return;
    try {
      const msg = await busy("Exporting…", () => invoke("export_bookmarks", { kind, ids, path, includePasswords: $("#exp-pw").checked }));
      status(msg);
    } catch (_) {}
  };
  dlg.showModal();
};

// ---------- start ----------
$("#search").oninput = renderBookmarks;
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") hideContextMenu();
  if (!state.session || e.target.tagName === "INPUT" || document.querySelector("dialog[open]")) return;
  const [one] = state.selected.size === 1 ? selectedEntries() : [];
  if (e.key === "F2" && one) return $("#btn-rename").click();
  if (e.key === "Enter" && one) return one.is_dir ? openDir(join(state.session.path, one.name)) : openRemote(one, false);
  if (((e.key === "Backspace" && e.metaKey) || e.key === "Delete") && state.selected.size) $("#btn-delete").click();
  else if (e.key === "Backspace") $("#btn-up").click();
  else if ((e.metaKey || e.ctrlKey) && e.key === "a") { e.preventDefault(); state.entries.forEach((_, i) => state.selected.add(i)); renderFiles(); }
});
loadBookmarks().catch((e) => showError(e, "Could not load bookmarks"));
