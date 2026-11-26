"use strict";

const $ = id => document.getElementById(id);
const END_MARK = "-----END SSH SIGNATURE-----";

let me = null;          // { user, role, level }
let entries = [];
let editingId = null;   // null | "new" | id
let challenge = null;   // { nonce, namespace, expiresInSeconds }
let timerHandle = null;
let busy = false;

/* ---------- utilità ---------- */
async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", headers: {}, credentials: "same-origin" };
  if (opts.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.body);
  }
  const r = await fetch(path, init);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    const err = new Error(data.error || `Errore ${r.status}`);
    err.status = r.status;
    throw err;
  }
  return data;
}

// "vars" imposta variabili CSS via JavaScript: la CSP non blocca questo modo, a differenza di style="..."
function el(tag, props = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k === "vars") {
      for (const [name, val] of Object.entries(v)) n.style.setProperty(name, String(val));
    }
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const c of children) n.append(c);
  return n;
}

function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove("show"), 2200);
}

function show(id, visible) {
  $(id).hidden = !visible;
}

/* ---------- login ---------- */
function buildCommand() {
  const key = $("keypath").value.trim() || "~/.ssh/id_ed25519";
  const { nonce, namespace } = challenge;
  // Un solo comando: crea il file della sfida, lo firma, stampa la firma, pulisce i file.
  return `rm -f kr-login.txt kr-login.txt.sig && printf '%s' '${nonce}' > kr-login.txt && ssh-keygen -Y sign -f ${key} -n ${namespace} kr-login.txt && cat kr-login.txt.sig && rm -f kr-login.txt kr-login.txt.sig`;
}

function renderCommand() {
  if (challenge) $("cmd").textContent = buildCommand();
}

async function newChallenge() {
  clearInterval(timerHandle);
  $("loginErr").textContent = "";
  $("sig").value = "";
  challenge = await api("api/challenge");
  renderCommand();

  let left = challenge.expiresInSeconds;
  const tick = () => {
    if (left <= 0) {
      clearInterval(timerHandle);
      $("timer").textContent = "Sfida scaduta";
      $("loginErr").textContent = "La sfida è scaduta: premi Nuova sfida.";
      return;
    }
    $("timer").textContent = `Valida ancora ${left} s`;
    left--;
  };
  tick();
  timerHandle = setInterval(tick, 1000);
}

async function copyCommand() {
  try {
    await navigator.clipboard.writeText($("cmd").textContent);
    toast("Comando copiato");
  } catch {
    toast("Copia non riuscita: seleziona il testo a mano");
  }
}

async function login() {
  if (busy) return;
  if (!challenge) return newChallenge();
  const signature = $("sig").value.trim();
  if (!signature.includes(END_MARK)) {
    $("loginErr").textContent = "Incolla l'output completo del comando.";
    return;
  }
  busy = true;
  try {
    await api("api/login", { method: "POST", body: { nonce: challenge.nonce, signature } });
    clearInterval(timerHandle);
    me = await api("api/me");
    await showVault();
  } catch (e) {
    // La sfida viene consumata a ogni tentativo: ne serve una nuova
    $("loginErr").textContent = e.message + ". Copia il nuovo comando e riprova.";
    challenge = null;
    await newChallenge().catch(() => {});
  } finally {
    busy = false;
  }
}

function showLogin() {
  me = null;
  entries = [];
  show("vault", false);
  show("editor", false);
  $("logout").hidden = true;
  $("who").textContent = "";
  show("login", true);
  newChallenge().catch(e => ($("loginErr").textContent = e.message));
}

/* ---------- login con file della chiave ---------- */
async function loginWithKeyFile(file) {
  if (busy) return;
  busy = true;
  $("loginErr").textContent = "";
  $("keyinfo").textContent = "Lettura della chiave…";
  try {
    if (file.size > 16 * 1024) throw new Error("Il file è troppo grande per essere una chiave");
    const parsed = SSHSign.parseOpenSSHKey(await file.text());
    const signer = await SSHSign.importSigner(parsed);
    $("keyinfo").textContent = parsed.comment ? `Chiave: ${parsed.comment}` : "Chiave caricata";

    const c = await api("api/challenge");
    const signature = await SSHSign.signNonce(signer, parsed, c.nonce, c.namespace);
    await api("api/login", { method: "POST", body: { nonce: c.nonce, signature } });

    me = await api("api/me");
    await showVault();
  } catch (e) {
    $("keyinfo").textContent = "";
    if (e.code === "PASSPHRASE") {
      $("loginErr").textContent = "Questa chiave ha una passphrase: usa la sezione qui sotto con il terminale.";
      $("fallback").open = true;
    } else {
      $("loginErr").textContent = e.message;
    }
  } finally {
    busy = false;
    $("keyfile").value = "";
  }
}

/* ---------- vault ---------- */
async function showVault() {
  show("login", false);
  $("logout").hidden = false;
  $("who").textContent = me.user;
  const scopeTxt = me.scope && me.scope !== ".*" ? ` · voci: ${me.scope}` : "";
  $("role").textContent = (me.role === "write" ? "lettura e scrittura" : "sola lettura") + scopeTxt + ` · livello ${me.level}`;
  $("add").hidden = me.role !== "write";
  show("vault", true);
  await loadEntries();
}

async function loadEntries() {
  try {
    entries = (await api("api/entries")).entries;
    renderList();
  } catch (e) {
    if (e.status === 401) return showLogin();
    toast(e.message);
  }
}

const collapsed = new Set();   // percorsi delle cartelle chiuse

// Albero delle cartelle costruito dai percorsi (es. prod/db/main)
function buildTree(list) {
  const root = { folders: new Map(), items: [] };
  for (const entry of list) {
    const parts = entry.name.split("/");
    let node = root;
    let path = "";
    for (const seg of parts.slice(0, -1)) {
      path = path ? `${path}/${seg}` : seg;
      if (!node.folders.has(seg)) node.folders.set(seg, { name: seg, path, folders: new Map(), items: [] });
      node = node.folders.get(seg);
    }
    node.items.push({ entry, leaf: parts[parts.length - 1] });
  }
  return root;
}

function countEntries(node) {
  let n = node.items.length;
  for (const f of node.folders.values()) n += countEntries(f);
  return n;
}

function byText(a, b, key) {
  return a[key].localeCompare(b[key]);
}

function renderList() {
  const q = $("search").value.trim().toLowerCase();
  const list = $("list");
  list.replaceChildren();

  if (q) {
    const hits = entries
      .filter(e => (e.name + " " + e.username + " " + (e.notes || "")).toLowerCase().includes(q))
      .sort((a, b) => byText(a, b, "name"));
    if (!hits.length) list.append(el("p", { class: "muted center", text: "Nessun risultato." }));
    for (const e of hits) list.append(entryRow(e, e.name, 0));
    return;
  }

  if (!entries.length) {
    list.append(el("p", { class: "muted center", text: "Nessuna voce." }));
    return;
  }
  renderNode(buildTree(entries), list, 0);
}

function renderNode(node, container, depth) {
  const folders = [...node.folders.values()].sort((a, b) => byText(a, b, "name"));
  for (const f of folders) {
    const open = !collapsed.has(f.path);
    const actions = el("div", { class: "actions" });
    if (me.role === "write") {
      actions.append(
        el("button", { text: "Nuova voce", onclick: () => openEditor(null, f.path + "/") }),
        el("button", { text: "Rinomina", onclick: () => renameFolder(f.path) }),
        el("button", { class: "danger", text: "Elimina", onclick: () => deleteFolder(f.path) }),
      );
    }
    container.append(el("div", { class: "folder", vars: { "--depth": depth } },
      el("button", {
        class: "tree-toggle",
        text: open ? "▾" : "▸",
        onclick: () => { open ? collapsed.add(f.path) : collapsed.delete(f.path); renderList(); },
      }),
      el("strong", { text: f.name + "/" }),
      el("span", { class: "muted small", text: `${countEntries(f)} voci` }),
      el("span", { class: "grow" }),
      actions,
    ));
    if (open) renderNode(f, container, depth + 1);
  }

  const leaves = [...node.items].sort((a, b) => byText(a, b, "leaf"));
  for (const x of leaves) container.append(entryRow(x.entry, x.leaf, depth));
}

function entryRow(e, label, depth) {
  const vars = { "--depth": depth };
  const levelBadge = el("span", { class: "badge", text: `Livello ${e.level}` });

  // Voce sopra il livello dell'utente: nome e username sì, segreto e note no
  if (e.locked) {
    return el("div", { class: "row item level-" + e.level, vars },
      el("div", { class: "meta" },
        el("strong", { text: label }),
        el("span", { class: "muted small", text: e.username || "—" }),
      ),
      el("div", { class: "secret" }, el("span", { class: "muted small", text: "🔒 Segreto non visibile" })),
      el("div", { class: "actions" }, levelBadge),
    );
  }

  const reveal = el("button", { text: "Mostra" });
  const secretCode = el("code", { text: "••••••••" });
  let shown = false;
  reveal.addEventListener("click", () => {
    shown = !shown;
    secretCode.textContent = shown ? e.secret : "••••••••";
    reveal.textContent = shown ? "Nascondi" : "Mostra";
  });

  const actions = el("div", { class: "actions" },
    levelBadge,
    reveal,
    el("button", { text: "Copia segreto", onclick: () => copy(e.secret, "Segreto copiato") }),
  );
  if (e.username) actions.append(el("button", { text: "Copia user", onclick: () => copy(e.username, "Username copiato") }));
  if (me.role === "write") {
    actions.append(
      el("button", { text: "Modifica", onclick: () => openEditor(e) }),
      el("button", { class: "danger", text: "Elimina", onclick: () => deleteEntry(e) }),
    );
  }

  return el("div", { class: "row item level-" + e.level, vars },
    el("div", { class: "meta" },
      el("strong", { text: label }),
      el("span", { class: "muted small", text: e.username || "—" }),
      e.notes ? el("span", { class: "muted small", text: e.notes }) : '',
    ),
    el("div", { class: "secret" }, secretCode),
    actions,
  );
}

async function renameFolder(path) {
  const to = prompt("Nuovo percorso della cartella (es. prod/data):", path);
  if (!to || to.trim() === path) return;
  try {
    const r = await api("api/folders/rename", { method: "POST", body: { from: path, to: to.trim() } });
    await loadEntries();
    toast(`${r.moved} voci spostate`);
  } catch (e) {
    toast(e.message);
  }
}

async function deleteFolder(path) {
  if (!confirm(`Eliminare la cartella "${path}" e le voci che contiene e che puoi vedere?`)) return;
  try {
    const r = await api("api/folders/delete", { method: "POST", body: { path } });
    await loadEntries();
    toast(`${r.removed} voci eliminate`);
  } catch (e) {
    toast(e.message);
  }
}

async function deleteEntry(e) {
  if (!confirm(`Eliminare la voce "${e.name}"?`)) return;
  try {
    await api(`api/entries/${e.id}`, { method: "DELETE" });
    await loadEntries();
    toast("Eliminato");
  } catch (err) {
    toast(err.message);
  }
}

async function copy(text, msg) {
  try {
    await navigator.clipboard.writeText(text);
    toast(msg);
  } catch {
    toast("Copia non riuscita");
  }
}

/* ---------- editor ---------- */
function openEditor(entry, presetName = "") {
  editingId = entry ? entry.id : "new";
  $("editorTitle").textContent = entry ? "Modifica voce" : "Nuova voce";
  $("f-name").value = entry?.name || presetName;
  $("f-username").value = entry?.username || "";
  $("f-secret").value = entry?.secret || "";
  $("f-secret").type = "password";
  $("f-notes").value = entry?.notes || "";
  // Il livello della voce non può superare quello dell'utente
  $("f-level").value = String(entry?.level ?? 1);
  for (const o of $("f-level").options) o.disabled = Number(o.value) > me.level;
  $("f-delete").hidden = !entry;
  $("editorErr").textContent = "";
  show("vault", false);
  show("editor", true);
  $("f-name").focus();
  $("f-name").setSelectionRange($("f-name").value.length, $("f-name").value.length);
}

function closeEditor() {
  editingId = null;
  show("editor", false);
  show("vault", true);
}

function generatePassword(len = 24) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+";
  const r = crypto.getRandomValues(new Uint32Array(len));
  return Array.from(r, x => chars[x % chars.length]).join("");
}

async function saveEditor() {
  const body = {
    name: $("f-name").value,
    username: $("f-username").value,
    secret: $("f-secret").value,
    notes: $("f-notes").value,
    level: Number($("f-level").value),
  };
  try {
    if (editingId === "new") {
      await api("api/entries", { method: "POST", body });
    } else {
      await api(`api/entries/${editingId}`, { method: "PUT", body });
    }
    closeEditor();
    await loadEntries();
    toast("Salvato");
  } catch (e) {
    $("editorErr").textContent = e.message;
  }
}

async function deleteEditor() {
  if (!editingId || editingId === "new") return;
  if (!confirm("Eliminare questa voce?")) return;
  try {
    await api(`api/entries/${editingId}`, { method: "DELETE" });
    closeEditor();
    await loadEntries();
    toast("Eliminato");
  } catch (e) {
    $("editorErr").textContent = e.message;
  }
}

/* ---------- logout ---------- */
async function logout() {
  try {
    await api("api/logout", { method: "POST", body: {} });
  } finally {
    showLogin();
  }
}

/* ---------- eventi ---------- */
$("new").addEventListener("click", () => newChallenge().catch(e => ($("loginErr").textContent = e.message)));
$("copy").addEventListener("click", copyCommand);
$("pick").addEventListener("click", () => $("keyfile").click());
$("keyfile").addEventListener("change", e => {
  const f = e.target.files[0];
  if (f) loginWithKeyFile(f);
});
$("keypath").addEventListener("input", renderCommand);
$("submit").addEventListener("click", login);
// Login automatico appena l'output completo viene incollato
$("sig").addEventListener("input", () => {
  if ($("sig").value.includes(END_MARK)) login();
});
$("logout").addEventListener("click", logout);
$("search").addEventListener("input", renderList);
$("add").addEventListener("click", () => openEditor(null));
$("gen").addEventListener("click", () => {
  $("f-secret").value = generatePassword();
  $("f-secret").type = "text";
});
$("cancel").addEventListener("click", closeEditor);
$("editorForm").addEventListener("submit", e => {
  e.preventDefault();
  saveEditor();
});
$("f-delete").addEventListener("click", deleteEditor);

/* ---------- avvio ---------- */
(async function init() {
  try {
    me = await api("api/me");
    await showVault();
  } catch {
    showLogin();
  }
})();
