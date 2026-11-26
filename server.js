"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { spawn } = require("child_process");

/* ---------- configurazione ---------- */
const PORT = Number(process.env.PORT) || 8080;
const HOST = process.env.HOST || "127.0.0.1";
const NAMESPACE = "keyring-login";           // dominio di firma: le firme non valgono altrove
const CHALLENGE_TTL_MS = 2 * 60 * 1000;
const SESSION_TTL_MS = 30 * 60 * 1000;
const MAX_CHALLENGES = 1000;
const COOKIE_SECURE = process.env.COOKIE_SECURE === "1"; // imposta a 1 dietro HTTPS

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, "public");
const ACCESS_FILE = path.join(ROOT, "config", "access.json");
const DATA_DIR = path.join(ROOT, "data");
const DATA_FILE = path.join(DATA_DIR, "keyring.enc");
const AUDIT_FILE = path.join(DATA_DIR, "audit.log");

const SECURITY_HEADERS = {
  "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
};

const STATIC = {
  "/": ["index.html", "text/html; charset=utf-8"],
  "/app.js": ["app.js", "text/javascript; charset=utf-8"],
  "/style.css": ["style.css", "text/css; charset=utf-8"],
  "/sshsign.js": ["sshsign.js", "text/javascript; charset=utf-8"],
};

const MASTER_KEY = loadMasterKey();

// File fisso per le chiavi pubbliche, riscritto a ogni ricaricamento della configurazione
const SIGNERS_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "keyring-"));
const SIGNERS_FILE = path.join(SIGNERS_DIR, "allowed_signers");

function writeAllowedSigners(users) {
  const content = users.map(u => `${u.principal} ${u.publicKey.trim()}`).join("\n") + "\n";
  fs.writeFileSync(SIGNERS_FILE, content, { mode: 0o600 });
  return SIGNERS_FILE;
}

let USERS = loadUsers();
let ALLOWED_SIGNERS = writeAllowedSigners(USERS);

const challenges = new Map(); // nonce -> scadenza
const sessions = new Map();   // token -> { user, expiresAt, ... }

fs.mkdirSync(DATA_DIR, { recursive: true });

/* ---------- avvio: configurazione ---------- */
function loadMasterKey() {
  const raw = process.env.KEYRING_KEY;
  if (!raw) throw new Error("Variabile KEYRING_KEY mancante (vedi README).");
  const key = Buffer.from(raw, "base64");
  if (key.length !== 32) throw new Error("KEYRING_KEY deve essere 32 byte codificati in base64.");
  return key;
}

function loadUsers() {
  const cfg = JSON.parse(fs.readFileSync(ACCESS_FILE, "utf8"));
  const users = cfg.users || [];
  const seen = new Set();
  users.forEach((u, idx) => {
    if (typeof u.name !== "string" || !/^[\p{L}\p{N}._'\- ]{1,64}$/u.test(u.name) || u.name !== u.name.trim()) {
      throw new Error(`Nome non valido: "${u.name}" (lettere, cifre, spazi, . _ ' - ; niente spazi iniziali o finali)`);
    }
    if (seen.has(u.name)) throw new Error(`Nome duplicato: ${u.name}`);
    seen.add(u.name);
    // Principal interno senza spazi, usato da ssh-keygen (il nome può contenere spazi)
    u.principal = `u${idx}`;
    if (!["read", "write"].includes(u.role)) throw new Error(`Ruolo non valido per ${u.name}`);
    // Livello mancante: default 1. Se presente, deve essere 1-5.
    if (u.level === undefined) u.level = 1;
    if (!Number.isInteger(u.level) || u.level < 1 || u.level > 5) {
      throw new Error(`Livello non valido per ${u.name} (1-5)`);
    }
    // Perimetro: regex sul nome delle voci (case-insensitive). Default: tutte le voci.
    const src = u.entries ?? ".*";
    if (typeof src !== "string" || src.length > 200) throw new Error(`Campo "entries" non valido per ${u.name}`);
    try {
      u.scope = new RegExp(src, "i");
    } catch (e) {
      throw new Error(`Regex "entries" non valida per ${u.name}: ${e.message}`);
    }
    u.scopeSource = src;
    if (/[\r\n]/.test(u.publicKey) || !/^(ssh-ed25519|ecdsa-sha2-nistp256|ssh-rsa) [A-Za-z0-9+/=]+/.test(u.publicKey)) {
      throw new Error(`Chiave pubblica non valida per ${u.name}`);
    }
  });
  return users;
}

// Rilegge config/access.json. Se il file non è valido, resta la configurazione precedente.
function refreshUsers() {
  try {
    USERS = loadUsers();
    ALLOWED_SIGNERS = writeAllowedSigners(USERS);
  } catch (err) {
    console.error("Configurazione non ricaricata:", err.message);
    audit("-", "config-reload-failed", err.message);
  }
}

/* ---------- verifica firma SSH ---------- */
function run(args, input) {
  return new Promise(resolve => {
    // stdin è una pipe solo se serve il messaggio: ssh-keygen può uscire senza leggerlo
    const p = spawn("ssh-keygen", args, { stdio: [input ? "pipe" : "ignore", "pipe", "pipe"] });
    let out = "";
    p.stdout.on("data", d => (out += d));
    p.on("error", () => resolve({ code: 1, stdout: "" }));
    p.on("close", code => resolve({ code, stdout: out }));
    if (input) {
      p.stdin.on("error", () => {}); // EPIPE se il processo esce prima di leggere
      p.stdin.end(input);
    }
  });
}

async function verifySignature(nonce, signature) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sig-"));
  const sigFile = path.join(dir, "sig");
  try {
    fs.writeFileSync(sigFile, signature.trim() + "\n", { mode: 0o600 });

    // Quale utente ha questa chiave?
    const found = await run(["-Y", "find-principals", "-f", ALLOWED_SIGNERS, "-s", sigFile]);
    if (found.code !== 0) return null;
    const principal = found.stdout.split("\n").map(s => s.trim()).find(Boolean);
    if (!principal || !USERS.some(u => u.principal === principal)) return null;

    // La firma è valida per il nonce, nel dominio corretto?
    const ver = await run(
      ["-Y", "verify", "-f", ALLOWED_SIGNERS, "-I", principal, "-n", NAMESPACE, "-s", sigFile],
      nonce
    );
    return ver.code === 0 ? principal : null;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/* ---------- sessioni ---------- */
function newToken() {
  return crypto.randomBytes(32).toString("base64url");
}

// Ruolo, livello e perimetro vengono riletti dalla configurazione corrente a ogni richiesta
function getSession(req) {
  const m = /(?:^|;\s*)kr_session=([A-Za-z0-9_-]+)/.exec(req.headers.cookie || "");
  if (!m) return null;
  const s = sessions.get(m[1]);
  if (!s) return null;
  if (s.expiresAt < Date.now()) {
    sessions.delete(m[1]);
    return null;
  }
  const u = USERS.find(x => x.name === s.user);
  if (!u) {
    sessions.delete(m[1]);
    return null;
  }
  s.role = u.role;
  s.level = u.level;
  s.scope = u.scope;
  s.scopeSource = u.scopeSource;
  s.expiresAt = Date.now() + SESSION_TTL_MS; // scadenza scorrevole
  return { token: m[1], ...s };
}

function cookie(value, maxAgeSec) {
  return `kr_session=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSec}${COOKIE_SECURE ? "; Secure" : ""}`;
}

function pruneChallenges() {
  const now = Date.now();
  for (const [nonce, exp] of challenges) if (exp < now) challenges.delete(nonce);
}

/* ---------- archivio cifrato ---------- */
function loadData() {
  if (!fs.existsSync(DATA_FILE)) return { entries: [] };
  const env = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", MASTER_KEY, Buffer.from(env.iv, "base64"));
    decipher.setAuthTag(Buffer.from(env.tag, "base64"));
    const pt = Buffer.concat([decipher.update(Buffer.from(env.ct, "base64")), decipher.final()]);
    return JSON.parse(pt.toString("utf8"));
  } catch {
    throw new Error(
      "Impossibile decifrare keyring.enc: KEYRING_KEY non corrisponde ai dati o il file è corrotto"
    );
  }
}

function saveData(data) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", MASTER_KEY, iv);
  const ct = Buffer.concat([cipher.update(JSON.stringify(data), "utf8"), cipher.final()]);
  const env = JSON.stringify({
    v: 1,
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ct: ct.toString("base64"),
  });
  const tmp = DATA_FILE + ".tmp";
  fs.writeFileSync(tmp, env, { mode: 0o600 });
  fs.renameSync(tmp, DATA_FILE);
}

function audit(user, action, detail = "") {
  fs.appendFileSync(AUDIT_FILE, `${new Date().toISOString()}\t${user}\t${action}\t${detail}\n`, { mode: 0o600 });
}

/* ---------- utilità HTTP ---------- */
function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

function json(res, status, body, extra = {}) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...SECURITY_HEADERS,
    ...extra,
  });
  res.end(JSON.stringify(body));
}

function readBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", c => {
      size += c.length;
      if (size > limit) {
        reject(httpError(413, "Richiesta troppo grande"));
        req.destroy();
      } else {
        chunks.push(c);
      }
    });
    req.on("end", () => {
      try {
        resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {});
      } catch {
        reject(httpError(400, "JSON non valido"));
      }
    });
    req.on("error", reject);
  });
}

function field(body, key, max, required = false) {
  const v = body[key] ?? "";
  if (typeof v !== "string" || v.length > max) throw httpError(400, `Campo non valido: ${key}`);
  if (required && !v.trim()) throw httpError(400, `Campo obbligatorio: ${key}`);
  return v;
}

// Blocca un nome fuori dal perimetro dell'utente
function assertName(session, name) {
  if (!session.scope.test(name)) {
    audit(session.user, "scope-denied", name);
    throw httpError(403, "Nome fuori dal perimetro di accesso");
  }
}

const MAX_DEPTH = 8;

// Nome di voce o percorso di cartella: segmenti separati da "/".
// Ogni segmento non vuoto, senza spazi attorno, senza "." o "..".
function validateEntryName(name) {
  const trimmed = String(name).trim();
  if (!trimmed || trimmed.length > 200) throw httpError(400, "Nome obbligatorio (massimo 200 caratteri)");
  if (/[\x00-\x1f\x7f]/.test(trimmed)) throw httpError(400, "Nome con caratteri non ammessi");
  const parts = trimmed.split("/");
  if (parts.length > MAX_DEPTH) throw httpError(400, `Profondità massima: ${MAX_DEPTH} livelli`);
  for (const part of parts) {
    if (!part || part.trim() !== part || part === "." || part === "..") {
      throw httpError(400, "Percorso non valido: segmenti vuoti, spazi attorno a / o . e ..");
    }
  }
  return trimmed;
}

function normalizeFolder(p) {
  if (typeof p !== "string") throw httpError(400, "Percorso cartella non valido");
  return validateEntryName(p.trim().replace(/\/+$/, ""));
}

function parseLevel(v) {
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1 || n > 5) throw httpError(400, "Livello non valido (1-5)");
  return n;
}

function cleanEntry(body) {
  return {
    name: validateEntryName(field(body, "name", 200, true)),
    username: field(body, "username", 200),
    secret: field(body, "secret", 4000),
    notes: field(body, "notes", 4000),
    level: parseLevel(body.level ?? 1),
  };
}

/* ---------- livelli di sicurezza ---------- */
// Le voci senza livello (create prima di questa versione) valgono come livello 5
const levelOf = e => (Number.isInteger(e.level) ? e.level : 5);
const canSee = (session, e) => levelOf(e) <= session.level;

// Un utente può creare o modificare solo voci a un livello uguale o inferiore al proprio
function assertLevel(session, level) {
  if (level > session.level) {
    audit(session.user, "level-denied", String(level));
    throw httpError(403, "Livello superiore al tuo");
  }
}

function serveStatic(p, res) {
  const entry = STATIC[p];
  if (!entry) {
    res.writeHead(404, SECURITY_HEADERS);
    return res.end("Not found");
  }
  const body = fs.readFileSync(path.join(PUBLIC_DIR, entry[0]));
  res.writeHead(200, { "Content-Type": entry[1], ...SECURITY_HEADERS });
  res.end(body);
}

/* ---------- router ---------- */
async function handle(req, res) {
  const url = new URL(req.url, "http://localhost");
  const p = url.pathname;
  const m = req.method;

  if (m === "GET" && !p.startsWith("/api/")) return serveStatic(p, res);

  // 1. Nuova sfida
  if (m === "GET" && p === "/api/challenge") {
    pruneChallenges();
    if (challenges.size >= MAX_CHALLENGES) throw httpError(503, "Troppe richieste, riprova tra poco");
    const nonce = crypto.randomBytes(32).toString("hex");
    challenges.set(nonce, Date.now() + CHALLENGE_TTL_MS);
    return json(res, 200, {
      nonce,
      namespace: NAMESPACE,
      expiresInSeconds: CHALLENGE_TTL_MS / 1000,
    });
  }

  // 2. Login con firma
  if (m === "POST" && p === "/api/login") {
    const body = await readBody(req);
    const nonce = typeof body.nonce === "string" ? body.nonce : "";
    const signature = typeof body.signature === "string" ? body.signature : "";

    const exp = challenges.get(nonce);
    challenges.delete(nonce); // monouso: viene consumata a ogni tentativo

    if (
      !exp ||
      exp < Date.now() ||
      !/^[0-9a-f]{64}$/.test(nonce) ||
      signature.length > 8000 ||
      !signature.includes("-----BEGIN SSH SIGNATURE-----")
    ) {
      throw httpError(401, "Verifica fallita o sfida scaduta");
    }

    // Ricarica config/access.json: modifiche a utenti e livelli valgono da questo login
    refreshUsers();

    const principal = await verifySignature(nonce, signature);
    if (!principal) {
      audit("-", "login-failed");
      throw httpError(401, "Verifica fallita o sfida scaduta");
    }

    const user = USERS.find(u => u.principal === principal);
    const token = newToken();
    sessions.set(token, {
      user: user.name,
      role: user.role,
      level: user.level,
      scope: user.scope,
      scopeSource: user.scopeSource,
      expiresAt: Date.now() + SESSION_TTL_MS,
    });
    audit(user.name, "login", user.role);
    return json(res, 200, { user: user.name, role: user.role, level: user.level }, {
      "Set-Cookie": cookie(token, SESSION_TTL_MS / 1000),
    });
  }

  // 3. Logout
  if (m === "POST" && p === "/api/logout") {
    const s = getSession(req);
    if (s) {
      sessions.delete(s.token);
      audit(s.user, "logout");
    }
    return json(res, 200, { ok: true }, { "Set-Cookie": cookie("", 0) });
  }

  // Da qui in poi: serve una sessione valida
  const session = getSession(req);
  if (!session) throw httpError(401, "Non autenticato");

  // Protezione CSRF di base: le scritture accettano solo JSON
  if (["POST", "PUT"].includes(m) && !(req.headers["content-type"] || "").startsWith("application/json")) {
    throw httpError(415, "Content-Type non valido");
  }

  if (m === "GET" && p === "/api/me") {
    return json(res, 200, { user: session.user, role: session.role, level: session.level, scope: session.scopeSource });
  }

  // Le voci sopra il livello dell'utente non vengono restituite affatto
  if (m === "GET" && p === "/api/entries") {
    const entries = loadData().entries
      .filter(e => session.scope.test(e.name) && canSee(session, e))
      .map(e => ({ ...e, level: levelOf(e) }));
    return json(res, 200, { entries });
  }

  const requireWrite = () => {
    if (session.role !== "write") throw httpError(403, "Permesso di sola lettura");
  };

  if (m === "POST" && p === "/api/entries") {
    requireWrite();
    const body = cleanEntry(await readBody(req));
    assertName(session, body.name);
    assertLevel(session, body.level);
    const entry = {
      id: crypto.randomUUID(),
      ...body,
      updatedAt: new Date().toISOString(),
      updatedBy: session.user,
    };
    const data = loadData();
    data.entries.push(entry);
    saveData(data);
    audit(session.user, "create", entry.id);
    return json(res, 201, { entry });
  }

  if (m === "POST" && p === "/api/folders/rename") {
    requireWrite();
    const body = await readBody(req);
    const from = normalizeFolder(body.from);
    const to = normalizeFolder(body.to);
    if (to === from || to.startsWith(from + "/")) throw httpError(400, "Destinazione non valida");
    const data = loadData();
    const moves = data.entries.filter(e => e.name.startsWith(from + "/") && session.scope.test(e.name) && canSee(session, e));
    if (!moves.length) throw httpError(404, "Cartella non trovata");
    // Tutto o niente: ogni nuovo nome deve essere valido e restare nel perimetro
    const newNames = new Map();
    for (const e of moves) {
      const name = validateEntryName(to + e.name.slice(from.length));
      assertName(session, name);
      newNames.set(e.id, name);
    }
    const now = new Date().toISOString();
    data.entries = data.entries.map(e => newNames.has(e.id)
      ? { ...e, name: newNames.get(e.id), updatedAt: now, updatedBy: session.user }
      : e);
    saveData(data);
    audit(session.user, "folder-rename", `${from} -> ${to} (${moves.length})`);
    return json(res, 200, { moved: moves.length });
  }

  if (m === "POST" && p === "/api/folders/delete") {
    requireWrite();
    const folder = normalizeFolder((await readBody(req)).path);
    const data = loadData();
    const before = data.entries.length;
    data.entries = data.entries.filter(e => !(e.name.startsWith(folder + "/") && session.scope.test(e.name) && canSee(session, e)));
    const removed = before - data.entries.length;
    if (!removed) throw httpError(404, "Cartella non trovata");
    saveData(data);
    audit(session.user, "folder-delete", `${folder} (${removed})`);
    return json(res, 200, { removed });
  }

  const idm = /^\/api\/entries\/([0-9a-f-]{36})$/.exec(p);

  if (idm && m === "PUT") {
    requireWrite();
    const body = cleanEntry(await readBody(req));
    const data = loadData();
    const i = data.entries.findIndex(e => e.id === idm[1]);
    if (i < 0 || !session.scope.test(data.entries[i].name) || !canSee(session, data.entries[i])) {
      throw httpError(404, "Voce non trovata");
    }
    assertName(session, body.name);
    assertLevel(session, body.level);
    data.entries[i] = {
      ...data.entries[i],
      ...body,
      updatedAt: new Date().toISOString(),
      updatedBy: session.user,
    };
    saveData(data);
    audit(session.user, "update", idm[1]);
    return json(res, 200, { entry: data.entries[i] });
  }

  if (idm && m === "DELETE") {
    requireWrite();
    const data = loadData();
    const target = data.entries.find(e => e.id === idm[1]);
    if (!target || !session.scope.test(target.name) || !canSee(session, target)) {
      throw httpError(404, "Voce non trovata");
    }
    data.entries = data.entries.filter(e => e.id !== idm[1]);
    saveData(data);
    audit(session.user, "delete", idm[1]);
    return json(res, 200, { ok: true });
  }

  throw httpError(404, "Non trovato");
}

const server = http.createServer(async (req, res) => {
  try {
    await handle(req, res);
  } catch (err) {
    const status = err.status || 500;
    if (status === 500) console.error(err);
    if (!res.headersSent) {
      json(res, status, { error: status === 500 ? "Errore interno" : err.message });
    }
  }
});

fs.mkdirSync(DATA_DIR, { recursive: true });

server.listen(PORT, HOST, () => {
  console.log(`Keyring in ascolto su http://${HOST}:${PORT}`);
  console.log(`Utenti configurati: ${USERS.length}`);
});
