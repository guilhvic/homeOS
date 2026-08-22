"use strict";

const express = require("express");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "data.db");
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 dias
const SESSION_COOKIE = "casa_session";
const STATE_LIMIT_BYTES = 1024 * 1024; // 1 MB por usuário

// --- DB ---
// Garante que o diretório do banco existe (ex: DB_PATH=/data/data.db em container)
fs.mkdirSync(path.dirname(path.resolve(DB_PATH)), { recursive: true });
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL,
    avatar TEXT NOT NULL DEFAULT '🏠',
    state TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
`);

// Migration: add per-user HA config columns
const userCols = new Set(db.prepare("PRAGMA table_info(users)").all().map(r => r.name));
if (!userCols.has("ha_url"))   db.exec("ALTER TABLE users ADD COLUMN ha_url TEXT NOT NULL DEFAULT ''");
if (!userCols.has("ha_token")) db.exec("ALTER TABLE users ADD COLUMN ha_token TEXT NOT NULL DEFAULT ''");

// --- Senha (scrypt) ---
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);
  return salt.toString("hex") + ":" + hash.toString("hex");
}
function verifyPassword(password, stored) {
  if (!stored || !stored.includes(":")) return false;
  try {
    const [saltHex, hashHex] = stored.split(":");
    const salt = Buffer.from(saltHex, "hex");
    const expected = Buffer.from(hashHex, "hex");
    const actual = crypto.scryptSync(password, salt, 64);
    if (actual.length !== expected.length) return false;
    return crypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

// --- Sessões ---
function createSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  const now = Date.now();
  db.prepare(
    "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)"
  ).run(token, userId, now, now + SESSION_TTL_MS);
  return token;
}
function getSessionUser(token) {
  if (!token) return null;
  const row = db.prepare(`
    SELECT u.*, s.expires_at AS s_expires
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token = ?
  `).get(token);
  if (!row) return null;
  if (row.s_expires < Date.now()) {
    db.prepare("DELETE FROM sessions WHERE token = ?").run(token);
    return null;
  }
  return row;
}
function destroySession(token) {
  if (!token) return;
  db.prepare("DELETE FROM sessions WHERE token = ?").run(token);
}

// Limpa sessões expiradas periodicamente
setInterval(() => {
  db.prepare("DELETE FROM sessions WHERE expires_at < ?").run(Date.now());
}, 60 * 60 * 1000).unref();

// ===== Web Push (notificações no celular, mesmo com o app fechado) =====
// Chaves VAPID: vêm do env, ou são geradas uma vez e persistidas em /data.
// Cada dispositivo (navegador/PWA) registra uma "subscription" ligada ao usuário.
let webpush = null, VAPID_PUBLIC = "";
const PUSH_DIR = fs.existsSync("/data") ? "/data" : __dirname;
const VAPID_FILE = path.join(PUSH_DIR, "vapid.json");
db.exec(`
  CREATE TABLE IF NOT EXISTS push_subs (
    endpoint TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sub TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS push_subs_user ON push_subs(user_id);
`);
try {
  webpush = require("web-push");
  let keys = null;
  if (process.env.VAPID_PUBLIC && process.env.VAPID_PRIVATE) {
    keys = { publicKey: process.env.VAPID_PUBLIC, privateKey: process.env.VAPID_PRIVATE };
  } else {
    try { keys = JSON.parse(fs.readFileSync(VAPID_FILE, "utf8")); } catch {}
    if (!keys || !keys.publicKey || !keys.privateKey) {
      keys = webpush.generateVAPIDKeys();
      try { fs.writeFileSync(VAPID_FILE, JSON.stringify(keys)); }
      catch (e) { console.warn("Não persistiu VAPID:", e.message); }
    }
  }
  webpush.setVapidDetails(process.env.VAPID_SUBJECT || "mailto:admin@homeos.local", keys.publicKey, keys.privateKey);
  VAPID_PUBLIC = keys.publicKey;
  console.log("Web Push habilitado.");
} catch (e) {
  console.warn("Web Push indisponível (web-push instalado?):", e.message);
}

function pushSubsForUser(uid) { return db.prepare("SELECT endpoint, sub FROM push_subs WHERE user_id = ?").all(uid); }
function pushAllSubs() { return db.prepare("SELECT endpoint, sub FROM push_subs").all(); }
async function sendPushRows(rows, payload) {
  if (!webpush || !rows.length) return 0;
  const body = JSON.stringify(payload);
  let sent = 0;
  await Promise.all(rows.map(async (row) => {
    let sub; try { sub = JSON.parse(row.sub); } catch { return; }
    try { await webpush.sendNotification(sub, body); sent++; }
    catch (err) {
      const code = err && err.statusCode;
      // 404/410 = subscription expirou/foi removida no dispositivo → limpa.
      if (code === 404 || code === 410) db.prepare("DELETE FROM push_subs WHERE endpoint = ?").run(row.endpoint);
    }
  }));
  return sent;
}
function sendPushToUser(uid, payload) { return sendPushRows(pushSubsForUser(uid), payload); }
function sendPushToAll(payload) { return sendPushRows(pushAllSubs(), payload); }

// --- Cookies ---
function parseCookies(req) {
  const header = req.headers.cookie;
  if (!header) return {};
  const out = {};
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    const v = decodeURIComponent(part.slice(i + 1).trim());
    out[k] = v;
  }
  return out;
}
function reqIsHttps(req) {
  const xf = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim();
  return xf === "https" || Boolean(req.socket && req.socket.encrypted);
}
function setSessionCookie(req, res, token) {
  const maxAge = Math.floor(SESSION_TTL_MS / 1000);
  const flags = ["HttpOnly", "SameSite=Lax", "Path=/", `Max-Age=${maxAge}`];
  // COOKIE_SECURE:
  //   "1"    -> sempre Secure (só funciona em HTTPS; quebra acesso http://).
  //   "auto" -> Secure só quando a requisição chega por HTTPS (ex.: via Tailscale
  //             serve, que envia X-Forwarded-Proto: https). Mantém o quiosque em
  //             http://localhost funcionando. Recomendado.
  const mode = process.env.COOKIE_SECURE;
  if (mode === "1" || (mode === "auto" && reqIsHttps(req))) flags.push("Secure");
  res.setHeader("Set-Cookie", `${SESSION_COOKIE}=${token}; ${flags.join("; ")}`);
}
function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`
  );
}

// --- App ---
const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "1.5mb" }));

function authRequired(req, res, next) {
  const cookies = parseCookies(req);
  const token = cookies[SESSION_COOKIE];
  const u = getSessionUser(token);
  if (!u) return res.status(401).json({ error: "não autenticado" });
  req.user = u;
  req.sessionToken = token;
  next();
}

function publicUser(u) {
  return {
    id: u.id,
    username: u.username,
    displayName: u.display_name,
    avatar: u.avatar,
    haUrl: u.ha_url || "",
    haConfigured: Boolean(u.ha_url && u.ha_token),
  };
}

// --- Validadores ---
const USERNAME_RE = /^[a-zA-Z0-9_.-]+$/;
function validateUsername(u) {
  if (typeof u !== "string") return "usuário inválido";
  const v = u.trim();
  if (v.length < 3 || v.length > 32) return "usuário deve ter 3–32 caracteres";
  if (!USERNAME_RE.test(v)) return "usuário só com letras, números, . _ -";
  return null;
}
function validatePassword(p) {
  if (typeof p !== "string") return "senha inválida";
  if (p.length < 6) return "senha precisa ter ao menos 6 caracteres";
  if (p.length > 200) return "senha muito longa";
  return null;
}

// --- Rotas: auth ---
app.post("/api/auth/signup", (req, res) => {
  const { username, password, displayName, avatar } = req.body || {};
  const eu = validateUsername(username);
  if (eu) return res.status(400).json({ error: eu });
  const ep = validatePassword(password);
  if (ep) return res.status(400).json({ error: ep });

  const uname = username.trim();
  const dn = (typeof displayName === "string" && displayName.trim()) || uname;
  const av = (typeof avatar === "string" && avatar) || "🏠";

  const exists = db.prepare("SELECT id FROM users WHERE username = ?").get(uname);
  if (exists) return res.status(409).json({ error: "usuário já cadastrado" });

  const info = db.prepare(
    "INSERT INTO users (username, password_hash, display_name, avatar) VALUES (?, ?, ?, ?)"
  ).run(uname, hashPassword(password), dn.slice(0, 60), av.slice(0, 8));

  const token = createSession(info.lastInsertRowid);
  setSessionCookie(req, res, token);
  const u = db.prepare("SELECT * FROM users WHERE id = ?").get(info.lastInsertRowid);
  res.status(201).json(publicUser(u));
});

app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== "string" || typeof password !== "string")
    return res.status(400).json({ error: "credenciais inválidas" });
  const u = db.prepare("SELECT * FROM users WHERE username = ?").get(username.trim());
  if (!u || !verifyPassword(password, u.password_hash))
    return res.status(401).json({ error: "usuário ou senha incorretos" });
  const token = createSession(u.id);
  setSessionCookie(req, res, token);
  res.json(publicUser(u));
});

app.post("/api/auth/logout", (req, res) => {
  const cookies = parseCookies(req);
  destroySession(cookies[SESSION_COOKIE]);
  clearSessionCookie(res);
  res.status(204).end();
});

app.post("/api/auth/change-password", authRequired, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (typeof currentPassword !== "string")
    return res.status(400).json({ error: "senha atual obrigatória" });
  const ep = validatePassword(newPassword);
  if (ep) return res.status(400).json({ error: ep });
  if (!verifyPassword(currentPassword, req.user.password_hash))
    return res.status(401).json({ error: "senha atual incorreta" });
  db.prepare("UPDATE users SET password_hash = ? WHERE id = ?")
    .run(hashPassword(newPassword), req.user.id);
  db.prepare("DELETE FROM sessions WHERE user_id = ? AND token != ?")
    .run(req.user.id, req.sessionToken);
  res.status(204).end();
});

// --- Rotas: perfil ---
app.get("/api/me", authRequired, (req, res) => {
  res.json(publicUser(req.user));
});

app.patch("/api/me", authRequired, (req, res) => {
  const { displayName, avatar, haUrl, haToken } = req.body || {};
  const sets = [];
  const params = [];
  if (typeof displayName === "string" && displayName.trim()) {
    sets.push("display_name = ?");
    params.push(displayName.trim().slice(0, 60));
  }
  if (typeof avatar === "string" && avatar) {
    sets.push("avatar = ?");
    params.push(avatar.slice(0, 8));
  }
  if (haUrl !== undefined) {
    const v = (typeof haUrl === "string" ? haUrl : "").trim();
    if (v && !/^https?:\/\//i.test(v)) return res.status(400).json({ error: "URL deve começar com http:// ou https://" });
    sets.push("ha_url = ?");
    params.push(v.replace(/\/$/, "").slice(0, 300));
  }
  if (haToken !== undefined) {
    const v = (typeof haToken === "string" ? haToken : "").trim();
    if (v && v.length < 20) return res.status(400).json({ error: "token muito curto" });
    sets.push("ha_token = ?");
    params.push(v.slice(0, 4000));
  }
  if (!sets.length) return res.status(400).json({ error: "nada para atualizar" });
  params.push(req.user.id);
  db.prepare(`UPDATE users SET ${sets.join(", ")} WHERE id = ?`).run(...params);
  const u = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
  res.json(publicUser(u));
});

app.delete("/api/me", authRequired, (req, res) => {
  const { password } = req.body || {};
  if (!verifyPassword(password || "", req.user.password_hash))
    return res.status(401).json({ error: "senha incorreta" });
  db.prepare("DELETE FROM users WHERE id = ?").run(req.user.id);
  clearSessionCookie(res);
  res.status(204).end();
});

// --- Rotas: estado ---
app.get("/api/state", authRequired, (req, res) => {
  try {
    res.json(JSON.parse(req.user.state || "{}"));
  } catch {
    res.json({});
  }
});

app.put("/api/state", authRequired, (req, res) => {
  const { state } = req.body || {};
  if (!state || typeof state !== "object" || Array.isArray(state))
    return res.status(400).json({ error: "state inválido" });
  const serialized = JSON.stringify(state);
  if (serialized.length > STATE_LIMIT_BYTES)
    return res.status(413).json({ error: "state acima do limite (1 MB)" });
  db.prepare("UPDATE users SET state = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
    .run(serialized, req.user.id);
  res.status(204).end();
});

// --- Home Assistant proxy (per-user) ---
const HA_DOMAINS = new Set([
  "light", "switch", "climate", "fan", "cover", "media_player",
  "binary_sensor", "sensor", "lock", "vacuum", "humidifier", "camera", "weather",
]);

// One-time migration: seed the env values into any user that has no config yet.
// Lets existing setups keep working after the per-user switch, then becomes inert.
(() => {
  const envUrl = (process.env.HA_URL || "").replace(/\/$/, "");
  const envTok = process.env.HA_TOKEN || "";
  if (envUrl && envTok) {
    const r = db.prepare("UPDATE users SET ha_url = ?, ha_token = ? WHERE ha_url = '' AND ha_token = ''").run(envUrl, envTok);
    if (r.changes) console.log(`Migrated HA env config into ${r.changes} existing user(s).`);
  }
})();

function userHaConfig(u) {
  return { url: (u.ha_url || "").replace(/\/$/, ""), token: u.ha_token || "" };
}
function userHaEnabled(u) {
  const { url, token } = userHaConfig(u);
  return Boolean(url && token);
}

async function haFetch(u, pathSuffix, init = {}) {
  const { url, token } = userHaConfig(u);
  if (!url || !token) throw new Error("HA não configurado");
  const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...(init.headers || {}) };
  return fetch(url + pathSuffix, { ...init, headers });
}

// Temperatura da CPU do host (lida de /sys/class/thermal, exposto no container).
app.get("/api/system/temp", authRequired, (req, res) => {
  try {
    const base = "/sys/class/thermal";
    let dirs = [];
    try { dirs = fs.readdirSync(base).filter(d => /^thermal_zone\d+$/.test(d)); }
    catch { return res.json({ available: false }); }
    let max = null;
    const zones = [];
    for (const d of dirs) {
      try {
        const milli = parseInt(fs.readFileSync(path.join(base, d, "temp"), "utf8").trim(), 10);
        if (!Number.isFinite(milli)) continue;
        const c = Math.round(milli / 1000);
        let type = "";
        try { type = fs.readFileSync(path.join(base, d, "type"), "utf8").trim(); } catch {}
        zones.push({ type, c });
        if (max === null || c > max) max = c;
      } catch {}
    }
    if (max === null) return res.json({ available: false });
    res.json({ available: true, celsius: max, zones });
  } catch (e) {
    res.json({ available: false, error: String(e.message || e) });
  }
});

// Saúde do servidor (host): uptime, RAM, disco, carga, temperatura, CPU%,
// swap, frequência, bateria, rede e Wi-Fi.
let prevCpu = null, prevNet = null;
function readSystemHealth() {
  const out = { ok: true };
  // Uptime (segundos do host)
  try {
    const up = parseFloat(fs.readFileSync("/proc/uptime", "utf8").split(" ")[0]);
    if (Number.isFinite(up)) out.uptimeSec = Math.round(up);
  } catch {}
  // Memória
  try {
    const mi = fs.readFileSync("/proc/meminfo", "utf8");
    const grab = k => {
      const m = mi.match(new RegExp("^" + k + ":\\s+(\\d+)\\s*kB", "m"));
      return m ? parseInt(m[1], 10) * 1024 : null;
    };
    const total = grab("MemTotal");
    const avail = grab("MemAvailable");
    if (total && avail != null) {
      out.mem = { total, used: total - avail, pct: Math.round((1 - avail / total) * 100) };
    }
  } catch {}
  // Carga (load average)
  try {
    const la = fs.readFileSync("/proc/loadavg", "utf8").split(" ");
    out.load = { "1m": parseFloat(la[0]), "5m": parseFloat(la[1]), "15m": parseFloat(la[2]) };
  } catch {}
  // Disco (usa /data, que é bind-mount do host; cai pra / se não existir)
  try {
    const target = fs.existsSync("/data") ? "/data" : "/";
    const st = fs.statfsSync(target);
    const total = st.blocks * st.bsize;
    const free = st.bavail * st.bsize;
    if (total > 0) out.disk = { total, used: total - free, pct: Math.round((1 - free / total) * 100) };
  } catch {}
  // Temperatura (maior zona)
  try {
    const base = "/sys/class/thermal";
    let max = null;
    for (const d of fs.readdirSync(base).filter(x => /^thermal_zone\d+$/.test(x))) {
      try {
        const c = Math.round(parseInt(fs.readFileSync(path.join(base, d, "temp"), "utf8").trim(), 10) / 1000);
        if (Number.isFinite(c) && (max === null || c > max)) max = c;
      } catch {}
    }
    if (max !== null) out.tempC = max;
  } catch {}
  // Uso de CPU (%) — delta desde a leitura anterior de /proc/stat
  try {
    const line = fs.readFileSync("/proc/stat", "utf8").split("\n")[0];
    const p = line.trim().split(/\s+/).slice(1).map(Number);
    const idle = (p[3] || 0) + (p[4] || 0);
    const total = p.reduce((s, x) => s + (x || 0), 0);
    if (prevCpu && total > prevCpu.total) {
      const dt = total - prevCpu.total, di = idle - prevCpu.idle;
      out.cpuPct = Math.max(0, Math.min(100, Math.round((1 - di / dt) * 100)));
    }
    prevCpu = { total, idle };
  } catch {}
  // Swap
  try {
    const mi = fs.readFileSync("/proc/meminfo", "utf8");
    const grab = k => { const m = mi.match(new RegExp("^" + k + ":\\s+(\\d+)", "m")); return m ? parseInt(m[1], 10) * 1024 : null; };
    const st = grab("SwapTotal"), sf = grab("SwapFree");
    if (st != null && sf != null && st > 0) out.swap = { total: st, used: st - sf, pct: Math.round((1 - sf / st) * 100) };
  } catch {}
  // Frequência média da CPU (MHz)
  try {
    const base = "/sys/devices/system/cpu";
    let sum = 0, n = 0;
    for (const c of fs.readdirSync(base).filter(x => /^cpu\d+$/.test(x))) {
      try { const khz = parseInt(fs.readFileSync(path.join(base, c, "cpufreq/scaling_cur_freq"), "utf8").trim(), 10); if (Number.isFinite(khz)) { sum += khz; n++; } } catch {}
    }
    if (n) out.cpuMhz = Math.round(sum / n / 1000);
  } catch {}
  // Bateria / energia (é um notebook)
  try {
    const base = "/sys/class/power_supply";
    let bat = null, ac = null;
    for (const e of fs.readdirSync(base)) {
      let type = ""; try { type = fs.readFileSync(path.join(base, e, "type"), "utf8").trim(); } catch {}
      if (type === "Battery" && !bat) bat = e;
      if ((type === "Mains" || /^(AC|ADP|ACAD)/i.test(e)) && ac === null) {
        try { ac = parseInt(fs.readFileSync(path.join(base, e, "online"), "utf8").trim(), 10); } catch {}
      }
    }
    if (bat) {
      const rd = f => { try { return fs.readFileSync(path.join(base, bat, f), "utf8").trim(); } catch { return null; } };
      const cap = parseInt(rd("capacity"), 10);
      const full = parseFloat(rd("energy_full") || rd("charge_full"));
      const design = parseFloat(rd("energy_full_design") || rd("charge_full_design"));
      out.battery = {
        present: true,
        percent: Number.isFinite(cap) ? cap : null,
        status: rd("status"),
        acOnline: ac === 1 ? true : (ac === 0 ? false : null),
        healthPct: (full && design) ? Math.round((full / design) * 100) : null,
      };
    } else if (ac !== null) {
      out.battery = { present: false, acOnline: ac === 1 };
    }
  } catch {}
  // Rede: taxa de download/upload somando interfaces reais
  try {
    const rows = fs.readFileSync("/proc/net/dev", "utf8").split("\n").slice(2);
    let rx = 0, tx = 0;
    for (const ln of rows) {
      const m = ln.trim().match(/^([\w.-]+):\s+(.+)$/);
      if (!m) continue;
      const iface = m[1];
      if (iface === "lo" || /^(docker|veth|br-)/.test(iface)) continue;
      const f = m[2].trim().split(/\s+/).map(Number);
      rx += f[0] || 0; tx += f[8] || 0;
    }
    const now = Date.now();
    if (prevNet && now > prevNet.t) {
      const dt = (now - prevNet.t) / 1000;
      out.net = { rxBps: Math.max(0, Math.round((rx - prevNet.rx) / dt)), txBps: Math.max(0, Math.round((tx - prevNet.tx) / dt)) };
    }
    prevNet = { t: now, rx, tx };
  } catch {}
  // Sinal do Wi-Fi
  try {
    const rows = fs.readFileSync("/proc/net/wireless", "utf8").split("\n").slice(2);
    for (const ln of rows) {
      const m = ln.trim().match(/^([\w.-]+):\s+(.+)$/);
      if (!m) continue;
      const f = m[2].trim().split(/\s+/);
      const quality = parseFloat(f[1]); // link quality (base 70)
      const signal = parseFloat(f[2]);  // dBm
      out.wifi = {
        iface: m[1],
        qualityPct: Number.isFinite(quality) ? Math.round(Math.min(100, (quality / 70) * 100)) : null,
        signalDbm: Number.isFinite(signal) ? Math.round(signal) : null,
      };
      break;
    }
  } catch {}
  return out;
}
app.get("/api/system/health", authRequired, (req, res) => {
  res.json(readSystemHealth());
});

// Info estática do host (lida uma vez pelo cliente).
app.get("/api/system/info", authRequired, (req, res) => {
  const os = require("os");
  const info = {};
  try { info.kernel = os.release(); } catch {}
  try { info.arch = os.arch(); } catch {}
  try { const c = os.cpus(); info.cores = c.length; info.cpuModel = (c[0] || {}).model || null; } catch {}
  try { info.hostname = fs.readFileSync("/etc/hostname", "utf8").trim(); } catch {}
  if (!info.hostname) { try { info.hostname = os.hostname(); } catch {} }
  try { info.totalMem = os.totalmem(); } catch {}
  res.json(info);
});

// ===== Alertas proativos (Web Push) =====
// Dispara quando uma métrica cruza o limite (edge-triggered, com histerese pra
// não spammar). Enviados a TODOS os dispositivos inscritos (é um alerta do
// servidor da casa, não de um usuário específico).
const ALERT_RULES = [
  { key: "disk", get: h => h.disk ? h.disk.pct : null, hi: 85, lo: 80, title: "💾 Disco quase cheio", msg: v => `Disco em ${v}% no servidor` },
  { key: "temp", get: h => typeof h.tempC === "number" ? h.tempC : null, hi: 75, lo: 68, title: "🔥 Servidor quente", msg: v => `CPU a ${v}°C no servidor` },
  { key: "mem",  get: h => h.mem ? h.mem.pct : null, hi: 90, lo: 85, title: "🧠 Memória alta", msg: v => `RAM em ${v}% no servidor` },
];
const alertActive = Object.create(null); // key -> bool (está acima do limite?)
let powerAlertActive = false;
function checkServerAlerts(h) {
  for (const rule of ALERT_RULES) {
    const v = rule.get(h);
    if (v == null) continue;
    if (!alertActive[rule.key] && v >= rule.hi) {
      alertActive[rule.key] = true;
      sendPushToAll({ title: rule.title, body: rule.msg(v), tag: "homeos-" + rule.key, url: "/" }).catch(() => {});
    } else if (alertActive[rule.key] && v <= rule.lo) {
      alertActive[rule.key] = false;
    }
  }
  // Queda de energia (notebook rodando na bateria).
  const onBatt = !!(h.battery && h.battery.present && h.battery.acOnline === false);
  if (onBatt && !powerAlertActive) {
    powerAlertActive = true;
    const pct = (h.battery && typeof h.battery.percent === "number") ? ` (${h.battery.percent}%)` : "";
    sendPushToAll({ title: "⚡ Queda de energia", body: `Servidor rodando na bateria${pct}`, tag: "homeos-power", url: "/" }).catch(() => {});
  } else if (!onBatt && powerAlertActive && h.battery && h.battery.acOnline === true) {
    powerAlertActive = false;
    sendPushToAll({ title: "🔌 Energia restaurada", body: "Servidor de volta na tomada", tag: "homeos-power", url: "/" }).catch(() => {});
  }
}

// ===== Histórico de saúde =====
// Dois níveis de retenção:
//  - Buffer recente em alta resolução: 1 amostra/60s, últimas 48h (para os
//    gráficos detalhados), persistido em health-history.json.
//  - Log de longo prazo: 1 resumo/hora (média/mín/máx), append-only em
//    health-log.jsonl, mantido por ~2 anos. É o "log" consultável de qualquer
//    momento futuro.
const HEALTH_SAMPLE_MS = 60 * 1000;
const HEALTH_MAX = 2880;                                  // 48h a 60s
const HEALTH_DIR = fs.existsSync("/data") ? "/data" : null;
const HEALTH_FILE = HEALTH_DIR ? HEALTH_DIR + "/health-history.json" : null;
const HEALTH_LOG = HEALTH_DIR ? HEALTH_DIR + "/health-log.jsonl" : null;
const HEALTH_LOG_MAX = 17520;                             // ~2 anos de resumos horários
const HEALTH_METRICS = ["temp", "cpu", "mem", "disk", "load", "batt", "net"];

let healthHistory = [];
(function loadHealthHistory() {
  if (!HEALTH_FILE) return;
  try {
    const arr = JSON.parse(fs.readFileSync(HEALTH_FILE, "utf8"));
    if (Array.isArray(arr)) healthHistory = arr.slice(-HEALTH_MAX);
  } catch {}
})();

// Acumulador da hora corrente para o resumo horário.
let hourAccum = null; // { hourStart, temp:[...], mem:[...], disk:[...], load:[...] }
function hourStartOf(ms) { return Math.floor(ms / 3600000) * 3600000; }
function summarize(vals) {
  const v = vals.filter(x => x != null && Number.isFinite(x));
  if (!v.length) return null;
  const sum = v.reduce((s, x) => s + x, 0);
  return { avg: +(sum / v.length).toFixed(2), min: Math.min(...v), max: Math.max(...v) };
}
function flushHourAccum() {
  if (!hourAccum || !HEALTH_LOG) { hourAccum = null; return; }
  const n = (hourAccum[HEALTH_METRICS[0]] || []).length; // nº de amostras na hora (p/ uptime)
  const row = { t: hourAccum.hourStart, n };
  for (const k of HEALTH_METRICS) { const s = summarize(hourAccum[k]); if (s) row[k] = s; }
  hourAccum = null;
  if (n <= 0) return;
  try {
    fs.appendFileSync(HEALTH_LOG, JSON.stringify(row) + "\n");
    trimHealthLogIfNeeded();
  } catch {}
}
let healthLogAppends = 0;
function trimHealthLogIfNeeded() {
  if (!HEALTH_LOG) return;
  // Só verifica de vez em quando (custa reler o arquivo).
  if (++healthLogAppends % 24 !== 0) return;
  try {
    const lines = fs.readFileSync(HEALTH_LOG, "utf8").split("\n").filter(Boolean);
    if (lines.length > HEALTH_LOG_MAX) {
      fs.writeFileSync(HEALTH_LOG, lines.slice(-HEALTH_LOG_MAX).join("\n") + "\n");
    }
  } catch {}
}

let healthDirty = false;
function sampleHealth() {
  const h = readSystemHealth();
  const pt = {
    t: Date.now(),
    temp: typeof h.tempC === "number" ? h.tempC : null,
    cpu: typeof h.cpuPct === "number" ? h.cpuPct : null,
    mem: h.mem ? h.mem.pct : null,
    disk: h.disk ? h.disk.pct : null,
    load: h.load ? h.load["1m"] : null,
    batt: h.battery && typeof h.battery.percent === "number" ? h.battery.percent : null,
    // Rede: throughput total (download+upload) em KB/s
    net: h.net ? Math.round((h.net.rxBps + h.net.txBps) / 1024) : null,
  };
  healthHistory.push(pt);
  if (healthHistory.length > HEALTH_MAX) healthHistory = healthHistory.slice(-HEALTH_MAX);
  healthDirty = true;
  try { checkServerAlerts(h); } catch {}
  // Agrega no resumo da hora; ao virar a hora, grava a anterior no log.
  const hs = hourStartOf(pt.t);
  if (!hourAccum || hourAccum.hourStart !== hs) {
    if (hourAccum) flushHourAccum();
    hourAccum = { hourStart: hs };
    for (const k of HEALTH_METRICS) hourAccum[k] = [];
  }
  for (const k of HEALTH_METRICS) hourAccum[k].push(pt[k]);
}
function persistHealthHistory() {
  if (!HEALTH_FILE || !healthDirty) return;
  try { fs.writeFileSync(HEALTH_FILE, JSON.stringify(healthHistory)); healthDirty = false; } catch {}
}
function persistAll() { persistHealthHistory(); flushHourAccum(); }
sampleHealth();
setInterval(sampleHealth, HEALTH_SAMPLE_MS).unref?.();
setInterval(persistHealthHistory, 2 * 60 * 1000).unref?.();
process.on("SIGTERM", persistAll);
process.on("SIGINT", persistAll);

function readHealthLog(sinceMs) {
  if (!HEALTH_LOG) return [];
  let out = [];
  try {
    const lines = fs.readFileSync(HEALTH_LOG, "utf8").split("\n");
    for (const ln of lines) {
      if (!ln) continue;
      let row; try { row = JSON.parse(ln); } catch { continue; }
      if (row && row.t >= sinceMs) {
        // Achata o resumo horário para o mesmo formato do buffer (usa a média).
        const p = { t: row.t };
        for (const k of HEALTH_METRICS) p[k] = row[k] ? row[k].avg : null;
        out.push(p);
      }
    }
  } catch {}
  return out;
}

app.get("/api/system/health/history", authRequired, (req, res) => {
  const hours = Math.min(24 * 800, Math.max(1, parseInt(req.query.hours, 10) || 6));
  const since = Date.now() - hours * 3600 * 1000;
  // Até 48h: buffer de minuto. Acima disso: resumos horários do log.
  const useLog = hours > 48;
  const points = useLog ? readHealthLog(since) : healthHistory.filter(p => p.t >= since);
  res.json({ hours, resolution: useLog ? "hour" : "minute", sampleMs: HEALTH_SAMPLE_MS, points });
});

// Lê as linhas cruas do log (com `n`) desde `since` — usado pelo cálculo de uptime.
function readHealthLogRaw(sinceMs) {
  if (!HEALTH_LOG) return [];
  const out = [];
  try {
    for (const ln of fs.readFileSync(HEALTH_LOG, "utf8").split("\n")) {
      if (!ln) continue;
      let row; try { row = JSON.parse(ln); } catch { continue; }
      if (row && row.t >= sinceMs) out.push(row);
    }
  } catch {}
  return out;
}

// Disponibilidade (uptime %) num período: mede a cobertura das amostras.
// - Até 48h: buffer de minuto, somando lacunas (gaps) como downtime.
// - Acima: resumos horários (n amostras/hora), medindo desde o 1º registro
//   (não penaliza por o período ser maior que o histórico disponível).
app.get("/api/system/uptime", authRequired, (req, res) => {
  const hours = Math.min(24 * 800, Math.max(1, parseInt(req.query.hours, 10) || 24));
  const now = Date.now();
  const since = now - hours * 3600 * 1000;
  const EXPECT_PER_HOUR = 3600000 / HEALTH_SAMPLE_MS;
  if (hours <= 48) {
    const ts = healthHistory.filter(p => p.t >= since).map(p => p.t).sort((a, b) => a - b);
    if (ts.length < 2) return res.json({ hours, pct: null, resolution: "minute", sinceMs: ts[0] || null });
    const grace = HEALTH_SAMPLE_MS * 2.5;
    let downtime = 0;
    for (let i = 1; i < ts.length; i++) {
      const gap = ts[i] - ts[i - 1];
      if (gap > grace) downtime += gap - HEALTH_SAMPLE_MS;
    }
    const span = now - ts[0];
    const pct = span > 0 ? Math.max(0, Math.min(100, 100 * (1 - downtime / span))) : 100;
    return res.json({ hours, pct: +pct.toFixed(2), resolution: "minute", sinceMs: ts[0] });
  }
  const rows = readHealthLogRaw(since);
  if (!rows.length) return res.json({ hours, pct: null, resolution: "hour", sinceMs: null });
  let upFrac = 0;
  for (const r of rows) upFrac += Math.min(1, (r.n || 0) / EXPECT_PER_HOUR);
  const firstHour = rows[0].t;
  const hoursObserved = Math.max(1, (now - firstHour) / 3600000);
  const pct = Math.max(0, Math.min(100, 100 * upFrac / hoursObserved));
  res.json({ hours, pct: +pct.toFixed(2), resolution: "hour", sinceMs: firstHour });
});

// ===== Web Push: chave pública, inscrição e teste =====
app.get("/api/push/pubkey", authRequired, (req, res) => {
  res.json({ key: VAPID_PUBLIC || null, enabled: !!webpush });
});
app.post("/api/push/subscribe", authRequired, (req, res) => {
  const sub = req.body && req.body.subscription;
  if (!sub || !sub.endpoint || typeof sub.endpoint !== "string")
    return res.status(400).json({ error: "subscription inválida" });
  db.prepare(`INSERT INTO push_subs (endpoint, user_id, sub, created_at) VALUES (?,?,?,?)
    ON CONFLICT(endpoint) DO UPDATE SET user_id=excluded.user_id, sub=excluded.sub`)
    .run(sub.endpoint, req.user.id, JSON.stringify(sub), Date.now());
  res.status(201).json({ ok: true });
});
app.post("/api/push/unsubscribe", authRequired, (req, res) => {
  const ep = req.body && req.body.endpoint;
  if (ep) db.prepare("DELETE FROM push_subs WHERE endpoint = ? AND user_id = ?").run(ep, req.user.id);
  res.json({ ok: true });
});
app.post("/api/push/test", authRequired, async (req, res) => {
  if (!webpush) return res.status(503).json({ error: "push indisponível" });
  const sent = await sendPushToUser(req.user.id, { title: "homeOS", body: "Notificações ativadas ✅", tag: "homeos-test", url: "/" });
  res.json({ ok: true, sent });
});

// ===== Docker (listar e reiniciar containers pela página Servidor) =====
// Usa a Engine API pelo socket unix montado no container (ver docker-compose).
const DOCKER_SOCK = "/var/run/docker.sock";
function dockerAvailable() { try { return fs.existsSync(DOCKER_SOCK); } catch { return false; } }
function dockerRequest(method, urlPath) {
  return new Promise((resolve, reject) => {
    const http = require("http");
    const r = http.request({ socketPath: DOCKER_SOCK, path: urlPath, method, timeout: 20000 }, (resp) => {
      let body = "";
      resp.on("data", c => body += c);
      resp.on("end", () => resolve({ status: resp.statusCode, body }));
    });
    r.on("error", reject);
    r.on("timeout", () => r.destroy(new Error("timeout")));
    r.end();
  });
}
app.get("/api/docker/containers", authRequired, async (req, res) => {
  if (!dockerAvailable()) return res.json({ available: false, containers: [] });
  try {
    const r = await dockerRequest("GET", "/containers/json?all=1");
    if (r.status !== 200) return res.status(502).json({ available: true, error: "docker respondeu " + r.status });
    const list = JSON.parse(r.body).map(c => ({
      id: c.Id,
      name: ((c.Names && c.Names[0]) || "").replace(/^\//, ""),
      image: c.Image,
      state: c.State,
      status: c.Status,
    }));
    res.json({ available: true, containers: list });
  } catch (e) {
    res.status(502).json({ available: true, error: String(e.message || e) });
  }
});
app.post("/api/docker/containers/:id/restart", authRequired, async (req, res) => {
  if (!dockerAvailable()) return res.status(503).json({ error: "docker indisponível" });
  const id = String(req.params.id || "");
  if (!/^[a-zA-Z0-9][\w.-]{0,127}$/.test(id)) return res.status(400).json({ error: "id inválido" });
  try {
    const r = await dockerRequest("POST", `/containers/${encodeURIComponent(id)}/restart?t=10`);
    if (r.status === 204) return res.json({ ok: true });
    return res.status(502).json({ error: "docker respondeu " + r.status });
  } catch (e) {
    res.status(502).json({ error: String(e.message || e) });
  }
});

// ===== Speed test agendado (mede download via Cloudflare, sem binário extra) =====
const SPEED_LOG = HEALTH_DIR ? HEALTH_DIR + "/speedtest-log.jsonl" : null;
const SPEED_LOG_MAX = 4000;
const SPEED_INTERVAL_MS = 6 * 3600 * 1000; // a cada 6h
const SPEED_BYTES = 25 * 1000 * 1000;      // baixa ~25 MB por medição
let lastSpeedtest = null, speedtestRunning = false;
async function measureLatency() {
  let best = null;
  for (let i = 0; i < 3; i++) {
    const ctrl = new AbortController();
    const to = setTimeout(() => ctrl.abort(), 5000);
    const t0 = Date.now();
    try {
      await fetch("https://speed.cloudflare.com/__down?bytes=0", { signal: ctrl.signal, cache: "no-store" });
      const dt = Date.now() - t0;
      if (best == null || dt < best) best = dt;
    } catch {} finally { clearTimeout(to); }
  }
  return best;
}
async function runSpeedtest() {
  if (speedtestRunning) return lastSpeedtest;
  speedtestRunning = true;
  const result = { t: Date.now(), ok: false, downMbps: null, latencyMs: null };
  try {
    result.latencyMs = await measureLatency();
    const ctrl = new AbortController();
    const to = setTimeout(() => ctrl.abort(), 30000);
    const t0 = Date.now();
    try {
      const r = await fetch("https://speed.cloudflare.com/__down?bytes=" + SPEED_BYTES, { signal: ctrl.signal, cache: "no-store" });
      const buf = await r.arrayBuffer();
      const secs = (Date.now() - t0) / 1000;
      if (secs > 0 && buf.byteLength > 0) {
        result.downMbps = +((buf.byteLength * 8) / secs / 1e6).toFixed(1);
        result.ok = true;
      }
    } finally { clearTimeout(to); }
  } catch (e) { result.error = String(e.message || e); }
  speedtestRunning = false;
  lastSpeedtest = result;
  if (SPEED_LOG && result.ok) {
    try {
      fs.appendFileSync(SPEED_LOG, JSON.stringify(result) + "\n");
      const lines = fs.readFileSync(SPEED_LOG, "utf8").split("\n").filter(Boolean);
      if (lines.length > SPEED_LOG_MAX) fs.writeFileSync(SPEED_LOG, lines.slice(-SPEED_LOG_MAX).join("\n") + "\n");
    } catch {}
  }
  return result;
}
function readSpeedLog(sinceMs) {
  if (!SPEED_LOG) return [];
  const out = [];
  try {
    for (const ln of fs.readFileSync(SPEED_LOG, "utf8").split("\n")) {
      if (!ln) continue;
      let row; try { row = JSON.parse(ln); } catch { continue; }
      if (row && row.t >= sinceMs) out.push(row);
    }
  } catch {}
  return out;
}
app.get("/api/speedtest/history", authRequired, (req, res) => {
  const hours = Math.min(24 * 400, Math.max(1, parseInt(req.query.hours, 10) || 168));
  res.json({ hours, last: lastSpeedtest, points: readSpeedLog(Date.now() - hours * 3600 * 1000) });
});
app.post("/api/speedtest/run", authRequired, async (req, res) => {
  if (speedtestRunning) return res.status(409).json({ error: "teste já em andamento" });
  try { const r = await runSpeedtest(); res.json({ ok: r.ok, result: r }); }
  catch (e) { res.status(502).json({ error: String(e.message || e) }); }
});
setTimeout(() => runSpeedtest().catch(() => {}), 60 * 1000).unref?.();
setInterval(() => runSpeedtest().catch(() => {}), SPEED_INTERVAL_MS).unref?.();

// Proxy de snapshot de câmera: repassa o JPEG do HA (camera_proxy) já autenticado.
app.get("/api/ha/camera/:entityId", authRequired, async (req, res) => {
  if (!userHaEnabled(req.user)) return res.status(503).end();
  const id = String(req.params.entityId || "");
  if (!/^camera\.[a-z0-9_]+$/.test(id)) return res.status(400).end();
  // Timeout: câmeras RTSP (ex.: Tapo) podem demorar a gerar o snapshot.
  // Sem isso a requisição fica pendurada e o cliente "carrega pra sempre".
  const ctrl = new AbortController();
  const to = setTimeout(() => ctrl.abort(), 8000);
  try {
    const r = await haFetch(req.user, "/api/camera_proxy/" + encodeURIComponent(id), { signal: ctrl.signal });
    if (!r.ok) return res.status(502).end();
    const buf = Buffer.from(await r.arrayBuffer());
    res.set("Content-Type", r.headers.get("content-type") || "image/jpeg");
    res.set("Cache-Control", "no-store");
    res.send(buf);
  } catch (e) {
    res.status(502).end();
  } finally {
    clearTimeout(to);
  }
});

// Stream MJPEG ao vivo (multipart/x-mixed-replace). Muito melhor que snapshot
// para câmeras RTSP: o <img> renderiza o fluxo contínuo direto.
app.get("/api/ha/camera_stream/:entityId", authRequired, async (req, res) => {
  if (!userHaEnabled(req.user)) return res.status(503).end();
  const id = String(req.params.entityId || "");
  if (!/^camera\.[a-z0-9_]+$/.test(id)) return res.status(400).end();
  const ctrl = new AbortController();
  req.on("close", () => ctrl.abort());
  try {
    const r = await haFetch(req.user, "/api/camera_proxy_stream/" + encodeURIComponent(id), { signal: ctrl.signal });
    if (!r.ok || !r.body) return res.status(502).end();
    res.set("Content-Type", r.headers.get("content-type") || "multipart/x-mixed-replace");
    res.set("Cache-Control", "no-store");
    res.set("Connection", "close");
    const { Readable } = require("node:stream");
    const nodeStream = Readable.fromWeb(r.body);
    nodeStream.on("error", () => { try { res.end(); } catch {} });
    res.on("close", () => { try { nodeStream.destroy(); } catch {} });
    nodeStream.pipe(res);
  } catch (e) {
    try { res.status(502).end(); } catch {}
  }
});

app.get("/api/ha/status", authRequired, async (req, res) => {
  if (!userHaEnabled(req.user)) return res.json({ configured: false });
  try {
    const r = await haFetch(req.user, "/api/");
    res.json({ configured: true, ok: r.ok, status: r.status });
  } catch (e) {
    res.json({ configured: true, ok: false, error: String(e.message || e) });
  }
});

app.get("/api/ha/states", authRequired, async (req, res) => {
  if (!userHaEnabled(req.user)) return res.status(503).json({ error: "HA não configurado" });
  try {
    const r = await haFetch(req.user, "/api/states");
    if (!r.ok) return res.status(502).json({ error: "HA respondeu " + r.status });
    const all = await r.json();
    const slim = all
      .filter(e => {
        const dom = (e.entity_id || "").split(".")[0];
        if (!HA_DOMAINS.has(dom)) return false;
        // Skip noisy internal sensors (backup status, sun timestamps, etc.)
        if (dom === "sensor") {
          const a = e.attributes || {};
          const hasUnit = !!a.unit_of_measurement;
          const usefulDeviceClass = ["temperature","humidity","illuminance","power","energy","voltage","current","battery","pressure"].includes(a.device_class);
          if (!hasUnit && !usefulDeviceClass) return false;
        }
        return true;
      })
      .map(e => ({
        entity_id: e.entity_id,
        state: e.state,
        attributes: {
          friendly_name: e.attributes?.friendly_name,
          unit_of_measurement: e.attributes?.unit_of_measurement,
          device_class: e.attributes?.device_class,
          icon: e.attributes?.icon,
          brightness: e.attributes?.brightness,
          current_temperature: e.attributes?.current_temperature,
          temperature: e.attributes?.temperature,
          hvac_action: e.attributes?.hvac_action,
          hvac_modes: e.attributes?.hvac_modes,
          min_temp: e.attributes?.min_temp,
          max_temp: e.attributes?.max_temp,
          target_temp_step: e.attributes?.target_temp_step,
        },
        last_changed: e.last_changed,
      }));
    res.json({ entities: slim });
  } catch (e) {
    res.status(502).json({ error: String(e.message || e) });
  }
});

// Histórico numérico de uma entidade (para gráficos de sensores)
app.get("/api/ha/history", authRequired, async (req, res) => {
  if (!userHaEnabled(req.user)) return res.status(503).json({ error: "HA não configurado" });
  const entityId = String(req.query.entity_id || "");
  if (!/^[a-z_]+\.[a-z0-9_]+$/.test(entityId)) return res.status(400).json({ error: "entity_id inválido" });
  const hours = Math.min(168, Math.max(1, parseInt(req.query.hours, 10) || 24));
  const start = new Date(Date.now() - hours * 3600 * 1000).toISOString();
  try {
    const suffix = `/api/history/period/${encodeURIComponent(start)}`
      + `?filter_entity_id=${encodeURIComponent(entityId)}&minimal_response&no_attributes`;
    const r = await haFetch(req.user, suffix);
    if (!r.ok) return res.status(502).json({ error: "HA respondeu " + r.status });
    const data = await r.json();
    const series = Array.isArray(data) && Array.isArray(data[0]) ? data[0] : [];
    const points = [];
    for (const p of series) {
      const v = Number(p.state);
      if (!Number.isFinite(v)) continue; // ignora unknown/unavailable
      const t = new Date(p.last_changed || p.last_updated || 0).getTime();
      if (!Number.isFinite(t) || t === 0) continue;
      points.push({ t, v });
    }
    res.json({ entity_id: entityId, hours, points });
  } catch (e) {
    res.status(502).json({ error: String(e.message || e) });
  }
});

// --- Routines ---
// Routines are stored in the user's state.routines array. The server exposes a
// "run by id" endpoint and runs time-triggered routines on a minute scheduler.

function loadUserState(u) {
  try { return JSON.parse(u.state || "{}"); } catch { return {}; }
}
function saveUserState(uid, st) {
  db.prepare("UPDATE users SET state = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
    .run(JSON.stringify(st), uid);
}

const ACTION_PRESETS = {
  light:         { on: { service: "turn_on" },  off: { service: "turn_off" } },
  switch:        { on: { service: "turn_on" },  off: { service: "turn_off" } },
  fan:           { on: { service: "turn_on" },  off: { service: "turn_off" } },
  humidifier:    { on: { service: "turn_on" },  off: { service: "turn_off" } },
  media_player:  { on: { service: "turn_on" },  off: { service: "turn_off" } },
  cover:         { on: { service: "open_cover" }, off: { service: "close_cover" } },
  lock:          { on: { service: "lock" },     off: { service: "unlock" } },
  vacuum:        { on: { service: "start" },    off: { service: "return_to_base" } },
  climate: {
    on:  { service: "set_hvac_mode", data: { hvac_mode: "cool" } },
    off: { service: "set_hvac_mode", data: { hvac_mode: "off" } },
  },
};

// Resolve uma ação (entity + preset [+ value]) para { domain, service, data }.
// Além de on/off (tabela acima), suporta ações com valor: brilho da luz,
// temperatura do climate e volume do media_player.
function resolveAction(action) {
  const entityId = action.entityId || "";
  const domain = entityId.split(".")[0];
  const preset = action.preset;
  const val = Number(action.value);
  if (preset === "brightness" && domain === "light" && Number.isFinite(val))
    return { domain: "light", service: "turn_on", data: { brightness_pct: Math.max(0, Math.min(100, Math.round(val))) } };
  if (preset === "temperature" && domain === "climate" && Number.isFinite(val))
    return { domain: "climate", service: "set_temperature", data: { temperature: val } };
  if (preset === "volume" && domain === "media_player" && Number.isFinite(val))
    return { domain: "media_player", service: "volume_set", data: { volume_level: Math.max(0, Math.min(1, val / 100)) } };
  const p = ACTION_PRESETS[domain] && ACTION_PRESETS[domain][preset];
  if (p) return { domain, service: p.service, data: p.data || {} };
  return null;
}

async function runRoutineFor(u, routine) {
  if (!userHaEnabled(u)) throw new Error("HA não configurado");
  const results = [];
  for (const action of (routine.actions || [])) {
    const entityId = action.entityId;
    const r = resolveAction(action);
    if (!r) { results.push({ entityId, ok: false, error: "ação não suportada" }); continue; }
    try {
      const resp = await haFetch(u, `/api/services/${r.domain}/${r.service}`, {
        method: "POST",
        body: JSON.stringify({ entity_id: entityId, ...r.data }),
      });
      results.push({ entityId, service: r.service, ok: resp.ok, status: resp.status });
    } catch (e) {
      results.push({ entityId, ok: false, error: String(e.message || e) });
    }
  }
  // Stamp lastRunAt in user state
  const st = loadUserState(u);
  if (Array.isArray(st.routines)) {
    const r = st.routines.find(x => x.id === routine.id);
    if (r) { r.lastRunAt = new Date().toISOString(); saveUserState(u.id, st); }
  }
  return results;
}

app.post("/api/routines/:id/run", authRequired, async (req, res) => {
  const st = loadUserState(req.user);
  const routine = (st.routines || []).find(r => r.id === req.params.id);
  if (!routine) return res.status(404).json({ error: "rotina não encontrada" });
  try {
    const results = await runRoutineFor(req.user, routine);
    res.json({ ok: true, results });
  } catch (e) {
    res.status(502).json({ error: String(e.message || e) });
  }
});

// Scheduler — a cada minuto, checa rotinas com gatilho de horário OU de sol.
// lastFiredKey guarda o último "marcador" já disparado por rotina (dedup por minuto).
const lastFiredKey = new Map(); // `${userId}:${routineId}` -> marcador
function dayBlocked(days, dow) {
  return Array.isArray(days) && days.length && !days.includes(dow);
}
async function loadSun(u) {
  try {
    const r = await haFetch(u, "/api/states/sun.sun");
    if (!r.ok) return null;
    const s = await r.json();
    return (s && s.attributes) ? s.attributes : null; // { next_rising, next_setting, ... }
  } catch { return null; }
}
async function tickScheduler() {
  const now = new Date();
  const nowMin = Math.floor(now.getTime() / 60000);
  const hhmm = String(now.getHours()).padStart(2, "0") + ":" + String(now.getMinutes()).padStart(2, "0");
  const users = db.prepare("SELECT * FROM users WHERE ha_url <> '' AND ha_token <> ''").all();
  for (const u of users) {
    const st = loadUserState(u);
    const routines = Array.isArray(st.routines) ? st.routines : [];
    let sun; // carregado sob demanda (só se houver rotina de sol)
    const fire = (r, marker) => {
      const key = `${u.id}:${r.id}`;
      if (lastFiredKey.get(key) === marker) return;
      lastFiredKey.set(key, marker);
      runRoutineFor(u, r).catch(err => console.error(`Routine ${r.id} for user ${u.id} failed:`, err));
    };
    for (const r of routines) {
      if (!r || r.enabled === false || !r.trigger) continue;
      const tr = r.trigger;
      if (tr.type === "time") {
        if (tr.time !== hhmm) continue;
        if (dayBlocked(tr.days, now.getDay())) continue;
        fire(r, hhmm);
      } else if (tr.type === "sun") {
        if (sun === undefined) sun = await loadSun(u);
        if (!sun) continue;
        const iso = tr.event === "sunrise" ? sun.next_rising : sun.next_setting;
        if (!iso) continue;
        const target = new Date(iso).getTime() + (Number(tr.offsetMin) || 0) * 60000;
        if (!Number.isFinite(target) || Math.floor(target / 60000) !== nowMin) continue;
        if (dayBlocked(tr.days, new Date(target).getDay())) continue;
        fire(r, "sun:" + Math.floor(target / 60000));
      }
    }
  }
}
setInterval(() => tickScheduler().catch(() => {}), 60 * 1000).unref();

app.post("/api/ha/services/:domain/:service", authRequired, async (req, res) => {
  if (!userHaEnabled(req.user)) return res.status(503).json({ error: "HA não configurado" });
  const { domain, service } = req.params;
  if (!/^[a-z_]+$/.test(domain) || !/^[a-z_]+$/.test(service))
    return res.status(400).json({ error: "domain/service inválido" });
  // Alguns serviços (ex.: weather.get_forecasts) devolvem dados só com
  // ?return_response=true. Repassamos o parâmetro quando pedido.
  const suffix = req.query.return_response === "true"
    ? `/api/services/${domain}/${service}?return_response=true`
    : `/api/services/${domain}/${service}`;
  try {
    const r = await haFetch(req.user, suffix, {
      method: "POST",
      body: JSON.stringify(req.body || {}),
    });
    if (!r.ok) return res.status(502).json({ error: "HA respondeu " + r.status });
    res.json(await r.json());
  } catch (e) {
    res.status(502).json({ error: String(e.message || e) });
  }
});

// --- PWA: manifest e service worker com headers corretos ---
app.get("/manifest.webmanifest", (req, res) => {
  res.type("application/manifest+json");
  res.sendFile(path.join(__dirname, "manifest.webmanifest"));
});
app.get("/sw.js", (req, res) => {
  res.type("application/javascript");
  res.set("Service-Worker-Allowed", "/");
  res.set("Cache-Control", "no-cache");
  res.sendFile(path.join(__dirname, "sw.js"));
});

// --- Bloqueia arquivos sensíveis antes do estático ---
// express.static serviria QUALQUER arquivo do diretório (inclusive .env e o DB).
const BLOCKED_STATIC = new Set([
  ".env", "data.db", "server.js", "generate-icons.js",
  "package.json", "package-lock.json", "docker-compose.yml", "vapid.json",
]);
app.use((req, res, next) => {
  const clean = decodeURIComponent(req.path).replace(/^\/+/, "").toLowerCase();
  const first = clean.split("/")[0];
  if (
    BLOCKED_STATIC.has(clean) ||
    first === "ha-config" || first === ".git" || first === "node_modules" ||
    clean.startsWith("data.db") ||   // WAL/SHM
    first.startsWith(".env")
  ) {
    return res.status(404).send("Not found");
  }
  next();
});

// --- Estático ---
app.use(express.static(__dirname, { extensions: ["html"] }));

// --- 404 JSON p/ /api ---
app.use("/api", (req, res) => res.status(404).json({ error: "rota não encontrada" }));

app.listen(PORT, () => {
  console.log(`homeOS → http://localhost:${PORT}`);
});
