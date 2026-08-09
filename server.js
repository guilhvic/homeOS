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
function setSessionCookie(res, token) {
  const maxAge = Math.floor(SESSION_TTL_MS / 1000);
  const flags = ["HttpOnly", "SameSite=Lax", "Path=/", `Max-Age=${maxAge}`];
  // Secure exige HTTPS — ative COOKIE_SECURE=1 só depois que o HTTPS estiver no ar
  // (ex: via Tailscale). Sem isso, dá pra testar em http:// no primeiro boot.
  if (process.env.COOKIE_SECURE === "1") flags.push("Secure");
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
  setSessionCookie(res, token);
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
  setSessionCookie(res, token);
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
  "binary_sensor", "sensor", "lock", "vacuum", "humidifier",
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

async function runRoutineFor(u, routine) {
  if (!userHaEnabled(u)) throw new Error("HA não configurado");
  const results = [];
  for (const action of (routine.actions || [])) {
    const entityId = action.entityId;
    const domain = (entityId || "").split(".")[0];
    const preset = ACTION_PRESETS[domain] && ACTION_PRESETS[domain][action.preset];
    if (!preset) { results.push({ entityId, ok: false, error: "ação não suportada" }); continue; }
    try {
      const r = await haFetch(u, `/api/services/${domain}/${preset.service}`, {
        method: "POST",
        body: JSON.stringify({ entity_id: entityId, ...(preset.data || {}) }),
      });
      results.push({ entityId, service: preset.service, ok: r.ok, status: r.status });
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

// Time-trigger scheduler — every minute, check all users for due routines.
// Tracks the last "HH:MM" we already fired for each routine so each schedule fires once per minute.
const lastFiredKey = new Map(); // `${userId}:${routineId}` -> "HH:MM"
function tickScheduler() {
  const now = new Date();
  const hhmm = String(now.getHours()).padStart(2, "0") + ":" + String(now.getMinutes()).padStart(2, "0");
  const users = db.prepare("SELECT * FROM users WHERE ha_url <> '' AND ha_token <> ''").all();
  for (const u of users) {
    const st = loadUserState(u);
    const routines = Array.isArray(st.routines) ? st.routines : [];
    for (const r of routines) {
      if (!r || r.enabled === false) continue;
      if (!r.trigger || r.trigger.type !== "time") continue;
      if (r.trigger.time !== hhmm) continue;
      const key = `${u.id}:${r.id}`;
      if (lastFiredKey.get(key) === hhmm) continue;
      lastFiredKey.set(key, hhmm);
      runRoutineFor(u, r).catch(err => console.error(`Routine ${r.id} for user ${u.id} failed:`, err));
    }
  }
}
setInterval(tickScheduler, 60 * 1000).unref();

app.post("/api/ha/services/:domain/:service", authRequired, async (req, res) => {
  if (!userHaEnabled(req.user)) return res.status(503).json({ error: "HA não configurado" });
  const { domain, service } = req.params;
  if (!/^[a-z_]+$/.test(domain) || !/^[a-z_]+$/.test(service))
    return res.status(400).json({ error: "domain/service inválido" });
  try {
    const r = await haFetch(req.user, `/api/services/${domain}/${service}`, {
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
  "package.json", "package-lock.json", "docker-compose.yml",
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
