"use strict";

const express = require("express");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");

const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "data.db");
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 dias
const SESSION_COOKIE = "casa_session";
const STATE_LIMIT_BYTES = 1024 * 1024; // 1 MB por usuário

// --- DB ---
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
  if (process.env.NODE_ENV === "production") flags.push("Secure");
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
        },
        last_changed: e.last_changed,
      }));
    res.json({ entities: slim });
  } catch (e) {
    res.status(502).json({ error: String(e.message || e) });
  }
});

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

// --- Estático ---
app.use(express.static(__dirname, { extensions: ["html"] }));

// --- 404 JSON p/ /api ---
app.use("/api", (req, res) => res.status(404).json({ error: "rota não encontrada" }));

app.listen(PORT, () => {
  console.log(`homeOS → http://localhost:${PORT}`);
});
