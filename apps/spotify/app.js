// ============ CONFIG ============
// 1. Acesse https://developer.spotify.com/dashboard e crie um app
// 2. Em "Redirect URIs" adicione EXATAMENTE a URL onde você vai rodar este app.
//    Para rodar local, recomendo: http://127.0.0.1:5173/
//    (Spotify não aceita mais http://localhost — tem que ser 127.0.0.1)
// 3. Copie o "Client ID" e cole abaixo:
const CLIENT_ID = '8bab46f6abf94f26b56d8a4d3e9f0df0';
// ================================

const REDIRECT_URI = window.location.origin + window.location.pathname;
const SCOPES = 'user-read-currently-playing user-read-playback-state user-modify-playback-state';
const AUTH_URL = 'https://accounts.spotify.com/authorize';
const TOKEN_URL = 'https://accounts.spotify.com/api/token';
const API_BASE = 'https://api.spotify.com/v1';

// ---------- PKCE ----------
function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

async function pkcePair() {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return { verifier, challenge: b64url(hash) };
}

// ---------- Auth ----------
async function login() {
  if (CLIENT_ID === 'COLE_SEU_CLIENT_ID_AQUI') {
    alert('Edite app.js e coloque seu Spotify Client ID antes de logar.');
    return;
  }
  const { verifier, challenge } = await pkcePair();
  // localStorage (não sessionStorage) para o popup de login conseguir ler o verifier,
  // já que sessionStorage não é compartilhado entre janelas.
  localStorage.setItem('pkce_verifier', verifier);
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    scope: SCOPES,
    redirect_uri: REDIRECT_URI,
    code_challenge_method: 'S256',
    code_challenge: challenge,
  });
  const url = `${AUTH_URL}?${params}`;
  // Dentro de um iframe (embutido no homeOS) a tela de login do Spotify é bloqueada
  // (X-Frame-Options). Abre num popup; o token vai pro localStorage (mesma origem)
  // e a versão embutida recarrega já logada.
  if (window.self !== window.top) {
    const w = 480, h = 720, x = (screen.width - w) / 2, y = (screen.height - h) / 2;
    window.open(url, 'spotify_login', `width=${w},height=${h},left=${x},top=${y}`);
  } else {
    window.location.href = url;
  }
}

async function exchangeCode(code) {
  const verifier = localStorage.getItem('pkce_verifier') || sessionStorage.getItem('verifier');
  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier,
  });
  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!res.ok) throw new Error('Token exchange failed: ' + await res.text());
  return res.json();
}

async function refresh() {
  const rt = localStorage.getItem('refresh_token');
  if (!rt) return null;
  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    grant_type: 'refresh_token',
    refresh_token: rt,
  });
  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!res.ok) return null;
  return res.json();
}

function saveTokens(t) {
  localStorage.setItem('access_token', t.access_token);
  if (t.refresh_token) localStorage.setItem('refresh_token', t.refresh_token);
  localStorage.setItem('expires_at', String(Date.now() + (t.expires_in - 60) * 1000));
  localStorage.setItem('scopes', SCOPES);
}

async function getToken() {
  // force re-login if the stored token was issued with a different scope set
  // (also catches legacy tokens saved before we started tracking scopes)
  const storedScopes = localStorage.getItem('scopes');
  const hasToken = localStorage.getItem('access_token') || localStorage.getItem('refresh_token');
  if (hasToken && storedScopes !== SCOPES) {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('expires_at');
    localStorage.removeItem('scopes');
    return null;
  }
  const expires = Number(localStorage.getItem('expires_at') || 0);
  let token = localStorage.getItem('access_token');
  if (!token || Date.now() >= expires) {
    const t = await refresh();
    if (!t) return null;
    saveTokens(t);
    token = t.access_token;
  }
  return token;
}

// ---------- Polling ----------
let currentTrackId = null;
let palette = [[40, 40, 60], [80, 80, 120], [200, 200, 220]];

async function poll() {
  try {
    const token = await getToken();
    if (!token) { showLogin(); return; }
    const res = await fetch(`${API_BASE}/me/player/currently-playing`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (res.status === 204 || res.status === 202) {
      setStatus('Nada tocando');
      document.getElementById('player').classList.add('hidden');
      document.body.classList.add('no-player');
      document.body.classList.remove('expanded-player');
      return;
    }
    if (res.status === 401) { localStorage.clear(); showLogin(); return; }
    if (!res.ok) { setStatus('Erro ' + res.status); return; }
    const data = await res.json();
    if (!data || !data.item) return;
    updateUI(data);
  } catch (e) {
    console.error(e);
    setStatus('Erro de rede');
  }
}

function fmtDuration(ms) {
  const total = Math.floor(ms / 1000);
  const m = Math.floor(total / 60);
  const s = String(total % 60).padStart(2, '0');
  return `${m}:${s}`;
}

function updateUI(data) {
  const item = data.item;
  document.getElementById('track').textContent = item.name;
  document.getElementById('artist').textContent = item.artists.map(a => a.name).join(', ');

  const extraParts = [];
  if (item.album && item.album.name) extraParts.push(item.album.name);
  if (item.album && item.album.release_date) extraParts.push(item.album.release_date.slice(0, 4));
  if (item.duration_ms) extraParts.push(fmtDuration(item.duration_ms));
  if (item.explicit) extraParts.push('Explicit');
  document.getElementById('extra').textContent = extraParts.join('  ·  ');

  const pct = (data.progress_ms / item.duration_ms) * 100;
  document.getElementById('progress-fill').style.width = pct + '%';

  vizState.progressMs = data.progress_ms;
  vizState.durationMs = item.duration_ms;
  vizState.isPlaying = data.is_playing;
  vizState.lastSync = performance.now();
  syncPlayPauseIcon();

  if (item.id !== currentTrackId) {
    currentTrackId = item.id;
    if (queueOpen) fetchQueue();
    const cover = document.getElementById('cover');
    const img = new Image();
    img.crossOrigin = 'anonymous';
    img.onload = () => {
      cover.src = img.src;
      try {
        const ct = new ColorThief();
        palette = ct.getPalette(img, 5);
      } catch (e) { console.warn('color extract failed', e); }
    };
    img.src = item.album.images[0].url;
    loadLyrics(item);
  }

  document.getElementById('player').classList.remove('hidden');
  document.body.classList.remove('no-player');
  document.getElementById('login').classList.add('hidden');
  setStatus('');
}

function setStatus(msg) {
  const el = document.getElementById('status');
  if (!msg) { el.classList.add('hidden'); return; }
  el.textContent = msg;
  el.classList.remove('hidden');
}

function showLogin() {
  document.getElementById('login').classList.remove('hidden');
  document.getElementById('player').classList.add('hidden');
}

// ---------- Lyrics (LRCLIB) ----------
let lyrics = [];
let lyricEls = [];
let currentLyricIdx = -2;
const LINE_GAP_PX = 74;
const VISIBLE_RANGE = 4;
const lyricsEl = document.getElementById('lyrics');
const skeletonEl = document.getElementById('lyrics-skeleton');
let skeletonTimer = null;
let lyricsEnabled = localStorage.getItem('lyrics_enabled') !== 'false';

function setPlayerExpanded(expanded) {
  document.getElementById('player').classList.toggle('expanded', expanded);
  document.body.classList.toggle('expanded-player', expanded);
}

function applyLyricsVisibility() {
  const playerEl = document.getElementById('player');
  const hasLoaded = lyrics.length > 0;
  if (lyricsEnabled && hasLoaded) {
    lyricsEl.classList.remove('hidden');
    setPlayerExpanded(false);
  } else {
    lyricsEl.classList.add('hidden');
    if (!playerEl.classList.contains('hidden')) {
      setPlayerExpanded(true);
    }
  }
}

function showSkeleton() {
  clearTimeout(skeletonTimer);
  // small delay avoids flash for very fast (cached) responses
  skeletonTimer = setTimeout(() => skeletonEl.classList.remove('hidden'), 120);
}

function hideSkeleton() {
  clearTimeout(skeletonTimer);
  skeletonEl.classList.add('hidden');
}

async function loadLyrics(item) {
  lyrics = [];
  lyricEls = [];
  currentLyricIdx = -2;
  lyricsEl.innerHTML = '';
  lyricsEl.classList.add('hidden');

  // user has lyrics turned off globally — skip fetch, expand the card
  if (!lyricsEnabled) {
    setPlayerExpanded(true);
    return;
  }

  setPlayerExpanded(false);
  showSkeleton();

  const params = new URLSearchParams({
    track_name: item.name,
    artist_name: item.artists[0].name,
    album_name: item.album.name,
    duration: String(Math.round(item.duration_ms / 1000)),
  });

  try {
    const res = await fetch(`https://lrclib.net/api/get?${params}`);
    if (res.ok) {
      const data = await res.json();
      if (data && data.syncedLyrics) {
        lyrics = parseLRC(data.syncedLyrics);
        if (lyrics.length) buildLyricDom();
      }
    }
  } catch (e) {
    console.warn('lyrics fetch failed', e);
  } finally {
    hideSkeleton();
    applyLyricsVisibility();
  }
}

function parseLRC(text) {
  const out = [];
  const re = /\[(\d+):(\d+)(?:[.:](\d+))?\](.*)/;
  for (const line of text.split('\n')) {
    const m = line.match(re);
    if (!m) continue;
    const min = parseInt(m[1], 10);
    const sec = parseInt(m[2], 10);
    const frac = m[3] ? parseInt(m[3].padEnd(3, '0').slice(0, 3), 10) : 0;
    const time = (min * 60 + sec) * 1000 + frac;
    const txt = m[4].trim() || '♪'; // ♪ for instrumental gaps
    out.push({ time, text: txt });
  }
  return out.sort((a, b) => a.time - b.time);
}

function buildLyricDom() {
  const frag = document.createDocumentFragment();
  lyricEls = lyrics.map((l) => {
    const div = document.createElement('div');
    div.className = 'lyric';
    div.textContent = l.text;
    frag.appendChild(div);
    return div;
  });
  lyricsEl.appendChild(frag);
}

function updateLyrics() {
  if (!lyrics.length) return;
  const ms = currentSec() * 1000;
  let idx = -1;
  for (let i = 0; i < lyrics.length; i++) {
    if (lyrics[i].time <= ms) idx = i;
    else break;
  }
  if (idx === currentLyricIdx) return;
  currentLyricIdx = idx;

  for (let i = 0; i < lyricEls.length; i++) {
    const offset = i - idx;
    const abs = Math.abs(offset);
    const el = lyricEls[i];

    if (abs > VISIBLE_RANGE) {
      el.style.opacity = '0';
      el.style.transform = `translateY(calc(-50% + ${Math.sign(offset) * (VISIBLE_RANGE + 1) * LINE_GAP_PX}px))`;
      el.classList.remove('current');
      continue;
    }

    el.style.transform = `translateY(calc(-50% + ${offset * LINE_GAP_PX}px))`;

    if (offset === 0) {
      el.classList.add('current');
      el.style.opacity = '1';
      el.style.filter = 'blur(0)';
    } else {
      el.classList.remove('current');
      el.style.opacity = String(Math.max(0.08, 0.5 - abs * 0.11));
      el.style.filter = `blur(${Math.min(2.5, abs * 0.6)}px)`;
    }
  }
}

// ---------- Visualizer ----------
const canvas = document.getElementById('viz');
const ctx = canvas.getContext('2d');
let W = 0, H = 0;

function resize() {
  W = canvas.width = window.innerWidth * devicePixelRatio;
  H = canvas.height = window.innerHeight * devicePixelRatio;
}
window.addEventListener('resize', resize);
resize();

const vizState = {
  progressMs: 0,
  durationMs: 0,
  isPlaying: true, // animate even before login
  lastSync: performance.now(),
};

function currentSec() {
  const base = vizState.progressMs;
  const delta = vizState.isPlaying ? performance.now() - vizState.lastSync : 0;
  return (base + delta) / 1000;
}

function drawBackground(t) {
  const c1 = palette[0] || [40, 40, 60];
  const c2 = palette[1] || [10, 10, 20];
  const bg = ctx.createRadialGradient(W/2, H/2, 0, W/2, H/2, Math.max(W, H) * 0.7);
  bg.addColorStop(0, `rgb(${Math.round(c1[0]*0.4)},${Math.round(c1[1]*0.4)},${Math.round(c1[2]*0.4)})`);
  bg.addColorStop(0.6, `rgb(${Math.round(c2[0]*0.15)},${Math.round(c2[1]*0.15)},${Math.round(c2[2]*0.15)})`);
  bg.addColorStop(1, '#000');
  ctx.fillStyle = bg;
  ctx.fillRect(0, 0, W, H);
}

// ---------- Per-visualizer tunable params ----------
const VIZ_PARAMS = {
  spectrum: [
    { key: 'cols', label: 'Colunas', min: 24, max: 96, step: 4, def: 56 },
    { key: 'rows', label: 'Linhas', min: 12, max: 40, step: 2, def: 24 },
    { key: 'glow', label: 'Brilho', min: 0.2, max: 1.6, step: 0.1, def: 1 },
    { key: 'peakDecay', label: 'Queda do pico', min: 0.1, max: 2, step: 0.1, def: 0.5 },
    { key: 'tilt', label: 'Reforço agudos', min: 0, max: 3, step: 0.1, def: 1 },
    { key: 'range', label: 'Alcance freq.', min: 0.2, max: 1, step: 0.05, def: 0.6 },
  ],
  particles: [
    { key: 'count', label: 'Quantidade', min: 20, max: 200, step: 10, def: 70 },
    { key: 'size', label: 'Tamanho', min: 0.5, max: 3, step: 0.1, def: 1 },
    { key: 'react', label: 'Reatividade', min: 0, max: 3, step: 0.1, def: 1 },
  ],
  waves: [
    { key: 'lines', label: 'Linhas', min: 1, max: 6, step: 1, def: 3 },
    { key: 'amp', label: 'Amplitude', min: 0.3, max: 3, step: 0.1, def: 1 },
    { key: 'speed', label: 'Velocidade', min: 0.2, max: 3, step: 0.1, def: 1 },
    { key: 'opacity', label: 'Opacidade', min: 0.1, max: 1, step: 0.05, def: 1 },
  ],
  oscilloscope: [
    { key: 'amp', label: 'Amplitude', min: 0.3, max: 2, step: 0.1, def: 1 },
    { key: 'glow', label: 'Brilho', min: 0.2, max: 2, step: 0.1, def: 1 },
    { key: 'crt', label: 'Efeito CRT', min: 0, max: 1.5, step: 0.1, def: 1 },
  ],
  kitty: [
    { key: 'count', label: 'Gatinhos', min: 2, max: 10, step: 1, def: 6 },
    { key: 'size', label: 'Tamanho', min: 0.5, max: 2, step: 0.1, def: 1 },
    { key: 'react', label: 'Reatividade', min: 0, max: 3, step: 0.1, def: 1 },
  ],
};

const VIZ_SETTINGS_KEY = 'viz_params_v1';
let vizSettings = {};
try { vizSettings = JSON.parse(localStorage.getItem(VIZ_SETTINGS_KEY) || '{}'); } catch { vizSettings = {}; }

function saveVizSettings() {
  try { localStorage.setItem(VIZ_SETTINGS_KEY, JSON.stringify(vizSettings)); } catch {}
}

function getP(vizId, key) {
  const stored = vizSettings[vizId] && vizSettings[vizId][key];
  if (typeof stored === 'number' && !Number.isNaN(stored)) return stored;
  const def = (VIZ_PARAMS[vizId] || []).find((p) => p.key === key);
  return def ? def.def : 0;
}

function setP(vizId, key, value) {
  (vizSettings[vizId] = vizSettings[vizId] || {})[key] = value;
  saveVizSettings();
}

// --- Scene: Waves ---
function renderWaves(t) {
  const c1 = palette[0] || [40, 40, 60];
  const lines = Math.round(getP('waves', 'lines'));
  const ampMul = getP('waves', 'amp');
  const speed = getP('waves', 'speed');
  const opMul = getP('waves', 'opacity');
  const amp = (1 + audioAmplitude() * 2.2) * ampMul;
  ctx.lineWidth = 1.5 * devicePixelRatio;
  for (let wi = 0; wi < lines; wi++) {
    const color = palette[wi % palette.length] || c1;
    ctx.strokeStyle = `rgba(${color[0]},${color[1]},${color[2]},${(0.28 + audioAmplitude() * 0.3) * opMul})`;
    ctx.beginPath();
    for (let x = 0; x <= W; x += 4) {
      const y = H/2
        + Math.sin(x * 0.005 + t * 0.8 * speed + wi * 1.7) * H * 0.14 * amp
        + Math.sin(x * 0.012 + t * 1.3 * speed + wi) * H * 0.07 * amp;
      x === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    }
    ctx.stroke();
  }
}

// --- Scene: Particles ---
function makeParticles(n) {
  return Array.from({ length: n }, () => ({
    x: Math.random(),
    y: Math.random(),
    vx: (Math.random() - 0.5) * 0.06,
    vy: (Math.random() - 0.5) * 0.06,
    r: 1 + Math.random() * 3.5,
    ci: Math.floor(Math.random() * 5),
    phase: Math.random() * Math.PI * 2,
    angle: Math.random() * Math.PI * 2, // current thrust heading (accumulates)
    spinDir: Math.random() < 0.5 ? 1 : -1, // CW or CCW under audio
    freqBin: 2 + Math.floor(Math.random() * 60), // each particle "tuned" to a freq band
  }));
}
let PARTICLES = makeParticles(70);

let lastParticleMs = 0;
function renderParticles(t) {
  const nowMs = performance.now();
  const dt = lastParticleMs ? Math.min(0.05, (nowMs - lastParticleMs) / 1000) : 0;
  lastParticleMs = nowMs;

  const hasAudio = !!freqData;
  const overallE = hasAudio ? audioAmplitude() : 0;
  const wantCount = Math.round(getP('particles', 'count'));
  if (PARTICLES.length !== wantCount) PARTICLES = makeParticles(wantCount);
  const sizeMul = getP('particles', 'size');
  const reactMul = getP('particles', 'react');
  ctx.globalCompositeOperation = 'lighter';

  for (const p of PARTICLES) {
    let reactE = 0;
    let bandE = 0;
    if (hasAudio) {
      bandE = (freqData[p.freqBin] || 0) / 255;
      reactE = (overallE * 0.85 + bandE * 0.55) * reactMul;
      // angle accumulates: slow base drift + audio-driven spin (sign per particle)
      // bandE adds an extra twist so each band's hit changes that particle's heading
      const angVel = 0.3 + reactE * 6 + bandE * 4 * p.spinDir;
      p.angle += angVel * p.spinDir * dt;
      const thrust = reactE * reactE * 5.5;
      p.vx += Math.cos(p.angle) * thrust * dt;
      p.vy += Math.sin(p.angle) * thrust * dt;
      const drag = Math.pow(0.35, dt);
      p.vx *= drag;
      p.vy *= drag;
    } else {
      // silent baseline rotation so heading still drifts when no audio
      p.angle += 0.2 * p.spinDir * dt;
    }

    // ambient drift — always-on subtle motion so static moments still breathe
    p.vx += Math.sin(t * 0.4 + p.phase) * 0.0025 * dt;
    p.vy += Math.cos(t * 0.5 + p.phase * 1.3) * 0.0025 * dt;

    // integrate + wrap
    p.x += p.vx * dt;
    p.y += p.vy * dt;
    if (p.x < 0) p.x += 1; else if (p.x > 1) p.x -= 1;
    if (p.y < 0) p.y += 1; else if (p.y > 1) p.y -= 1;

    const px = p.x * W;
    const py = p.y * H;
    const color = palette[p.ci % palette.length] || [180, 180, 200];
    const pulse = (1 + Math.sin(t * 1.2 + p.phase) * 0.3) * (1 + reactE * 1.8);
    const r = p.r * devicePixelRatio * pulse * sizeMul;

    const grd = ctx.createRadialGradient(px, py, 0, px, py, r * 9);
    grd.addColorStop(0, `rgba(${color[0]},${color[1]},${color[2]},0.55)`);
    grd.addColorStop(1, `rgba(${color[0]},${color[1]},${color[2]},0)`);
    ctx.fillStyle = grd;
    ctx.fillRect(px - r*9, py - r*9, r*18, r*18);

    ctx.fillStyle = `rgba(${color[0]},${color[1]},${color[2]},0.95)`;
    ctx.beginPath();
    ctx.arc(px, py, r, 0, Math.PI * 2);
    ctx.fill();
  }
  ctx.globalCompositeOperation = 'source-over';
}

// --- Scene: Spectrum (liquid glass LED matrix) ---
let peakLevels = new Float32Array(56);

function lerpColor(a, b, t) {
  return [
    Math.round(a[0] + (b[0] - a[0]) * t),
    Math.round(a[1] + (b[1] - a[1]) * t),
    Math.round(a[2] + (b[2] - a[2]) * t),
  ];
}

function roundRectPath(x, y, w, h, r) {
  const rr = Math.min(r, w / 2, h / 2);
  ctx.beginPath();
  if (ctx.roundRect) {
    ctx.roundRect(x, y, w, h, rr);
  } else {
    ctx.moveTo(x + rr, y);
    ctx.arcTo(x + w, y, x + w, y + h, rr);
    ctx.arcTo(x + w, y + h, x, y + h, rr);
    ctx.arcTo(x, y + h, x, y, rr);
    ctx.arcTo(x, y, x + w, y, rr);
    ctx.closePath();
  }
}

function drawGlassCell(x, y, size, col, intensity) {
  const r = size * 0.3;
  const a = 0.55 * intensity; // ambient: lower base alpha

  // 1. soft halo — diffuse, not punchy
  const haloR = size * 0.75;
  const halo = ctx.createRadialGradient(
    x + size / 2, y + size / 2, size * 0.1,
    x + size / 2, y + size / 2, haloR
  );
  halo.addColorStop(0, `rgba(${col[0]},${col[1]},${col[2]},${0.14 * intensity})`);
  halo.addColorStop(1, `rgba(${col[0]},${col[1]},${col[2]},0)`);
  ctx.fillStyle = halo;
  ctx.fillRect(x - size * 0.35, y - size * 0.35, size * 1.7, size * 1.7);

  // 2. body — subtle vertical gradient, no white bump on top (kills the emoji vibe)
  roundRectPath(x, y, size, size, r);
  const body = ctx.createLinearGradient(x, y, x, y + size);
  body.addColorStop(0, `rgba(${col[0]},${col[1]},${col[2]},${a})`);
  body.addColorStop(1, `rgba(${(col[0]*0.7)|0},${(col[1]*0.7)|0},${(col[2]*0.7)|0},${a * 0.85})`);
  ctx.fillStyle = body;
  ctx.fill();
}

function drawOffCell(x, y, size, col) {
  // barely-there ghost grid — gives the "screen" texture without screaming
  const r = size * 0.3;
  roundRectPath(x, y, size, size, r);
  ctx.fillStyle = `rgba(${col[0]},${col[1]},${col[2]},0.025)`;
  ctx.fill();
}

let lastSpectrumMs = 0;
function renderSpectrum(t) {
  const nowMs = performance.now();
  const dt = lastSpectrumMs ? Math.min(0.1, (nowMs - lastSpectrumMs) / 1000) : 0;
  lastSpectrumMs = nowMs;

  const BAR_COUNT = Math.round(getP('spectrum', 'cols'));
  const SEGMENTS = Math.round(getP('spectrum', 'rows'));
  const PEAK_DECAY = getP('spectrum', 'peakDecay');
  const glowMul = getP('spectrum', 'glow');
  const tilt = getP('spectrum', 'tilt');
  const rangeFrac = getP('spectrum', 'range');
  if (peakLevels.length !== BAR_COUNT) peakLevels = new Float32Array(BAR_COUNT);

  const hasAudio = !!freqData;
  const dpr = devicePixelRatio;
  const sidePad = 24 * dpr;
  const usableW = W - sidePad * 2;
  const cellSize = usableW / (BAR_COUNT * 1.45);
  const cellGap = (usableW - cellSize * BAR_COUNT) / (BAR_COUNT - 1);
  const fieldH = SEGMENTS * cellSize + (SEGMENTS - 1) * cellGap;
  const baseY = Math.min(H * 0.88, H * 0.5 + fieldH / 2);

  const low = palette[0] || [80, 200, 120];
  const mid = palette[1] || palette[0] || [200, 180, 100];
  const high = palette[2] || palette[1] || [240, 100, 80];

  // pre-compute per-row colors
  const rowColors = new Array(SEGMENTS);
  for (let s = 0; s < SEGMENTS; s++) {
    const ratio = s / (SEGMENTS - 1);
    rowColors[s] = ratio < 0.5
      ? lerpColor(low, mid, ratio * 2)
      : lerpColor(mid, high, (ratio - 0.5) * 2);
  }

  // pass 1: off cells (simple, batched look)
  for (let i = 0; i < BAR_COUNT; i++) {
    const x = sidePad + i * (cellSize + cellGap);
    for (let s = 0; s < SEGMENTS; s++) {
      const y = baseY - (s + 1) * cellSize - s * cellGap;
      drawOffCell(x, y, cellSize, rowColors[s]);
    }
  }

  // pass 2: active cells + peaks (the expensive glass passes)
  ctx.globalCompositeOperation = 'lighter';
  for (let i = 0; i < BAR_COUNT; i++) {
    let v;
    if (hasAudio) {
      v = Math.pow(audioBin(i, BAR_COUNT, rangeFrac), 0.7);
      // tilt: linear gain ramp toward high frequencies to counter
      // music's natural bass-heavy energy distribution
      v *= 1 + tilt * (i / (BAR_COUNT - 1));
    } else {
      const f1 = Math.sin(t * 2.1 + i * 0.35);
      const f2 = Math.sin(t * 4.7 + i * 0.71);
      const f3 = Math.sin(t * 1.3 + i * 1.13);
      v = (f1 * 0.5 + f2 * 0.3 + f3 * 0.2 + 1) / 2;
      v *= 0.55 + (1 - i / BAR_COUNT) * 0.55;
    }
    v = Math.max(0, Math.min(1, v));

    if (v > peakLevels[i]) peakLevels[i] = v;
    else peakLevels[i] = Math.max(0, peakLevels[i] - PEAK_DECAY * dt);

    const activeSegs = Math.round(v * SEGMENTS);
    const x = sidePad + i * (cellSize + cellGap);

    for (let s = 0; s < activeSegs; s++) {
      const y = baseY - (s + 1) * cellSize - s * cellGap;
      // brighter near the top of the bar for "warming up"
      const intensity = 0.7 + (s / Math.max(1, activeSegs - 1)) * 0.3;
      drawGlassCell(x, y, cellSize, rowColors[s], intensity * glowMul);
    }

    if (peakLevels[i] > 0.04) {
      const peakSeg = Math.min(SEGMENTS - 1, Math.floor(peakLevels[i] * SEGMENTS));
      const py = baseY - (peakSeg + 1) * cellSize - peakSeg * cellGap;
      drawGlassCell(x, py, cellSize, rowColors[peakSeg], glowMul);
    }
  }
  ctx.globalCompositeOperation = 'source-over';
}

// --- Scene: Cats (cute audio-reactive kitties) ---
const CAT_COLORS = [
  { fur: '#f4a59a', inner: '#ffc7be' }, // pink
  { fur: '#e8a85a', inner: '#f4c98a' }, // orange tabby
  { fur: '#9a9a9a', inner: '#bdbdbd' }, // grey
  { fur: '#3a3a3a', inner: '#6a6a6a' }, // black
  { fur: '#f5e6d3', inner: '#fff4e3' }, // cream
  { fur: '#704632', inner: '#9b6a4c' }, // brown
];
function makeCats(n) {
  return Array.from({ length: n }, (_, i) => ({
    color: CAT_COLORS[i % CAT_COLORS.length],
    freqBin: 4 + i * 8,
    earPhase: Math.random() * Math.PI * 2,
    blinkTimer: 1 + Math.random() * 4,
    blinking: 0,
  }));
}
let CATS = makeCats(6);

function drawCat(cx, cy, size, m) {
  const s = size * m.scale;
  const col = m.color;
  ctx.save();
  ctx.translate(cx, cy + m.bob);

  // ears
  const earBase = s * 0.36;
  const earH = s * 0.42;
  for (const side of [-1, 1]) {
    ctx.save();
    ctx.translate(side * s * 0.32, -s * 0.35);
    ctx.rotate(side * (0.25 + m.earTilt * side));
    // outer
    ctx.fillStyle = col.fur;
    ctx.beginPath();
    ctx.moveTo(-earBase / 2, earBase / 2);
    ctx.lineTo(earBase / 2, earBase / 2);
    ctx.lineTo(0, -earH / 2);
    ctx.closePath();
    ctx.fill();
    // inner
    ctx.fillStyle = '#ffb6c1';
    ctx.beginPath();
    ctx.moveTo(-earBase / 3, earBase / 3);
    ctx.lineTo(earBase / 3, earBase / 3);
    ctx.lineTo(0, -earH / 3.5);
    ctx.closePath();
    ctx.fill();
    ctx.restore();
  }

  // head
  ctx.fillStyle = col.fur;
  ctx.beginPath();
  ctx.arc(0, 0, s / 2, 0, Math.PI * 2);
  ctx.fill();

  // cheeks (subtle blush)
  ctx.fillStyle = 'rgba(255,150,170,0.45)';
  ctx.beginPath();
  ctx.arc(-s * 0.26, s * 0.08, s * 0.08, 0, Math.PI * 2);
  ctx.arc(s * 0.26, s * 0.08, s * 0.08, 0, Math.PI * 2);
  ctx.fill();

  // eyes
  const eyeY = -s * 0.05;
  const eyeX = s * 0.18;
  ctx.fillStyle = '#1a1a1a';
  if (m.eyeOpen > 0.3) {
    for (const ex of [-eyeX, eyeX]) {
      ctx.beginPath();
      ctx.ellipse(ex, eyeY, s * 0.055, s * 0.13 * m.eyeOpen, 0, 0, Math.PI * 2);
      ctx.fill();
      // shine
      ctx.fillStyle = '#fff';
      ctx.beginPath();
      ctx.arc(ex + s * 0.02, eyeY - s * 0.04 * m.eyeOpen, s * 0.018, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = '#1a1a1a';
    }
  } else {
    // happy closed-eye arcs
    ctx.lineWidth = s * 0.035;
    ctx.strokeStyle = '#1a1a1a';
    ctx.lineCap = 'round';
    for (const ex of [-eyeX, eyeX]) {
      ctx.beginPath();
      ctx.arc(ex, eyeY + s * 0.04, s * 0.08, Math.PI * 1.15, Math.PI * 1.85, true);
      ctx.stroke();
    }
  }

  // nose
  ctx.fillStyle = '#ff8da1';
  ctx.beginPath();
  ctx.moveTo(-s * 0.045, s * 0.09);
  ctx.lineTo(s * 0.045, s * 0.09);
  ctx.lineTo(0, s * 0.14);
  ctx.closePath();
  ctx.fill();

  // mouth
  ctx.lineWidth = s * 0.025;
  ctx.strokeStyle = '#1a1a1a';
  ctx.lineCap = 'round';
  ctx.beginPath();
  ctx.moveTo(0, s * 0.14);
  ctx.lineTo(0, s * 0.18);
  ctx.stroke();
  if (m.mouthOpen > 0.15) {
    // singing "o"
    ctx.fillStyle = '#5a2a3a';
    ctx.beginPath();
    ctx.ellipse(0, s * 0.24, s * 0.07, s * 0.06 * (1 + m.mouthOpen * 1.4), 0, 0, Math.PI * 2);
    ctx.fill();
  } else {
    // ":3" mouth
    ctx.beginPath();
    ctx.arc(-s * 0.05, s * 0.18, s * 0.05, 0, Math.PI);
    ctx.stroke();
    ctx.beginPath();
    ctx.arc(s * 0.05, s * 0.18, s * 0.05, 0, Math.PI);
    ctx.stroke();
  }

  // whiskers
  ctx.lineWidth = s * 0.012;
  ctx.strokeStyle = 'rgba(255,255,255,0.85)';
  for (let i = 0; i < 3; i++) {
    const wy = s * 0.12 + i * s * 0.045;
    const droop = (i - 1) * s * 0.025;
    ctx.beginPath();
    ctx.moveTo(-s * 0.17, wy);
    ctx.lineTo(-s * 0.42, wy + droop);
    ctx.stroke();
    ctx.beginPath();
    ctx.moveTo(s * 0.17, wy);
    ctx.lineTo(s * 0.42, wy + droop);
    ctx.stroke();
  }

  ctx.restore();
}

let lastCatMs = 0;
function renderCats(t) {
  const nowMs = performance.now();
  const dt = lastCatMs ? Math.min(0.1, (nowMs - lastCatMs) / 1000) : 0;
  lastCatMs = nowMs;

  const hasAudio = !!freqData;
  const overall = hasAudio ? audioAmplitude() : 0;

  const wantCats = Math.round(getP('kitty', 'count'));
  if (CATS.length !== wantCats) CATS = makeCats(wantCats);
  const CAT_COUNT = CATS.length;
  const reactMul = getP('kitty', 'react');
  const catSize = Math.min(W * 0.14, H * 0.22) * getP('kitty', 'size');
  const spacing = Math.min(W / (CAT_COUNT + 1), catSize * 1.45);
  const rowY = H * 0.62;
  const startX = W / 2 - (CAT_COUNT - 1) * spacing / 2;

  for (let i = 0; i < CAT_COUNT; i++) {
    const cat = CATS[i];
    const bandE = hasAudio ? (freqData[cat.freqBin] || 0) / 255 : 0;
    const totalE = (overall * 0.55 + bandE * 0.8) * reactMul;

    // blink timer
    cat.blinkTimer -= dt;
    if (cat.blinkTimer <= 0) {
      cat.blinkTimer = 2.5 + Math.random() * 4;
      cat.blinking = 0.22;
    }
    cat.blinking = Math.max(0, cat.blinking - dt);
    const blinkFrac = cat.blinking > 0 ? cat.blinking / 0.22 : 0;
    const eyeOpen = 1 - blinkFrac;

    // idle bob + audio bounce
    const idle = Math.sin(t * 1.6 + i * 0.7) * catSize * 0.035;
    const bob = idle - totalE * catSize * 0.22;
    const earTilt = Math.sin(t * 3 + cat.earPhase) * 0.08 + bandE * 0.45 * (i % 2 ? 1 : -1);
    const scale = 1 + totalE * 0.16;
    const mouthOpen = Math.max(0, bandE * 1.6 - 0.18);

    drawCat(startX + i * spacing, rowY, catSize, {
      bob, earTilt, eyeOpen, mouthOpen, scale,
      color: cat.color,
    });
  }
}

// --- Scene: Oscilloscope ---
// Trigger: among all rising zero-crossings in the first half of the buffer,
// pick the one with the steepest local slope (favors the fundamental period),
// then bias toward the previous frame's lock point so the trace stays put.
let lastTriggerIdx = 0;
const TRIGGER_DIST_PENALTY = 0.25;
function findRisingEdge(data) {
  const half = (data.length / 2) | 0;
  let bestIdx = -1;
  let bestScore = -Infinity;
  for (let i = 4; i < half - 4; i++) {
    if (data[i - 1] < 128 && data[i] >= 128) {
      const slope = data[i + 3] - data[i - 3]; // strength of this crossing
      const score = slope - Math.abs(i - lastTriggerIdx) * TRIGGER_DIST_PENALTY;
      if (score > bestScore) { bestScore = score; bestIdx = i; }
    }
  }
  if (bestIdx >= 0) lastTriggerIdx = bestIdx;
  return bestIdx < 0 ? 0 : bestIdx;
}

let scopeGain = 5;
let scanlinePattern = null;
function getScanlinePattern() {
  if (scanlinePattern) return scanlinePattern;
  const off = document.createElement('canvas');
  const lineH = Math.max(2, Math.round(2 * devicePixelRatio));
  off.width = 4;
  off.height = lineH * 2;
  const oc = off.getContext('2d');
  oc.fillStyle = 'rgba(0,0,0,0.28)';
  oc.fillRect(0, lineH, 4, lineH);
  scanlinePattern = ctx.createPattern(off, 'repeat');
  return scanlinePattern;
}

function renderOscilloscope(t) {
  const dpr = devicePixelRatio;
  const hasAudio = !!timeData;

  // graticule (oscilloscope grid)
  ctx.strokeStyle = 'rgba(255,255,255,0.04)';
  ctx.lineWidth = 1 * dpr;
  ctx.beginPath();
  for (let i = 1; i < 10; i++) {
    const x = (W / 10) * i;
    ctx.moveTo(x, 0); ctx.lineTo(x, H);
  }
  for (let i = 1; i < 8; i++) {
    const y = (H / 8) * i;
    ctx.moveTo(0, y); ctx.lineTo(W, y);
  }
  ctx.stroke();

  // bolder center crosshair
  ctx.strokeStyle = 'rgba(255,255,255,0.09)';
  ctx.lineWidth = 1.5 * dpr;
  ctx.beginPath();
  ctx.moveTo(0, H / 2); ctx.lineTo(W, H / 2);
  ctx.moveTo(W / 2, 0); ctx.lineTo(W / 2, H);
  ctx.stroke();

  // tiny tick marks along center axes (the retro scope touch)
  ctx.strokeStyle = 'rgba(255,255,255,0.12)';
  ctx.lineWidth = 1 * dpr;
  ctx.beginPath();
  const tick = 4 * dpr;
  for (let i = 0; i <= 50; i++) {
    const x = (W / 50) * i;
    ctx.moveTo(x, H / 2 - tick); ctx.lineTo(x, H / 2 + tick);
  }
  for (let i = 0; i <= 40; i++) {
    const y = (H / 40) * i;
    ctx.moveTo(W / 2 - tick, y); ctx.lineTo(W / 2 + tick, y);
  }
  ctx.stroke();

  // CRT phosphor green — locked color, ignores palette for that vintage scope look
  const colStr = '60,255,120';
  const hotCore = '210,255,220';

  // when lyrics are showing, push the trace below the lyric band so text stays readable;
  // otherwise center it vertically
  const lyricsVisible = lyricsEnabled && lyrics.length > 0;
  const traceH = (lyricsVisible ? H * 0.3 : H * 0.44) * getP('oscilloscope', 'amp');
  const centerY = lyricsVisible ? H * 0.72 : H * 0.5;
  let samples, getY;

  if (hasAudio) {
    // auto-gain — find current peak, target ~70% of trace height, smooth ramp
    let peak = 0.001;
    for (let i = 0; i < timeData.length; i++) {
      const v = Math.abs(timeData[i] - 128) / 128;
      if (v > peak) peak = v;
    }
    const target = Math.min(25, Math.max(1.5, 0.7 / peak));
    scopeGain += (target - scopeGain) * 0.1;

    const trigger = findRisingEdge(timeData);
    const usable = timeData.length - trigger;
    samples = Math.min(usable, timeData.length);
    getY = (i) => {
      let v = ((timeData[i + trigger] - 128) / 128) * scopeGain;
      if (v > 1.35) v = 1.35; else if (v < -1.35) v = -1.35;
      return centerY - v * traceH;
    };
  } else {
    // fake stable Lissajous-ish waveform when silent
    samples = 360;
    getY = (i) => {
      const ph = (i / samples) * Math.PI * 6;
      const v = Math.sin(ph + t * 1.4) * 0.35
              + Math.sin(ph * 2.7 + t * 0.9) * 0.18
              + Math.sin(ph * 5.1 + t * 2.2) * 0.08;
      return centerY - v * traceH;
    };
  }
  const stepX = W / (samples - 1);

  ctx.beginPath();
  for (let i = 0; i < samples; i++) {
    const x = i * stepX;
    const y = getY(i);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  }

  // additive blend so layered strokes sum into a bloom — true CRT phosphor feel
  ctx.globalCompositeOperation = 'lighter';
  ctx.lineJoin = 'round';
  ctx.lineCap = 'round';
  const glowMul = getP('oscilloscope', 'glow');
  const passes = [
    { w: 14 * dpr, a: 0.03, c: colStr },
    { w: 8 * dpr,  a: 0.07, c: colStr },
    { w: 4.5 * dpr, a: 0.18, c: colStr },
    { w: 2.2 * dpr, a: 0.5, c: colStr },
    { w: 1 * dpr,   a: 0.95, c: hotCore },
  ];
  for (const p of passes) {
    ctx.lineWidth = p.w;
    ctx.strokeStyle = `rgba(${p.c},${Math.min(1, p.a * glowMul)})`;
    ctx.stroke();
  }
  ctx.globalCompositeOperation = 'source-over';

  // ---- CRT post-process (intensity is user-tunable) ----
  const crt = getP('oscilloscope', 'crt');
  if (crt <= 0.01) return;
  const crtA = Math.min(1, crt);

  ctx.globalAlpha = crtA;
  ctx.fillStyle = 'rgba(20,60,30,0.04)';
  ctx.fillRect(0, 0, W, H);

  ctx.globalAlpha = 0.5 * crtA;
  ctx.fillStyle = getScanlinePattern();
  ctx.fillRect(0, 0, W, H);
  ctx.globalAlpha = crtA;

  // vignette — keep darkening but lighter through the middle band
  const vg = ctx.createRadialGradient(
    W / 2, H / 2, Math.min(W, H) * 0.35,
    W / 2, H / 2, Math.max(W, H) * 0.8
  );
  vg.addColorStop(0, 'rgba(0,0,0,0)');
  vg.addColorStop(0.7, 'rgba(0,0,0,0.18)');
  vg.addColorStop(1, 'rgba(0,0,0,0.55)');
  ctx.fillStyle = vg;
  ctx.fillRect(0, 0, W, H);

  const glare = ctx.createRadialGradient(
    W * 0.25, H * 0.18, 0,
    W * 0.25, H * 0.18, Math.min(W, H) * 0.5
  );
  glare.addColorStop(0, 'rgba(255,255,255,0.025)');
  glare.addColorStop(1, 'rgba(255,255,255,0)');
  ctx.fillStyle = glare;
  ctx.fillRect(0, 0, W, H);
  ctx.globalAlpha = 1;
}

const VISUALIZERS = [
  { id: 'spectrum', name: 'Spectrum', render: renderSpectrum },
  { id: 'particles', name: 'Particles', render: renderParticles },
  { id: 'waves', name: 'Waves', render: renderWaves },
  { id: 'oscilloscope', name: 'Scope', render: renderOscilloscope },
  { id: 'kitty', name: 'Kitty', render: renderCats },
];

let currentVizIdx = Number(localStorage.getItem('viz_idx') || 0);
if (!Number.isInteger(currentVizIdx) || currentVizIdx < 0 || currentVizIdx >= VISUALIZERS.length) {
  currentVizIdx = 0;
}

function setViz(idx) {
  currentVizIdx = (idx + VISUALIZERS.length) % VISUALIZERS.length;
  localStorage.setItem('viz_idx', String(currentVizIdx));
  document.getElementById('viz-name').textContent = VISUALIZERS[currentVizIdx].name;
  refreshVizSettingsPanel();
}

// ---------- Viz settings panel ----------
const vizSettingsBtn = document.getElementById('viz-settings');
const vizSettingsPanel = document.getElementById('viz-settings-panel');
let vizSettingsOpen = false;

function fmtParamValue(p, v) {
  return p.step < 1 ? Number(v).toFixed(p.step < 0.1 ? 2 : 1) : String(Math.round(v));
}

function buildVizSettingsPanel() {
  const viz = VISUALIZERS[currentVizIdx];
  const params = VIZ_PARAMS[viz.id] || [];
  vizSettingsPanel.innerHTML = '';

  const header = document.createElement('div');
  header.className = 'vsp-header';
  const title = document.createElement('span');
  title.textContent = `Ajustes · ${viz.name}`;
  const reset = document.createElement('button');
  reset.className = 'vsp-reset';
  reset.textContent = 'Resetar';
  reset.addEventListener('click', () => {
    delete vizSettings[viz.id];
    saveVizSettings();
    buildVizSettingsPanel();
  });
  header.appendChild(title);
  header.appendChild(reset);
  vizSettingsPanel.appendChild(header);

  for (const p of params) {
    const row = document.createElement('div');
    row.className = 'vsp-row';
    const label = document.createElement('label');
    label.textContent = p.label;
    const input = document.createElement('input');
    input.type = 'range';
    input.min = p.min;
    input.max = p.max;
    input.step = p.step;
    input.value = getP(viz.id, p.key);
    const val = document.createElement('span');
    val.className = 'vsp-value';
    val.textContent = fmtParamValue(p, getP(viz.id, p.key));
    input.addEventListener('input', () => {
      const v = Number(input.value);
      setP(viz.id, p.key, v);
      val.textContent = fmtParamValue(p, v);
    });
    row.appendChild(label);
    row.appendChild(input);
    row.appendChild(val);
    vizSettingsPanel.appendChild(row);
  }
}

function refreshVizSettingsPanel() {
  if (vizSettingsOpen) buildVizSettingsPanel();
}

function setVizSettingsOpen(open) {
  vizSettingsOpen = open;
  vizSettingsPanel.classList.toggle('hidden', !open);
  vizSettingsBtn.classList.toggle('active', open);
  if (open) buildVizSettingsPanel();
}

vizSettingsBtn.addEventListener('click', () => setVizSettingsOpen(!vizSettingsOpen));

function render() {
  const t = currentSec() || performance.now() / 1000;
  sampleAudio();
  updateLyrics();
  drawBackground(t);
  VISUALIZERS[currentVizIdx].render(t);
  requestAnimationFrame(render);
}

// ---------- Bootstrap ----------
document.getElementById('login-btn').addEventListener('click', login);
document.getElementById('viz-prev').addEventListener('click', () => setViz(currentVizIdx - 1));
document.getElementById('viz-next').addEventListener('click', () => setViz(currentVizIdx + 1));
window.addEventListener('keydown', (e) => {
  if (e.key === 'ArrowLeft') setViz(currentVizIdx - 1);
  if (e.key === 'ArrowRight') setViz(currentVizIdx + 1);
  if (e.key === 'f' || e.key === 'F') toggleFullscreen();
});
setViz(currentVizIdx);

// ---------- Playback controls ----------
const iconPlay = document.querySelector('.icon-play');
const iconPause = document.querySelector('.icon-pause');

function syncPlayPauseIcon() {
  iconPlay.style.display = vizState.isPlaying ? 'none' : '';
  iconPause.style.display = vizState.isPlaying ? '' : 'none';
  document.getElementById('ctrl-play').setAttribute('data-tip', vizState.isPlaying ? 'Pausar (Espaço)' : 'Tocar (Espaço)');
}

async function ctrl(method, path, body) {
  const token = await getToken();
  if (!token) return null;
  try {
    const res = await fetch(`${API_BASE}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (res.status === 403) setStatus('Requer Spotify Premium');
    else if (res.status === 404) setStatus('Nenhum dispositivo ativo');
    else if (res.ok || res.status === 204) setStatus('');
    return res;
  } catch (e) {
    console.warn('ctrl failed', e);
    return null;
  }
}

async function togglePlayPause() {
  const wasPlaying = vizState.isPlaying;
  vizState.isPlaying = !wasPlaying;
  vizState.lastSync = performance.now();
  syncPlayPauseIcon();
  await ctrl('PUT', wasPlaying ? '/me/player/pause' : '/me/player/play');
  setTimeout(poll, 300);
}

async function skipNext() {
  await ctrl('POST', '/me/player/next');
  setTimeout(poll, 350);
}

async function skipPrev() {
  await ctrl('POST', '/me/player/previous');
  setTimeout(poll, 350);
}

document.getElementById('ctrl-prev').addEventListener('click', skipPrev);
document.getElementById('ctrl-next').addEventListener('click', skipNext);
document.getElementById('ctrl-play').addEventListener('click', togglePlayPause);

window.addEventListener('keydown', (e) => {
  if (e.target && (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA')) return;
  if (e.code === 'Space') { e.preventDefault(); togglePlayPause(); }
  if (e.key === 'l' || e.key === 'L') setLyricsEnabled(!lyricsEnabled);
  if (e.key === 'q' || e.key === 'Q') setQueueOpen(!queueOpen);
});

// ---------- Audio reactivity ----------
let audioMode = 'off';
let audioCtx = null;
let analyser = null;
let analyserStream = null;
let freqData = null;
let timeData = null;

const audioSwitch = document.getElementById('audio-switch');
const audioOpts = Array.from(audioSwitch.querySelectorAll('.audio-opt'));
const audioLevelEl = document.getElementById('audio-level');

function updateAudioBtnUI() {
  for (const btn of audioOpts) {
    btn.classList.toggle('active', btn.dataset.mode === audioMode);
    btn.setAttribute('aria-checked', btn.dataset.mode === audioMode ? 'true' : 'false');
  }
}

function teardownAudio() {
  if (analyserStream) {
    analyserStream.getTracks().forEach((t) => t.stop());
    analyserStream = null;
  }
  if (audioCtx) {
    audioCtx.close().catch(() => {});
    audioCtx = null;
  }
  analyser = null;
  freqData = null;
  timeData = null;
}

async function setAudioMode(mode) {
  teardownAudio();
  audioMode = mode;
  updateAudioBtnUI();
  if (mode === 'off') { setStatus(''); return; }

  try {
    let stream;
    if (mode === 'mic') {
      stream = await navigator.mediaDevices.getUserMedia({
        audio: { echoCancellation: false, noiseSuppression: false, autoGainControl: false },
      });
    } else {
      // system: requires user to share a tab/window with audio
      stream = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: true });
      if (stream.getAudioTracks().length === 0) {
        stream.getTracks().forEach((t) => t.stop());
        setStatus('Você precisa marcar "Compartilhar áudio"');
        audioMode = 'off';
        updateAudioBtnUI();
        return;
      }
      // discard video, keep audio only
      stream.getVideoTracks().forEach((t) => t.stop());
    }

    analyserStream = stream;
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    // Chrome autoplay policy: AudioContext started behind an await can be suspended.
    // Force resume so the analyser actually receives samples.
    if (audioCtx.state === 'suspended') {
      try { await audioCtx.resume(); } catch (e) { console.warn('resume failed', e); }
    }
    const src = audioCtx.createMediaStreamSource(stream);
    analyser = audioCtx.createAnalyser();
    analyser.fftSize = 1024;
    analyser.smoothingTimeConstant = 0.78;
    src.connect(analyser);
    freqData = new Uint8Array(analyser.frequencyBinCount);
    timeData = new Uint8Array(analyser.frequencyBinCount);
    console.log('[audio] mode=%s, ctx state=%s, sampleRate=%d', mode, audioCtx.state, audioCtx.sampleRate);

    // if user stops the share via browser UI, revert
    stream.getAudioTracks()[0].addEventListener('ended', () => {
      if (audioMode !== 'off') setAudioMode('off');
    });
    setStatus('');
  } catch (e) {
    console.warn('audio mode failed', e);
    setStatus(mode === 'mic' ? 'Permissão de mic negada' : 'Compartilhamento cancelado');
    audioMode = 'off';
    updateAudioBtnUI();
  }
}

let lastLevelUpdate = 0;
function sampleAudio() {
  if (!analyser) return;
  analyser.getByteFrequencyData(freqData);
  analyser.getByteTimeDomainData(timeData);
  // throttle DOM write to ~20fps for the level meter
  const now = performance.now();
  if (now - lastLevelUpdate > 50) {
    lastLevelUpdate = now;
    const pct = Math.min(100, audioAmplitude() * 220);
    audioLevelEl.style.setProperty('--level', pct + '%');
  }
}

function audioAmplitude() {
  if (!freqData) return 0;
  // average of lower-mid bins (skip very low DC) for "punch"
  let sum = 0;
  const lo = 2, hi = Math.min(48, freqData.length);
  for (let i = lo; i < hi; i++) sum += freqData[i];
  return sum / ((hi - lo) * 255); // 0..1
}

function audioBin(idx, total, rangeFrac = 0.75) {
  if (!freqData) return 0;
  // log-ish mapping to spread visible spectrum across the bars;
  // rangeFrac caps the top frequency so bars aren't wasted on empty highs
  const usable = Math.max(8, Math.floor(freqData.length * rangeFrac));
  const t = idx / (total - 1);
  const start = Math.floor(Math.pow(t, 1.6) * usable);
  const end = Math.max(start + 1, Math.floor(Math.pow((idx + 1) / total, 1.6) * usable));
  let sum = 0;
  for (let i = start; i < end; i++) sum += freqData[i];
  return (sum / (end - start)) / 255;
}

for (const btn of audioOpts) {
  btn.addEventListener('click', () => {
    if (btn.dataset.mode !== audioMode) setAudioMode(btn.dataset.mode);
  });
}
updateAudioBtnUI();

// ---------- Lyrics toggle ----------
const lyricsToggleBtn = document.getElementById('lyrics-toggle');

function updateLyricsToggleUI() {
  lyricsToggleBtn.classList.toggle('active', lyricsEnabled);
  lyricsToggleBtn.setAttribute('data-tip', lyricsEnabled ? 'Esconder lyrics (L)' : 'Mostrar lyrics (L)');
}

async function setLyricsEnabled(enabled) {
  lyricsEnabled = enabled;
  localStorage.setItem('lyrics_enabled', String(enabled));
  updateLyricsToggleUI();
  // if turning on and we don't have lyrics in memory for the current track, refetch
  if (enabled && currentTrackId && lyrics.length === 0) {
    try {
      const token = await getToken();
      if (token) {
        const res = await fetch(`${API_BASE}/me/player/currently-playing`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (res.ok) {
          const data = await res.json();
          if (data && data.item) await loadLyrics(data.item);
        }
      }
    } catch (e) { console.warn('refetch lyrics failed', e); }
  } else {
    applyLyricsVisibility();
  }
}

lyricsToggleBtn.addEventListener('click', () => setLyricsEnabled(!lyricsEnabled));
updateLyricsToggleUI();

// ---------- Queue panel ----------
const queueToggleBtn = document.getElementById('queue-toggle');
const queuePanel = document.getElementById('queue-panel');
const queueList = document.getElementById('queue-list');
const queueCloseBtn = document.getElementById('queue-close');
let queueOpen = false;

function renderQueue(items) {
  queueList.innerHTML = '';
  if (!items || !items.length) {
    const empty = document.createElement('div');
    empty.className = 'queue-empty';
    empty.textContent = 'Nada na fila';
    queueList.appendChild(empty);
    return;
  }
  const frag = document.createDocumentFragment();
  for (const item of items.slice(0, 20)) {
    if (!item) continue;
    const row = document.createElement('div');
    row.className = 'queue-item';
    const img = document.createElement('img');
    img.src = item.album?.images?.[item.album.images.length - 1]?.url || '';
    img.alt = '';
    img.loading = 'lazy';
    const meta = document.createElement('div');
    meta.className = 'queue-item-meta';
    const title = document.createElement('div');
    title.className = 'queue-item-title';
    title.textContent = item.name || '';
    const artist = document.createElement('div');
    artist.className = 'queue-item-artist';
    artist.textContent = (item.artists || []).map((a) => a.name).join(', ');
    meta.appendChild(title);
    meta.appendChild(artist);
    row.appendChild(img);
    row.appendChild(meta);
    frag.appendChild(row);
  }
  queueList.appendChild(frag);
}

async function fetchQueue() {
  try {
    const token = await getToken();
    if (!token) return;
    const res = await fetch(`${API_BASE}/me/player/queue`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.status === 204 || res.status === 404) {
      renderQueue([]);
      return;
    }
    if (!res.ok) {
      console.warn('[queue] HTTP', res.status);
      return;
    }
    const data = await res.json();
    renderQueue(data.queue || []);
  } catch (e) {
    console.warn('[queue] fetch failed', e);
  }
}

function setQueueOpen(open) {
  queueOpen = open;
  queuePanel.classList.toggle('hidden', !open);
  queueToggleBtn.classList.toggle('active', open);
  if (open) fetchQueue();
}

queueToggleBtn.addEventListener('click', () => setQueueOpen(!queueOpen));
queueCloseBtn.addEventListener('click', () => setQueueOpen(false));

// ---------- Fullscreen ----------
function toggleFullscreen() {
  if (document.fullscreenElement) {
    document.exitFullscreen();
  } else {
    document.documentElement.requestFullscreen().catch((e) => console.warn('fullscreen failed', e));
  }
}

document.getElementById('fullscreen-btn').addEventListener('click', toggleFullscreen);
document.addEventListener('fullscreenchange', () => {
  const isFs = !!document.fullscreenElement;
  document.querySelector('.icon-enter').style.display = isFs ? 'none' : '';
  document.querySelector('.icon-exit').style.display = isFs ? '' : 'none';
  document.getElementById('fullscreen-btn').setAttribute('data-tip', isFs ? 'Sair da tela cheia (F)' : 'Tela cheia (F)');
});

// Quando o popup de login termina, ele avisa a janela principal (homeOS embutido),
// que recarrega o iframe para pegar o token recém-salvo no localStorage.
window.addEventListener('message', (e) => {
  if (e.data === 'spotify-auth-done') location.reload();
});

(async function init() {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  if (code) {
    try {
      const t = await exchangeCode(code);
      saveTokens(t);
      localStorage.removeItem('pkce_verifier');
      window.history.replaceState({}, '', REDIRECT_URI);
      if (window.opener) {
        // Estávamos no popup de login: avisa o homeOS e fecha o popup.
        try { window.opener.postMessage('spotify-auth-done', '*'); } catch {}
        window.close();
        return;
      }
    } catch (e) {
      console.error(e);
      setStatus('Falha no login');
    }
  }

  const token = await getToken();
  if (!token) {
    showLogin();
  } else {
    document.getElementById('login').classList.add('hidden');
    document.getElementById('viz-selector').classList.remove('hidden');
    document.getElementById('audio-switch').classList.remove('hidden');
    poll();
    setInterval(poll, 1500);
  }

  render();
})();
