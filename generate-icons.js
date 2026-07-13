"use strict";
// Gera ícones PNG do homeOS sem dependências externas (Node puro).
// Desenha uma casinha branca sobre fundo laranja (accent), full-bleed
// para ser seguro como maskable no Windows.
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

// ---- CRC32 (para chunks PNG) ----
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, "ascii");
  const body = Buffer.concat([typeBuf, data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([len, body, crc]);
}
function encodePng(width, height, rgba) {
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;   // bit depth
  ihdr[9] = 6;   // color type RGBA
  ihdr[10] = 0;  // compression
  ihdr[11] = 0;  // filter
  ihdr[12] = 0;  // interlace
  // raw scanlines with filter byte 0
  const stride = width * 4;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0;
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, y * stride + stride);
  }
  const idat = zlib.deflateSync(raw, { level: 9 });
  return Buffer.concat([sig, chunk("IHDR", ihdr), chunk("IDAT", idat), chunk("IEND", Buffer.alloc(0))]);
}

// ---- desenho ----
const ACCENT = [194, 89, 42];   // #c2592a
const WHITE = [255, 255, 255];

function inTriangle(px, py, a, b, c) {
  const d1 = (px - b[0]) * (a[1] - b[1]) - (a[0] - b[0]) * (py - b[1]);
  const d2 = (px - c[0]) * (b[1] - c[1]) - (b[0] - c[0]) * (py - c[1]);
  const d3 = (px - a[0]) * (c[1] - a[1]) - (c[0] - a[0]) * (py - a[1]);
  const hasNeg = d1 < 0 || d2 < 0 || d3 < 0;
  const hasPos = d1 > 0 || d2 > 0 || d3 > 0;
  return !(hasNeg && hasPos);
}

// circular=true → recorta num círculo com cantos transparentes (ícone redondo).
// circular=false → full-bleed quadrado (usado no purpose maskable).
function drawIcon(N, circular) {
  const rgba = Buffer.alloc(N * N * 4);
  const roofApex = [0.5 * N, 0.28 * N];
  const roofL = [0.22 * N, 0.53 * N];
  const roofR = [0.78 * N, 0.53 * N];
  const bodyX0 = 0.30 * N, bodyX1 = 0.70 * N, bodyY0 = 0.50 * N, bodyY1 = 0.75 * N;
  const doorX0 = 0.445 * N, doorX1 = 0.555 * N, doorY0 = 0.60 * N, doorY1 = 0.75 * N;
  const cx = N / 2, cy = N / 2, radius = N / 2;
  // supersample 3x para bordas suaves (círculo + casa)
  const SS = 3;
  const samples = SS * SS;
  for (let y = 0; y < N; y++) {
    for (let x = 0; x < N; x++) {
      let coverage = 0; // fração dentro do círculo (ou 1 se quadrado)
      let whiteHits = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const px = x + (sx + 0.5) / SS;
          const py = y + (sy + 0.5) / SS;
          const insideShape = circular
            ? ((px - cx) * (px - cx) + (py - cy) * (py - cy)) <= radius * radius
            : true;
          if (!insideShape) continue;
          coverage++;
          const inBody = px >= bodyX0 && px <= bodyX1 && py >= bodyY0 && py <= bodyY1;
          const inRoof = inTriangle(px, py, roofApex, roofL, roofR);
          const inDoor = px >= doorX0 && px <= doorX1 && py >= doorY0 && py <= doorY1;
          if ((inBody || inRoof) && !inDoor) whiteHits++;
        }
      }
      const idx = (y * N + x) * 4;
      const alpha = coverage / samples;
      if (alpha === 0) {
        rgba[idx] = 0; rgba[idx + 1] = 0; rgba[idx + 2] = 0; rgba[idx + 3] = 0;
        continue;
      }
      const t = whiteHits / coverage; // proporção branca entre os pontos dentro da forma
      rgba[idx]     = Math.round(ACCENT[0] + (WHITE[0] - ACCENT[0]) * t);
      rgba[idx + 1] = Math.round(ACCENT[1] + (WHITE[1] - ACCENT[1]) * t);
      rgba[idx + 2] = Math.round(ACCENT[2] + (WHITE[2] - ACCENT[2]) * t);
      rgba[idx + 3] = Math.round(alpha * 255);
    }
  }
  return encodePng(N, N, rgba);
}

const out = __dirname;
for (const size of [192, 512]) {
  const circ = drawIcon(size, true);
  fs.writeFileSync(path.join(out, `icon-${size}.png`), circ);
  console.log(`icon-${size}.png circular (${circ.length} bytes)`);
  const sq = drawIcon(size, false);
  fs.writeFileSync(path.join(out, `icon-${size}-maskable.png`), sq);
  console.log(`icon-${size}-maskable.png (${sq.length} bytes)`);
}
console.log("Ícones gerados.");
