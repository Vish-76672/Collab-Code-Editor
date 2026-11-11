'use strict';
// security.js -- dependency-free security helpers (unit-tested in test-security.js)
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

function base32Encode(buf) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}
function base32Decode(text) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0; const out = [];
  for (const c of String(text).toUpperCase().replace(/=+$/g, '').replace(/\s/g, '')) {
    const n = alphabet.indexOf(c); if (n < 0) throw new Error('Invalid base32 secret');
    value = (value << 5) | n; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}
function generateTotpSecret() { return base32Encode(crypto.randomBytes(20)); }
function totpUri(secret, label, issuer) {
  const name = encodeURIComponent(`${issuer}:${label}`);
  return `otpauth://totp/${name}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}
function totpAt(secret, counter) {
  const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', base32Decode(secret)).update(b).digest();
  const offset = h[h.length - 1] & 15;
  const n = (((h[offset] & 127) << 24) | (h[offset + 1] << 16) | (h[offset + 2] << 8) | h[offset + 3]) >>> 0;
  return String(n % 1000000).padStart(6, '0');
}
function verifyTotp(secret, code, now = Date.now()) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return false;
  const step = Math.floor(now / 30000);
  for (let delta = -1; delta <= 1; delta++) {
    const expected = Buffer.from(totpAt(secret, step + delta));
    const actual = Buffer.from(code);
    if (expected.length === actual.length && crypto.timingSafeEqual(expected, actual)) return true;
  }
  return false;
}
function encryptTotpSecret(secret, jwtSecret) {
  const keySource = process.env.MFA_ENCRYPTION_KEY || jwtSecret;
  const key = crypto.createHash('sha256').update(keySource).digest();
  const iv = crypto.randomBytes(12); const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  return [iv.toString('hex'), cipher.getAuthTag().toString('hex'), encrypted.toString('hex')].join('.');
}
function decryptTotpSecret(stored, jwtSecret) {
  const [ivHex, tagHex, dataHex] = String(stored).split('.');
  if (!ivHex || !tagHex || !dataHex) throw new Error('Invalid encrypted MFA secret');
  const keySource = process.env.MFA_ENCRYPTION_KEY || jwtSecret;
  const key = crypto.createHash('sha256').update(keySource).digest();
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]).toString('utf8');
}
function generateRecoveryCodes() {
  return Array.from({ length: 10 }, () => crypto.randomBytes(8).toString('hex').toUpperCase());
}
function hashRecoveryCode(code) {
  return crypto.createHash('sha256').update(String(code).replace(/[-\s]/g, '').toUpperCase()).digest('hex');
}
function validEmail(email) {
  return typeof email === 'string' && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
function newOpaqueToken() { return crypto.randomBytes(32).toString('base64url'); }
function hashOpaqueToken(token) { return crypto.createHash('sha256').update(String(token)).digest('hex'); }

// ---- password hashing: scrypt (built into Node), per-user random salt ----
const SCRYPT = { N: 16384, r: 8, p: 1 };
const KEYLEN = 64;
const MAXMEM = 64 * 1024 * 1024;

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt, KEYLEN, { ...SCRYPT, maxmem: MAXMEM });
  return ['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p, salt.toString('hex'), key.toString('hex')].join('$');
}

async function verifyPassword(password, stored) {
  try {
    const parts = String(stored).split('$');
    if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
    const key = Buffer.from(parts[5], 'hex');
    const derived = await scrypt(password, Buffer.from(parts[4], 'hex'), key.length,
      { N: +parts[1], r: +parts[2], p: +parts[3], maxmem: MAXMEM });
    return key.length === derived.length && crypto.timingSafeEqual(key, derived);
  } catch (e) {
    return false;
  }
}

// A real hash to compare against when the username doesn't exist, so a
// wrong-username login takes as long as a wrong-password one (no user enumeration by timing).
let dummy = null;
async function dummyHash() {
  if (!dummy) dummy = await hashPassword('dummy-password-for-timing');
  return dummy;
}

// ---- validation ----
const USERNAME_RE = /^[A-Za-z0-9_.-]{3,24}$/;
const ROOM_ID_RE = /^[\w-]{1,64}$/;
const INVITE_RE = /^[\w-]{16,64}$/;
const COMMON = new Set(['password', 'password1', '12345678', '123456789', 'qwertyui', 'qwerty123', 'iloveyou', '11111111', 'abc12345', 'letmein1']);

const validUsername = (u) => typeof u === 'string' && USERNAME_RE.test(u);
const validRoomId = (r) => typeof r === 'string' && ROOM_ID_RE.test(r);
const validInvite = (c) => typeof c === 'string' && INVITE_RE.test(c);
const validFileId = (id) => typeof id === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(id);
const validFileName = (name) => typeof name === 'string' && name.length >= 1 && name.length <= 240 &&
  name.split('/').every((part) => part.length >= 1 && part.length <= 100 &&
    part !== '.' && part !== '..' && /^[A-Za-z0-9._-]+$/.test(part) && !part.endsWith('.'));

// returns an error message, or null if the password is acceptable
function passwordProblem(password, username) {
  if (typeof password !== 'string') return 'Password is required.';
  if (password.length < 8) return 'Password must be at least 8 characters.';
  if (password.length > 128) return 'Password must be at most 128 characters.';
  if (COMMON.has(password.toLowerCase())) return 'That password is too common.';
  if (typeof username === 'string' && password.toLowerCase() === username.toLowerCase()) return 'Password must not equal your username.';
  return null;
}

// ---- cookies ----
function parseCookies(header) {
  const out = {};
  if (typeof header !== 'string') return out;
  header.split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i < 0) return;
    const k = part.slice(0, i).trim();
    let v = part.slice(i + 1).trim();
    try { v = decodeURIComponent(v); } catch (e) { return; }
    if (k && !(k in out)) out[k] = v;
  });
  return out;
}

function makeCookie(name, value, { maxAgeSec, secure } = {}) {
  let c = `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Strict`;
  if (typeof maxAgeSec === 'number') c += `; Max-Age=${maxAgeSec}`;
  if (secure) c += '; Secure';
  return c;
}

// ---- origin / client ip ----
function isAllowedOrigin(origin, allowed) {
  if (!origin) return true; // non-browser clients; cookies can't be abused cross-site without a browser
  return allowed.includes(origin);
}

function clientIp(req, trustProxy) {
  if (trustProxy) {
    const xff = req.headers['x-forwarded-for'];
    if (typeof xff === 'string' && xff) return xff.split(',')[0].trim();
  }
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

// ---- fixed-window rate limiter (in memory: resets on restart, per instance) ----
function createLimiter(max, windowMs) {
  const hits = new Map();
  const timer = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset <= now) hits.delete(k);
  }, Math.min(windowMs, 60000));
  if (timer.unref) timer.unref();
  return function hit(key) {
    const now = Date.now();
    let e = hits.get(key);
    if (!e || e.reset <= now) { e = { count: 0, reset: now + windowMs }; hits.set(key, e); }
    e.count++;
    return e.count <= max;
  };
}

module.exports = {
  hashPassword, verifyPassword, dummyHash,
  validUsername, validRoomId, validInvite, validFileId, validFileName, passwordProblem,
  parseCookies, makeCookie, isAllowedOrigin, clientIp, createLimiter,
  generateTotpSecret, totpUri, verifyTotp, encryptTotpSecret, decryptTotpSecret,
  generateRecoveryCodes, hashRecoveryCode, validEmail, newOpaqueToken, hashOpaqueToken,
};
