'use strict';
// server.js -- Phase 7: real accounts, room access control, limits, hardening.
//
// What protects what:
//   * Accounts: username + password (scrypt hashed). Session = signed JWT in an
//     HttpOnly, SameSite=Strict cookie (never in a URL, never readable by page JS).
//   * Rooms: a user can only touch a room they are a member of. Enforced on the
//     HTTP API, the presence/chat socket AND on every ShareDB message (middleware
//     below), so guessing a room id gets you nothing.
//   * Limits: message-rate and byte-rate per connection, max op size, max doc
//     size, connection caps, login/sign-up/room-creation rate limits, Run quotas.
//   * Hardening: security headers + CSP, Origin checks on POST and WebSocket,
//     required secrets in production, crash handlers.
//   * Startup SELF-TEST: the server refuses to start if the ShareDB access rules
//     don't actually block an unauthorised connection (fail closed).

const express = require('express');
const http = require('http');
const url = require('url');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const WebSocket = require('ws');
const ShareDB = require('sharedb');
const richText = require('ot-text');
const { Duplex } = require('stream');
const Redis = require('ioredis');
const ShareDBPubSub = require('sharedb/lib/pubsub');

const db = require('./db');
const sec = require('./security');
const access = require('./access');
const { runCode } = require('./sandbox');
const enableTextPresence = require('./text-presence');

enableTextPresence(richText.type);
ShareDB.types.register(richText.type);

// ---------------------------------------------------------------- config
const IS_PROD = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT) || 8080;
const HOST = process.env.HOST || '127.0.0.1';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const COOKIE_SECURE = IS_PROD || process.env.COOKIE_SECURE === '1';
const REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6379';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || `http://localhost:${PORT},http://127.0.0.1:${PORT}`)
  .split(',').map((s) => s.trim()).filter(Boolean);

let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  if (IS_PROD) {
    console.error('FATAL: JWT_SECRET must be set (32+ characters) in production. Run: npm run setup');
    process.exit(1);
  }
  JWT_SECRET = crypto.randomBytes(32).toString('hex');
  console.warn('[security] JWT_SECRET not set: using a random one for this run (everyone is logged out on restart). Run `npm run setup` to create a .env.');
}

const COOKIE_NAME = 'collab_session';
const SESSION_SECONDS = 8 * 3600;
const MFA_CHALLENGE_SECONDS = 5 * 60;
const APP_BASE_URL = (process.env.APP_BASE_URL || `http://127.0.0.1:${PORT}`).replace(/\/$/, '');
const usedMfaChallenges = new Map();
const PRESENCE_GRACE_MS = 10000;
const FLUSH_INTERVAL_MS = 5000;
const RUN_COOLDOWN_MS = 3000;
const CHAT_MAX_LEN = 2000;
const CHAT_HISTORY = 100;
const MAX_WS_PAYLOAD = 2 * 1024 * 1024;
const MAX_CONN_PER_USER = 10;
const MAX_CONN_PER_IP = 60;

const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src https://fonts.gstatic.com",
  "img-src 'self' data:",
  "connect-src 'self' ws: wss:",
  "object-src 'none'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
].join('; ');

// ---------------------------------------------------------------- Redis pub/sub adapter
class RedisPubSub extends ShareDBPubSub {
  constructor(options) {
    super(options);
    this.client = new Redis(REDIS_URL);
    this.observer = new Redis(REDIS_URL);
    this.observer.on('message', (channel, message) => {
      let data;
      try { data = JSON.parse(message); } catch (e) { return; } // never crash on a bad message
      this._emit(channel, data);
    });
    this.client.on('error', (err) => console.error('[redis:publish]', err.message));
    this.observer.on('error', (err) => console.error('[redis:subscribe]', err.message));
  }
  _subscribe(channel, callback) { this.observer.subscribe(channel, callback); }
  _unsubscribe(channel, callback) { this.observer.unsubscribe(channel, callback); }
  _publish(channels, data, callback) {
    const message = JSON.stringify(data);
    let pending = channels.length;
    let done = false;
    channels.forEach((channel) => {
      this.client.publish(channel, message, (err) => {
        if (done) return;
        if (err) { done = true; return callback(err); }
        if (--pending === 0) { done = true; callback(); }
      });
    });
  }
}

const backend = new ShareDB({ pubsub: new RedisPubSub(), presence: true });



// ---------------------------------------------------------------- ShareDB access control
function getRoleCached(custom, roomId) {
  const now = Date.now();
  const hit = custom.roles.get(roomId);
  if (hit && hit.exp > now) return Promise.resolve(hit.role);
  return db.getWorkspaceRoomForDoc(roomId).then((workspaceRoomId) => db.getRole(custom.user.id, workspaceRoomId || roomId)).then((role) => {
    if (custom.roles.size > 500) custom.roles.clear();
    custom.roles.set(roomId, { role, exp: now + 30000 }); // membership changes apply within 30s
    return role;
  });
}

backend.use('connect', (ctx, next) => {
  const req = ctx.req || {};
  const c = ctx.agent.custom;
  c.internal = req.internal === true;
  c.user = req.user || null;
  c.ws = req.collabWs || null;
  c.roles = new Map();
  c.bucket = access.createBucket(120, 60); // bursts of 120 messages, 60/sec sustained
  next();
});

// The server's own trusted connection (room setup, flushing, running code).
// Create it after registering connect middleware so its internal flag is initialized.
const internalConn = backend.connect(null, { internal: true });
// ShareDB reports connection-level problems as 'error' events; with no listener Node would crash.
internalConn.on('error', (err) => console.error('[sharedb internal]', err && err.message ? err.message : err));

backend.use('receive', (ctx, next) => {
  const c = ctx.agent.custom;
  if (c.internal) return next();
  if (!c.user) return next('Unauthorized');
  if (!c.bucket.take()) {
    if (c.ws) c.ws.close(4008, 'rate limit');
    return next('Rate limit exceeded');
  }
  const data = ctx.data || {};
  const action = data.a;
  // ShareDB document-presence subscription/request messages carry only a
  // channel name, so they need their own room-membership check.
  if (action === 'ps' || action === 'pr' || action === 'pu') {
    const match = typeof data.ch === 'string' && /^documents\.([\w-]{1,64})$/.exec(data.ch);
    if (!match) return next('Forbidden');
    if (action === 'pu') return next(); // unsubscribe only removes this connection's listener
    return getRoleCached(c, match[1]).then((role) => {
      if (!role) return next('Forbidden');
      return getOrCreateRoom(match[1]).then(() => next(), (err) => next(err.message || 'Forbidden'));
    }, () => next('Forbidden'));
  }
  if (action === 'p') {
    const validDoc = data.c === 'documents' && typeof data.d === 'string'
      && /^[\w-]{1,64}$/.test(data.d) && data.ch === 'documents.' + data.d;
    if (!validDoc) return next('Forbidden');
    // A null value only clears this user's own cursor. Permit the cleanup if a
    // file was just deleted and its database mapping has already disappeared.
    if (data.p === null && typeof data.id === 'string' && data.id.startsWith(String(c.user.id) + ':')) return next();
    return getRoleCached(c, data.d).then((role) => {
      if (!role) return next('Forbidden');
      return getOrCreateRoom(data.d).then(() => next(), (err) => next(err.message || 'Forbidden'));
    }, () => next('Forbidden'));
  }
  access.checkMessage(data, c, (roomId) => getRoleCached(c, roomId))
    .then((ids) => Promise.all(ids.map(getOrCreateRoom))) // the doc always exists before a client touches it
    .then(() => next(), (err) => next(err.message || 'Forbidden'));
});

backend.use('receivePresence', (ctx, next) => {
  const custom = ctx.agent && ctx.agent.custom;
  const user = custom && custom.user;
  const presence = ctx.presence;
  if (custom && custom.internal) return next();
  if (!user || !presence || typeof presence.id !== 'string'
      || !presence.id.startsWith(String(user.id) + ':')) return next('Forbidden');
  if (presence.p === null) return next();
  const value = presence.p;
  if (!value || !Number.isSafeInteger(value.anchor) || !Number.isSafeInteger(value.head)
      || value.anchor < 0 || value.head < 0 || value.anchor > 2000000 || value.head > 2000000) {
    return next('Invalid cursor position');
  }
  presence.p = {
    anchor: value.anchor,
    head: value.head,
    userId: String(user.id),
    name: String(user.name || 'Collaborator').slice(0, 24),
    color: colorForUser(user.id),
  };
  next();
});

backend.use('submit', (ctx, next) => {
  if (ctx.agent.custom.internal) return next();
  const roleCheck = ctx.collection === 'documents' || ctx.collection === 'room_meta'
    ? db.getWorkspaceDocRole(ctx.agent.custom.user.id, ctx.id)
    : getRoleCached(ctx.agent.custom, ctx.id);
  roleCheck.then((role) => {
    if (!role) return next('No access to this room');
    if (role === 'viewer') return next('Read-only room access');
    try { access.validateSubmit(ctx.collection, ctx.op); } catch (e) { return next(e.message); }
    if (ctx.collection === 'documents') {
      lastEditorByDoc.set(ctx.id, { id: ctx.agent.custom.user.id, name: ctx.agent.custom.user.name });
    }
    // Keep a pre-edit checkpoint at the start of an editing burst and at most
    // once a minute. A separate timer saves changed contents every ten seconds.
    if (ctx.collection === 'documents') {
      const now = Date.now();
      const last = versionCaptureAt.get(ctx.id) || 0;
      if (now - last >= 60000) {
        versionCaptureAt.set(ctx.id, now);
        (async () => {
          const roomId = await db.getWorkspaceRoomForDoc(ctx.id);
          const file = roomId && await db.getWorkspaceFileForRoom(roomId, ctx.id);
          if (!file) return;
          const doc = internalConn.get('documents', ctx.id);
          if (typeof doc.data !== 'string') return;
          const meta = internalConn.get('room_meta', ctx.id).data;
          await db.createWorkspaceFileVersion(roomId, ctx.id, doc.data,
            meta && access.LANG_SET.has(meta.language) ? meta.language : file.language,
            ctx.agent.custom.user.id, ctx.agent.custom.user.name, 'before edit', false);
        })().then(() => next(), (err) => {
          versionCaptureAt.delete(ctx.id);
          console.error('[history] automatic checkpoint failed:', err.message);
          next();
        });
        return;
      }
    }
    next();
  }, () => next('No access to this room'));
});

backend.use('commit', (ctx, next) => {
  if (ctx.agent && ctx.agent.custom && ctx.agent.custom.internal) return next();
  try { access.validateSnapshot(ctx.collection, ctx.snapshot && ctx.snapshot.data); } catch (e) { return next(e.message); }
  next();
});

// ---------------------------------------------------------------- rooms + persistence
const dirtyFiles = new Set();
const dirtyVersionFiles = new Set();
const lastEditorByDoc = new Map();
const versionCaptureAt = new Map();
const roomInit = new Map();
const fileInit = new Map();

const subscribeDoc = (doc) => new Promise((res, rej) => doc.subscribe((e) => (e ? rej(e) : res())));
const createDoc = (doc, data, type) => new Promise((res, rej) => doc.create(data, type, (e) => (e ? rej(e) : res())));

function ensureFile(file) {
  if (!fileInit.has(file.docId)) {
    const promise = (async () => {
      const textDoc = internalConn.get('documents', file.docId);
      const metaDoc = internalConn.get('room_meta', file.docId);
      const saved = await db.loadDocument(file.docId);
      await subscribeDoc(textDoc);
      if (textDoc.type === null) await createDoc(textDoc, saved ? saved.content : '', 'text');
      await subscribeDoc(metaDoc);
      if (metaDoc.type === null) {
        const lang = saved && access.LANG_SET.has(saved.language) ? saved.language : file.language;
        await createDoc(metaDoc, { language: access.LANG_SET.has(lang) ? lang : 'javascript' }, 'json0');
      }
      textDoc.on('op', () => { dirtyFiles.add(file.docId); dirtyVersionFiles.add(file.docId); });
      metaDoc.on('op', () => dirtyFiles.add(file.docId));
      return file;
    })().catch((err) => { fileInit.delete(file.docId); throw err; });
    fileInit.set(file.docId, promise);
  }
  return fileInit.get(file.docId);
}

function ensureRoom(roomId) {
  if (!roomInit.has(roomId)) {
    const p = (async () => {
      const saved = await db.loadDocument(roomId);
      await db.ensureDefaultWorkspaceFile(roomId, saved && saved.language);
      const files = await db.listWorkspaceFiles(roomId);
      await Promise.all(files.map(ensureFile));
      return files;
    })().catch((err) => { roomInit.delete(roomId); throw err; });
    roomInit.set(roomId, p);
  }
  return roomInit.get(roomId);
}

async function getOrCreateRoom(docId) {
  const file = await db.getWorkspaceFile(docId);
  return file ? ensureFile(file) : ensureRoom(docId);
}

async function flushDirtyRooms() {
  if (dirtyFiles.size === 0) return;
  const ids = Array.from(dirtyFiles);
  dirtyFiles.clear();
  for (const docId of ids) {
    try {
      const text = internalConn.get('documents', docId).data;
      const meta = internalConn.get('room_meta', docId).data;
      const language = meta && access.LANG_SET.has(meta.language) ? meta.language : 'javascript';
      await db.saveWorkspaceDocument(docId, typeof text === 'string' ? text : '', language);
    } catch (err) {
      console.error(`[flush] failed to save workspace file "${docId}":`, err.message);
      dirtyFiles.add(docId);
    }
  }
}

async function checkpointDirtyFiles() {
  if (!dirtyVersionFiles.size) return;
  const ids = Array.from(dirtyVersionFiles);
  dirtyVersionFiles.clear();
  for (const docId of ids) {
    try {
      const roomId = await db.getWorkspaceRoomForDoc(docId);
      const file = roomId && await db.getWorkspaceFileForRoom(roomId, docId);
      if (!file) continue;
      const content = internalConn.get('documents', docId).data;
      if (typeof content !== 'string') continue;
      const meta = internalConn.get('room_meta', docId).data;
      const actor = lastEditorByDoc.get(docId) || {};
      await db.createWorkspaceFileVersion(roomId, file.id, content,
        meta && access.LANG_SET.has(meta.language) ? meta.language : file.language,
        actor.id, actor.name || 'Automatic save', 'auto-save', false);
    } catch (err) {
      console.error(`[history] automatic checkpoint failed for "${docId}":`, err.message);
      dirtyVersionFiles.add(docId);
    }
  }
}

// ---------------------------------------------------------------- presence + chat helpers
const roomPresence = new Map();
const getRoomPresence = (roomId) => {
  if (!roomPresence.has(roomId)) roomPresence.set(roomId, new Map());
  return roomPresence.get(roomId);
};
const colorForUser = (userId) =>
  `hsl(${parseInt(crypto.createHash('md5').update(String(userId)).digest('hex').slice(0, 6), 16) % 360}, 70%, 60%)`;

function broadcastToRoom(roomId, obj) {
  const payload = JSON.stringify(obj);
  getRoomPresence(roomId).forEach((info) => info.sockets.forEach((s) => {
    if (s.readyState === WebSocket.OPEN) s.send(payload);
  }));
}
function notifyRoomMember(roomId, userId, obj) {
  const member = getRoomPresence(roomId).get(String(userId));
  if (!member) return;
  const payload = JSON.stringify(obj);
  member.sockets.forEach((socket) => {
    if (socket.readyState === WebSocket.OPEN) socket.send(payload);
  });
}
function broadcastPresence(roomId) {
  const users = Array.from(getRoomPresence(roomId).entries()).map(([userId, i]) => ({
    userId, name: i.name, color: i.color, status: i.status,
  }));
  broadcastToRoom(roomId, { type: 'presence', users });
}
function presenceJoin(roomId, userId, name, ws) {
  const presence = getRoomPresence(roomId);
  let info = presence.get(userId);
  if (!info) { info = { name, color: colorForUser(userId), status: 'active', sockets: new Set() }; presence.set(userId, info); }
  info.status = 'active';
  info.sockets.add(ws);
  if (info.pendingRemoval) { clearTimeout(info.pendingRemoval); info.pendingRemoval = null; }
  broadcastPresence(roomId);
}
function presenceLeave(roomId, userId, ws) {
  const presence = getRoomPresence(roomId);
  const info = presence.get(userId);
  if (!info) return;
  info.sockets.delete(ws);
  if (info.sockets.size > 0) return;
  info.status = 'stale'; // tombstone
  broadcastPresence(roomId);
  info.pendingRemoval = setTimeout(() => {
    const cur = presence.get(userId);
    if (cur && cur.sockets.size === 0) {
      presence.delete(userId);
      if (presence.size === 0) roomPresence.delete(roomId);
      else broadcastPresence(roomId);
    }
  }, PRESENCE_GRACE_MS);
}

const chatLimiter = sec.createLimiter(5, 5000);

// ---------------------------------------------------------------- sessions
async function authenticate(req) {
  const token = sec.parseCookies(req.headers.cookie)[COOKIE_NAME];
  if (!token) return null;
  let payload;
  try { payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }); } catch (e) { return null; }
  const row = await db.getUserById(payload.sub);
  if (!row || row.token_version !== payload.ver) return null; // logged out / revoked
  return { id: String(row.id), name: row.username, expMs: payload.exp * 1000 };
}

function issueSession(res, user) {
  const token = jwt.sign({ sub: String(user.id), name: user.username, ver: user.token_version },
    JWT_SECRET, { algorithm: 'HS256', expiresIn: SESSION_SECONDS });
  res.setHeader('Set-Cookie', sec.makeCookie(COOKIE_NAME, token, { maxAgeSec: SESSION_SECONDS, secure: COOKIE_SECURE }));
}

function emailConfigured() {
  return !!(process.env.SMTP_HOST && process.env.SMTP_FROM);
}
async function sendEmail(to, subject, text) {
  if (!emailConfigured()) throw new Error('SMTP_NOT_CONFIGURED');
  const port = Number(process.env.SMTP_PORT || 587);
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port,
    secure: process.env.SMTP_SECURE === '1' || port === 465,
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS || '' } : undefined,
  });
  await transporter.sendMail({ from: process.env.SMTP_FROM, to, subject, text });
}
async function sendAuthLink(user, purpose) {
  if (!user.email || !user.email_verified && purpose === 'password-reset') return false;
  const token = sec.newOpaqueToken();
  const purposeDb = purpose === 'verify-email' ? 'verify-email' : 'password-reset';
  const expires = new Date(Date.now() + (purposeDb === 'verify-email' ? 24 : 1) * 60 * 60 * 1000);
  await db.createAuthToken(user.id, purposeDb, sec.hashOpaqueToken(token), expires);
  const path = purposeDb === 'verify-email' ? 'verify-email' : 'reset-password';
  const link = `${APP_BASE_URL}/#/${path}/${token}`;
  const subject = purposeDb === 'verify-email' ? 'Verify your Collab Editor email' : 'Reset your Collab Editor password';
  const hours = purposeDb === 'verify-email' ? '24 hours' : '1 hour';
  await sendEmail(user.email, subject, `Use this link within ${hours}:\n\n${link}\n\nIf you did not request this, you can ignore this message.`);
  return true;
}

// ---------------------------------------------------------------- connection bookkeeping
const connCounts = new Map();
const userSockets = new Map();
function acquireConn(key, max) {
  const n = connCounts.get(key) || 0;
  if (n >= max) return false;
  connCounts.set(key, n + 1);
  return true;
}
function releaseConn(key) {
  const n = (connCounts.get(key) || 1) - 1;
  if (n <= 0) connCounts.delete(key); else connCounts.set(key, n);
}
function disconnectRoomSockets(userId, roomId, code, reason) {
  const sockets = userSockets.get(String(userId));
  if (!sockets) return;
  for (const ws of Array.from(sockets)) {
    if (ws.collabRoomId && ws.collabRoomId !== roomId) continue;
    try { if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) ws.close(code || 4003, reason || 'room access changed'); } catch (e) { /* socket is already closing */ }
  }
}

// ---------------------------------------------------------------- HTTP
const app = express();
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', CSP);
  if (COOKIE_SECURE) res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
  next();
});
app.use((req, res, next) => {
  const isDraftRecovery = req.method === 'POST' && /^\/api\/rooms\/[^/]+\/files\/recover$/.test(req.path);
  express.json({ limit: isDraftRecovery ? '4mb' : '10kb' })(req, res, next);
});
app.use((req, res, next) => { // CSRF defence in depth (cookie is also SameSite=Strict)
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (!sec.isAllowedOrigin(req.headers.origin, ALLOWED_ORIGINS)) return res.status(403).json({ error: 'Origin not allowed.' });
  next();
});
app.use(express.static('public', { dotfiles: 'ignore' }));

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const requireAuth = wrap(async (req, res, next) => {
  const user = await authenticate(req);
  if (!user) return res.status(401).json({ error: 'Please log in.' });
  req.user = user;
  next();
});

const registerLimiter = sec.createLimiter(5, 3600000);
const loginIpLimiter = sec.createLimiter(30, 900000);
const loginUserLimiter = sec.createLimiter(10, 900000);
const createRoomLimiter = sec.createLimiter(10, 3600000);
const joinLimiter = sec.createLimiter(30, 3600000);

app.post('/api/register', wrap(async (req, res) => {
  if (!registerLimiter(sec.clientIp(req, TRUST_PROXY))) return res.status(429).json({ error: 'Too many sign-ups from this address. Try again later.' });
  const { username, password } = req.body || {};
  const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  if (!sec.validUsername(username)) return res.status(400).json({ error: 'Username must be 3–24 characters: letters, numbers, _ . -' });
  if (!sec.validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  const problem = sec.passwordProblem(password, username);
  if (problem) return res.status(400).json({ error: problem });
  let user;
  try { user = await db.createUser(username, await sec.hashPassword(password), email); }
  catch (e) {
    if (e.message === 'USERNAME_TAKEN') return res.status(409).json({ error: 'That username is taken.' });
    if (e.message === 'EMAIL_TAKEN') return res.status(409).json({ error: 'That email address is already in use.' });
    throw e;
  }
  let emailSent = false;
  try { emailSent = await sendAuthLink(user, 'verify-email'); }
  catch (e) { console.error('[email] verification delivery failed:', e.message); }
  issueSession(res, user);
  res.json({ user: { id: String(user.id), username: user.username }, emailVerificationSent: emailSent });
}));

app.post('/api/login', wrap(async (req, res) => {
  const { username, password } = req.body || {};
  if (!loginIpLimiter(sec.clientIp(req, TRUST_PROXY))) return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  if (typeof username !== 'string' || typeof password !== 'string' || password.length > 128) return res.status(400).json({ error: 'Invalid username or password.' });
  if (!loginUserLimiter(username.toLowerCase().slice(0, 64))) return res.status(429).json({ error: 'Too many attempts for this account. Try again later.' });
  const row = sec.validUsername(username) ? await db.getUserByName(username) : null;
  const ok = await sec.verifyPassword(password, row ? row.password_hash : await sec.dummyHash());
  if (!row || !ok) return res.status(401).json({ error: 'Invalid username or password.' });
  if (row.mfa_enabled) {
    const challenge = jwt.sign({ sub: String(row.id), ver: row.token_version, purpose: 'mfa', jti: crypto.randomUUID() }, JWT_SECRET,
      { algorithm: 'HS256', expiresIn: MFA_CHALLENGE_SECONDS });
    return res.json({ mfaRequired: true, challenge });
  }
  issueSession(res, row);
  res.json({ user: { id: String(row.id), username: row.username } });
}));

app.post('/api/login/mfa', wrap(async (req, res) => {
  const { challenge, code } = req.body || {};
  if (!mfaIpLimiter(sec.clientIp(req, TRUST_PROXY))) return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  let payload;
  try { payload = jwt.verify(challenge, JWT_SECRET, { algorithms: ['HS256'] }); } catch (e) { return res.status(401).json({ error: 'Your sign-in challenge expired. Please log in again.' }); }
  if (payload.purpose !== 'mfa') return res.status(401).json({ error: 'Invalid sign-in challenge.' });
  if (!mfaChallengeLimiter(payload.sub)) return res.status(429).json({ error: 'Too many code attempts. Please sign in again later.' });
  if (usedMfaChallenges.has(payload.jti)) return res.status(401).json({ error: 'This sign-in challenge was already used. Please log in again.' });
  usedMfaChallenges.set(payload.jti, Date.now() + MFA_CHALLENGE_SECONDS * 1000);
  for (const [id, exp] of usedMfaChallenges) if (exp <= Date.now()) usedMfaChallenges.delete(id);
  const row = await db.getUserById(payload.sub);
  if (!row || !row.mfa_enabled || row.token_version !== payload.ver) return res.status(401).json({ error: 'Please log in again.' });
  let accepted = false;
  try { accepted = sec.verifyTotp(sec.decryptTotpSecret(row.mfa_secret, JWT_SECRET), String(code || '')); }
  catch (e) { console.error('[security] could not read encrypted MFA secret'); }
  if (!accepted) accepted = await db.consumeRecoveryCode(row.id, sec.hashRecoveryCode(code || ''));
  if (!accepted) return res.status(401).json({ error: 'Invalid authenticator or recovery code.' });
  issueSession(res, row);
  res.json({ user: { id: String(row.id), username: row.username } });
}));

const forgotLimiter = sec.createLimiter(5, 15 * 60 * 1000);
const mfaIpLimiter = sec.createLimiter(20, 15 * 60 * 1000);
const mfaChallengeLimiter = sec.createLimiter(8, 15 * 60 * 1000);
const accountSecurityLimiter = sec.createLimiter(8, 15 * 60 * 1000);
app.post('/api/password/forgot', wrap(async (req, res) => {
  if (!forgotLimiter(sec.clientIp(req, TRUST_PROXY))) return res.status(429).json({ error: 'Too many requests. Try again later.' });
  if (!emailConfigured()) return res.status(503).json({ error: 'Password recovery email is not configured. Contact the administrator.' });
  const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  if (sec.validEmail(email)) {
    const user = await db.getUserByEmail(email);
    if (user && user.email_verified) {
      try { await sendAuthLink(user, 'password-reset'); }
      catch (e) { console.error('[email] password reset delivery failed:', e.message); }
    }
  }
  res.json({ message: 'If a verified account uses that address, a password reset link will arrive shortly.' });
}));

app.post('/api/password/reset', wrap(async (req, res) => {
  const { token, password } = req.body || {};
  const problem = sec.passwordProblem(password, '');
  if (problem) return res.status(400).json({ error: problem });
  if (typeof token !== 'string' || token.length > 100) return res.status(400).json({ error: 'This reset link is invalid or expired.' });
  const ok = await db.resetPasswordWithToken(sec.hashOpaqueToken(token), await sec.hashPassword(password));
  if (!ok) return res.status(400).json({ error: 'This reset link is invalid or expired.' });
  res.json({ ok: true });
}));

app.post('/api/account/email', requireAuth, wrap(async (req, res) => {
  if (!accountSecurityLimiter(req.user.id)) return res.status(429).json({ error: 'Too many security changes. Try again later.' });
  const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = req.body?.password;
  if (!sec.validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  const user = await db.getUserById(req.user.id);
  if (!user || !(await sec.verifyPassword(password || '', user.password_hash))) return res.status(401).json({ error: 'Enter your current password to change email.' });
  try { await db.setUserEmail(req.user.id, email); }
  catch (e) { if (e.message === 'EMAIL_TAKEN') return res.status(409).json({ error: 'That email address is already in use.' }); throw e; }
  const updated = { ...user, email, email_verified: false };
  let emailSent = false;
  try { emailSent = await sendAuthLink(updated, 'verify-email'); }
  catch (e) { console.error('[email] verification delivery failed:', e.message); }
  res.json({ email, emailVerified: false, emailSent });
}));

app.post('/api/account/email/verify', wrap(async (req, res) => {
  const token = req.body?.token;
  if (typeof token !== 'string' || token.length > 100 || !(await db.consumeEmailToken(sec.hashOpaqueToken(token)))) {
    return res.status(400).json({ error: 'This verification link is invalid or expired.' });
  }
  res.json({ ok: true });
}));

app.get('/api/account/security', requireAuth, wrap(async (req, res) => {
  const user = await db.getUserById(req.user.id);
  res.json({ email: user.email, emailVerified: !!user.email_verified, mfaEnabled: !!user.mfa_enabled });
}));

app.post('/api/account/mfa/setup', requireAuth, wrap(async (req, res) => {
  if (!accountSecurityLimiter(req.user.id)) return res.status(429).json({ error: 'Too many security changes. Try again later.' });
  const user = await db.getUserById(req.user.id);
  if (!user || !(await sec.verifyPassword(req.body?.password || '', user.password_hash))) return res.status(401).json({ error: 'Enter your current password to set up 2FA.' });
  const secret = sec.generateTotpSecret();
  await db.pool.query('UPDATE users SET mfa_pending_secret=$2 WHERE id=$1', [user.id, sec.encryptTotpSecret(secret, JWT_SECRET)]);
  res.json({ secret, uri: sec.totpUri(secret, user.email || user.username, 'Collab Editor') });
}));

app.post('/api/account/mfa/enable', requireAuth, wrap(async (req, res) => {
  if (!accountSecurityLimiter(req.user.id)) return res.status(429).json({ error: 'Too many security changes. Try again later.' });
  const user = await db.getUserById(req.user.id);
  if (!user?.mfa_pending_secret) return res.status(400).json({ error: 'Start 2FA setup first.' });
  const secret = sec.decryptTotpSecret(user.mfa_pending_secret, JWT_SECRET);
  if (!sec.verifyTotp(secret, String(req.body?.code || ''))) return res.status(400).json({ error: 'That code did not match. Try the current code from your authenticator app.' });
  const codes = sec.generateRecoveryCodes();
  await db.pool.query(`UPDATE users SET mfa_secret=$2, mfa_pending_secret=NULL, mfa_enabled=TRUE, mfa_recovery_hashes=$3::jsonb WHERE id=$1`,
    [user.id, sec.encryptTotpSecret(secret, JWT_SECRET), JSON.stringify(codes.map(sec.hashRecoveryCode))]);
  res.json({ recoveryCodes: codes });
}));

app.post('/api/account/mfa/disable', requireAuth, wrap(async (req, res) => {
  if (!accountSecurityLimiter(req.user.id)) return res.status(429).json({ error: 'Too many security changes. Try again later.' });
  const user = await db.getUserById(req.user.id);
  if (!user || !(await sec.verifyPassword(req.body?.password || '', user.password_hash))) return res.status(401).json({ error: 'Enter your current password to disable 2FA.' });
  if (!user.mfa_enabled) return res.json({ ok: true, mfaEnabled: false });
  let accepted = false;
  try { accepted = sec.verifyTotp(sec.decryptTotpSecret(user.mfa_secret, JWT_SECRET), String(req.body?.code || '')); } catch (e) {}
  if (!accepted) accepted = await db.consumeRecoveryCode(user.id, sec.hashRecoveryCode(req.body?.code || ''));
  if (!accepted) return res.status(401).json({ error: 'Invalid authenticator or recovery code.' });
  await db.pool.query(`UPDATE users SET mfa_enabled=FALSE, mfa_secret=NULL, mfa_pending_secret=NULL, mfa_recovery_hashes='[]'::jsonb, token_version=token_version+1 WHERE id=$1`, [user.id]);
  const updated = await db.getUserById(user.id);
  issueSession(res, updated);
  (userSockets.get(req.user.id) || new Set()).forEach((ws) => ws.close(4001, 'security settings changed'));
  res.json({ ok: true, mfaEnabled: false });
}));

app.post('/api/logout', requireAuth, wrap(async (req, res) => {
  await db.bumpTokenVersion(req.user.id); // revokes every session of this user
  (userSockets.get(req.user.id) || new Set()).forEach((ws) => ws.close(4001, 'logged out'));
  res.setHeader('Set-Cookie', sec.makeCookie(COOKIE_NAME, '', { maxAgeSec: 0, secure: COOKIE_SECURE }));
  res.json({ ok: true });
}));

app.get('/api/me', requireAuth, (req, res) => res.json({ user: { id: req.user.id, username: req.user.name } }));

app.get('/api/rooms', requireAuth, wrap(async (req, res) => res.json({ rooms: await db.listRooms(req.user.id) })));

app.get('/api/rooms/:id/members', requireAuth, wrap(async (req, res) => {
  const roomId = req.params.id;
  if (!sec.validRoomId(roomId)) return res.status(400).json({ error: 'Invalid room.' });
  const role = await db.getRole(req.user.id, roomId);
  if (!role) return res.status(403).json({ error: 'You do not have access to this room.' });
  res.json({ members: await db.listRoomMembers(roomId), role });
}));

app.delete('/api/rooms/:id/members/me', requireAuth, wrap(async (req, res) => {
  const roomId = req.params.id;
  if (!sec.validRoomId(roomId)) return res.status(400).json({ error: 'Invalid room.' });
  const role = await db.getRole(req.user.id, roomId);
  if (!role) return res.status(404).json({ error: 'You are not a member of this room.' });
  if (role === 'owner') return res.status(409).json({ error: 'Room ownership transfer and deletion are not available yet, so the owner cannot leave this room.' });
  await db.leaveRoom(roomId, req.user.id);
  disconnectRoomSockets(req.user.id, roomId, 4003, 'left room');
  res.json({ left: true });
}));

app.delete('/api/rooms/:id/members/:userId', requireAuth, wrap(async (req, res) => {
  const roomId = req.params.id;
  if (!sec.validRoomId(roomId)) return res.status(400).json({ error: 'Invalid room.' });
  if (!/^\d{1,10}$/.test(req.params.userId)) return res.status(400).json({ error: 'Invalid member.' });
  if ((await db.getRole(req.user.id, roomId)) !== 'owner') return res.status(403).json({ error: 'Only the room owner can remove members.' });
  const removed = await db.removeRoomMember(roomId, req.params.userId, req.user.id);
  if (!removed) return res.status(404).json({ error: 'That member was not found or cannot be removed.' });
  disconnectRoomSockets(removed.userId, roomId, 4003, 'room access revoked');
  res.json({ removed: true, inviteCode: removed.inviteCode });
}));

app.patch('/api/rooms/:id/members/:userId', requireAuth, wrap(async (req, res) => {
  const roomId = req.params.id;
  if (!sec.validRoomId(roomId) || !/^\d{1,10}$/.test(req.params.userId)) return res.status(400).json({ error: 'Invalid room or member.' });
  if ((await db.getRole(req.user.id, roomId)) !== 'owner') return res.status(403).json({ error: 'Only the room owner can change member roles.' });
  const role = req.body && req.body.role;
  if (!['editor', 'viewer'].includes(role)) return res.status(400).json({ error: 'Choose editor or viewer access.' });
  const updated = await db.updateRoomMemberRole(roomId, req.params.userId, role);
  if (!updated) return res.status(404).json({ error: 'That member was not found or cannot be changed.' });
  notifyRoomMember(roomId, req.params.userId, { type: 'role-changed', role });
  res.json({ updated: true, role });
}));

app.post('/api/rooms', requireAuth, wrap(async (req, res) => {
  if (!createRoomLimiter(req.user.id)) return res.status(429).json({ error: 'You are creating rooms too fast.' });
  try { res.json(await db.createRoom(req.user.id)); }
  catch (e) { if (e.message === 'ROOM_LIMIT') return res.status(409).json({ error: 'Room limit reached.' }); throw e; }
}));

app.post('/api/rooms/join', requireAuth, wrap(async (req, res) => {
  if (!joinLimiter(req.user.id)) return res.status(429).json({ error: 'Too many join attempts.' });
  const code = req.body && req.body.code;
  if (!sec.validInvite(code)) return res.status(400).json({ error: 'That invite link is not valid.' });
  try {
    const roomId = await db.joinByCode(req.user.id, code);
    if (!roomId) return res.status(404).json({ error: 'That invite link is invalid or has been reset.' });
    res.json({ roomId });
  } catch (e) { if (e.message === 'ROOM_FULL') return res.status(409).json({ error: 'That room is full.' }); throw e; }
}));

const FILE_EXTENSIONS = { js: 'javascript', mjs: 'javascript', cjs: 'javascript', ts: 'plaintext', tsx: 'plaintext', jsx: 'javascript', py: 'python', java: 'java', cpp: 'cpp', htm: 'html', html: 'html', css: 'css', json: 'json', rs: 'rust', md: 'plaintext', txt: 'plaintext', yml: 'plaintext', yaml: 'plaintext', toml: 'plaintext', sh: 'plaintext', xml: 'plaintext', sql: 'plaintext', go: 'plaintext', c: 'plaintext', h: 'plaintext', cs: 'plaintext', rb: 'plaintext', php: 'plaintext', vue: 'plaintext', svelte: 'plaintext', gitignore: 'plaintext', dockerfile: 'plaintext' };
const LANGUAGE_EXTENSIONS = { javascript: 'js', python: 'py', java: 'java', cpp: 'cpp', html: 'html', css: 'css', json: 'json', rust: 'rs', plaintext: 'txt' };
const fileWriteLimiter = sec.createLimiter(60, 60 * 60 * 1000);
const workspaceSearchLimiter = sec.createLimiter(90, 60 * 1000);
const gitApiLimiter = sec.createLimiter(20, 60 * 1000);
const gitStatusCache = new Map();
const gitImportPreviews = new Map();
const GIT_IMPORT_FILE_CAP = 24;
const GIT_IMPORT_FILE_BYTES = 500000;
const GIT_IMPORT_TOTAL_BYTES = 8000000;
function parseGithubRepository(input) {
  if (typeof input !== 'string' || input.trim().length > 300) return null;
  const value = input.trim();
  let owner, repo;
  if (/^https:\/\//i.test(value)) {
    let parsed;
    try { parsed = new URL(value); } catch (e) { return null; }
    if (parsed.hostname.toLowerCase() !== 'github.com' || parsed.username || parsed.password || parsed.search || parsed.hash) return null;
    const parts = parsed.pathname.split('/').filter(Boolean);
    if (parts.length !== 2) return null;
    [owner, repo] = parts;
  } else {
    const parts = value.split('/');
    if (parts.length !== 2) return null;
    [owner, repo] = parts;
  }
  repo = repo.replace(/\.git$/i, '');
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(owner)
      || !/^[A-Za-z0-9_.-]{1,100}$/.test(repo) || repo === '.' || repo === '..') return null;
  return { owner, repo };
}
async function githubPublicGet(path) {
  let response;
  try {
    response = await fetch('https://api.github.com' + path, {
      headers: { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'Collab-Editor' },
      signal: AbortSignal.timeout(10000),
    });
  } catch (err) {
    const e = new Error('Could not reach GitHub. Check the server network and try again.');
    e.code = 'GITHUB_UNAVAILABLE'; throw e;
  }
  if (response.status === 404) { const e = new Error('Repository not found. This connection step supports public GitHub repositories.'); e.code = 'GITHUB_NOT_FOUND'; throw e; }
  if (response.status === 403 && response.headers.get('x-ratelimit-remaining') === '0') { const e = new Error('GitHub public API rate limit reached. Wait a little and refresh.'); e.code = 'GITHUB_RATE_LIMIT'; throw e; }
  if (!response.ok) { const e = new Error('GitHub could not load this repository.'); e.code = 'GITHUB_ERROR'; throw e; }
  return response.json();
}
async function getGithubRepositoryStatus(owner, repo) {
  const base = '/repos/' + encodeURIComponent(owner) + '/' + encodeURIComponent(repo);
  const repository = await githubPublicGet(base);
  if (repository.private) { const e = new Error('Private repositories need GitHub account authorization, which is a later integration step.'); e.code = 'GITHUB_PRIVATE'; throw e; }
  const branch = await githubPublicGet(base + '/branches/' + encodeURIComponent(repository.default_branch));
  const commit = await githubPublicGet(base + '/commits/' + encodeURIComponent(branch.commit.sha));
  return {
    connected: true,
    repository: { owner: repository.owner.login, name: repository.name, fullName: repository.full_name, url: 'https://github.com/' + repository.full_name },
    branch: repository.default_branch,
    lastCommit: {
      sha: commit.sha,
      url: 'https://github.com/' + repository.full_name + '/commit/' + commit.sha,
      message: String(commit.commit && commit.commit.message || '').split('\n')[0].slice(0, 160),
      author: String(commit.commit && commit.commit.author && commit.commit.author.name || commit.author && commit.author.login || 'Unknown').slice(0, 80),
      date: commit.commit && commit.commit.author && commit.commit.author.date || null,
      files: Array.isArray(commit.files) ? commit.files.slice(0, 100).map((file) => ({
        path: String(file.filename || '').slice(0, 240),
        status: String(file.status || 'modified').slice(0, 20),
        additions: Number(file.additions) || 0,
        deletions: Number(file.deletions) || 0,
      })) : [],
      filesTruncated: Array.isArray(commit.files) && commit.files.length > 100,
    },
  };
}
function gitApiStatus(err) {
  return err.code === 'GITHUB_RATE_LIMIT' ? 429 : err.code === 'GITHUB_PRIVATE' ? 403 : err.code === 'GITHUB_NOT_FOUND' ? 404 : 502;
}
async function getGitTreeSnapshot(owner, repo, requestedBranch) {
  const base = '/repos/' + encodeURIComponent(owner) + '/' + encodeURIComponent(repo);
  const repository = await githubPublicGet(base);
  if (repository.private) { const e = new Error('Private repositories need GitHub account authorization, which is not available yet.'); e.code = 'GITHUB_PRIVATE'; throw e; }
  const branchName = requestedBranch || repository.default_branch;
  const branch = await githubPublicGet(base + '/branches/' + encodeURIComponent(branchName));
  const commit = await githubPublicGet(base + '/git/commits/' + encodeURIComponent(branch.commit.sha));
  const tree = await githubPublicGet(base + '/git/trees/' + encodeURIComponent(commit.tree.sha) + '?recursive=1');
  if (tree.truncated) { const e = new Error('This repository is too large to preview safely. Nothing was imported.'); e.code = 'GITHUB_TREE_TRUNCATED'; throw e; }
  return { base, branch: branchName, sha: branch.commit.sha, tree: tree.tree || [] };
}
function importLanguage(path) {
  const leaf = path.split('/').pop().toLowerCase();
  const dot = leaf.lastIndexOf('.');
  const ext = dot >= 0 ? leaf.slice(dot + 1) : leaf;
  return FILE_EXTENSIONS[ext] || null;
}
async function fetchGitBlob(base, sha) {
  const blob = await githubPublicGet(base + '/git/blobs/' + encodeURIComponent(sha));
  if (blob.encoding !== 'base64' || typeof blob.content !== 'string') throw new Error('GitHub returned an unreadable file.');
  const content = Buffer.from(blob.content.replace(/\s/g, ''), 'base64').toString('utf8');
  if (content.includes('\0') || Buffer.byteLength(content, 'utf8') > GIT_IMPORT_FILE_BYTES) throw new Error('A repository file exceeded the text file size limit.');
  return content;
}
function normalizedFileName(name, language) {
  const extension = LANGUAGE_EXTENSIONS[language];
  const stem = String(name).replace(/\.[^.]+$/, '') || 'untitled';
  return `${stem}.${extension}`;
}
async function sendWorkspaceFiles(roomId) {
  const files = await db.listWorkspaceFiles(roomId);
  broadcastToRoom(roomId, { type: 'workspace-files', files });
  return files;
}
function deleteShareDbDocument(collection, docId) {
  const doc = internalConn.get(collection, docId);
  if (doc.type === null) return Promise.resolve();
  return new Promise((resolve, reject) => doc.del((err) => err ? reject(err) : resolve()));
}

app.get('/api/rooms/:id/git/status', requireAuth, wrap(async (req, res) => {
  const roomId = req.params.id;
  if (!sec.validRoomId(roomId)) return res.status(400).json({ error: 'Invalid room.' });
  if (!(await db.getRole(req.user.id, roomId))) return res.status(403).json({ error: 'You do not have access to this room.' });
  const configured = await db.getRoomGitRepository(roomId);
  if (!configured) return res.json({ connected: false });
  const cached = gitStatusCache.get(roomId);
  if (cached && cached.expiresAt > Date.now()) return res.json(cached.value);
  if (!gitApiLimiter(req.user.id)) return res.status(429).json({ error: 'Too many GitHub refreshes. Wait a moment and try again.' });
  try {
    const value = await getGithubRepositoryStatus(configured.owner, configured.repo);
    if (gitStatusCache.size > 500) gitStatusCache.clear();
    gitStatusCache.set(roomId, { value, expiresAt: Date.now() + 60000 });
    res.json(value);
  } catch (err) {
    const status = err.code === 'GITHUB_RATE_LIMIT' ? 429 : err.code === 'GITHUB_PRIVATE' ? 403 : err.code === 'GITHUB_NOT_FOUND' ? 404 : 502;
    res.status(status).json({ error: err.message || 'Could not load GitHub status.' });
  }
}));

app.get('/api/rooms/:id/git/branches', requireAuth, wrap(async (req, res) => {
  const roomId = req.params.id;
  if (!sec.validRoomId(roomId)) return res.status(400).json({ error: 'Invalid room.' });
  if (!(await db.getRole(req.user.id, roomId))) return res.status(403).json({ error: 'You do not have access to this room.' });
  const configured = await db.getRoomGitRepository(roomId);
  if (!configured) return res.status(409).json({ error: 'Connect a GitHub repository first.' });
  if (!gitApiLimiter(req.user.id)) return res.status(429).json({ error: 'Too many GitHub requests. Wait a moment and try again.' });
  try {
    const path = '/repos/' + encodeURIComponent(configured.owner) + '/' + encodeURIComponent(configured.repo) + '/branches?per_page=100';
    const branches = await githubPublicGet(path);
    res.json({ branches: branches.map((branch) => String(branch.name || '').slice(0, 255)).filter(Boolean) });
  } catch (err) { res.status(gitApiStatus(err)).json({ error: err.message || 'Could not load repository branches.' }); }
}));

// Compare the shared room files with a public repository branch. This is a
// read-only review step; it never changes the GitHub repository.
app.get('/api/rooms/:id/git/compare', requireAuth, wrap(async (req, res) => {
  const roomId = req.params.id;
  if (!sec.validRoomId(roomId)) return res.status(400).json({ error: 'Invalid room.' });
  if (!(await db.getRole(req.user.id, roomId))) return res.status(403).json({ error: 'You do not have access to this room.' });
  const configured = await db.getRoomGitRepository(roomId);
  if (!configured) return res.status(409).json({ error: 'Connect a GitHub repository first.' });
  const requestedBranch = typeof req.query.branch === 'string' ? req.query.branch : '';
  if (requestedBranch.length > 255 || /[\u0000-\u001f]/.test(requestedBranch)) return res.status(400).json({ error: 'Invalid branch name.' });
  if (!gitApiLimiter(req.user.id)) return res.status(429).json({ error: 'Too many GitHub requests. Wait a moment and try again.' });
  try {
    const snapshot = await getGitTreeSnapshot(configured.owner, configured.repo, requestedBranch || undefined);
    const remotePaths = new Set(snapshot.tree.filter((entry) => entry.type === 'blob' && (entry.mode === '100644' || entry.mode === '100755') && sec.validFileName(entry.path) && importLanguage(entry.path) &&
      !entry.path.split('/').some((part) => /^\.env(?:\.|$)/i.test(part))).map((entry) => entry.path));
    const remoteEntries = new Map(snapshot.tree.filter((entry) => entry.type === 'blob').map((entry) => [entry.path, entry]));
    const workspaceFiles = await db.listWorkspaceFiles(roomId);
    const workspacePaths = new Set(workspaceFiles.map((file) => file.name));
    const files = [];
    let comparedFiles = 0;
    let comparedBytes = 0;
    for (const file of workspaceFiles) {
      const inRemote = remotePaths.has(file.name);
      let status = 'added';
      if (inRemote) {
        await ensureFile(file);
        const doc = internalConn.get('documents', file.docId);
        const current = typeof doc.data === 'string' ? doc.data : '';
        const entry = remoteEntries.get(file.name);
        if (!entry || !Number.isSafeInteger(entry.size) || entry.size > GIT_IMPORT_FILE_BYTES || comparedFiles >= GIT_IMPORT_FILE_CAP || comparedBytes + entry.size > GIT_IMPORT_TOTAL_BYTES) status = 'unavailable';
        else {
          const remote = await fetchGitBlob(snapshot.base, entry.sha);
          comparedFiles++;
          comparedBytes += entry.size;
          status = current === remote ? 'unchanged' : 'modified';
        }
      }
      files.push({ path: file.name, status });
    }
    for (const path of remotePaths) if (!workspacePaths.has(path)) files.push({ path, status: 'missing' });
    files.sort((a, b) => a.path.localeCompare(b.path));
    res.json({ repository: configured.owner + '/' + configured.repo, branch: snapshot.branch, sha: snapshot.sha,
      counts: files.reduce((acc, file) => { acc[file.status] = (acc[file.status] || 0) + 1; return acc; }, {}), files });
  } catch (err) {
    const status = err.code === 'GITHUB_TREE_TRUNCATED' ? 413 : gitApiStatus(err);
    res.status(status).json({ error: err.message || 'Could not compare workspace files.' });
  }
}));

app.get('/api/rooms/:id/git/compare-file', requireAuth, wrap(async (req, res) => {
  const roomId = req.params.id;
  if (!sec.validRoomId(roomId)) return res.status(400).json({ error: 'Invalid room.' });
  if (!(await db.getRole(req.user.id, roomId))) return res.status(403).json({ error: 'You do not have access to this room.' });
  const configured = await db.getRoomGitRepository(roomId);
  if (!configured) return res.status(409).json({ error: 'Connect a GitHub repository first.' });
  const path = typeof req.query.path === 'string' ? req.query.path : '';
  const requestedBranch = typeof req.query.branch === 'string' ? req.query.branch : '';
  if (!sec.validFileName(path) || !importLanguage(path) || path.length > 240 || path.split('/').some((part) => /^\.env(?:\.|$)/i.test(part)) ||
      requestedBranch.length > 255 || /[\u0000-\u001f]/.test(requestedBranch)) return res.status(400).json({ error: 'Invalid file or branch.' });
  if (!gitApiLimiter(req.user.id)) return res.status(429).json({ error: 'Too many GitHub requests. Wait a moment and try again.' });
  try {
    const snapshot = await getGitTreeSnapshot(configured.owner, configured.repo, requestedBranch || undefined);
    const file = (await db.listWorkspaceFiles(roomId)).find((item) => item.name === path);
    const entry = snapshot.tree.find((item) => item.type === 'blob' && (item.mode === '100644' || item.mode === '100755') && item.path === path);
    let workspace = null;
    if (file) {
      await ensureFile(file);
      const data = internalConn.get('documents', file.docId).data;
      workspace = typeof data === 'string' ? data : '';
    }
    let remote = null;
    if (entry) {
      if (!Number.isSafeInteger(entry.size) || entry.size > GIT_IMPORT_FILE_BYTES) return res.status(413).json({ error: 'This file is too large to compare in the browser.' });
      remote = await fetchGitBlob(snapshot.base, entry.sha);
    }
    res.json({ path, branch: snapshot.branch, workspace, remote });
  } catch (err) {
    const status = err.code === 'GITHUB_TREE_TRUNCATED' ? 413 : gitApiStatus(err);
    res.status(status).json({ error: err.message || 'Could not load file comparison.' });
  }
}));

app.get('/api/rooms/:id/git/import-preview', requireAuth, wrap(async (req, res) => {
  const roomId = req.params.id;
  if (!sec.validRoomId(roomId)) return res.status(400).json({ error: 'Invalid room.' });
  if (!(await db.getRole(req.user.id, roomId))) return res.status(403).json({ error: 'You do not have access to this room.' });
  const configured = await db.getRoomGitRepository(roomId);
  if (!configured) return res.status(409).json({ error: 'Connect a GitHub repository first.' });
  if (!gitApiLimiter(req.user.id)) return res.status(429).json({ error: 'Too many GitHub requests. Wait a moment and try again.' });
  try {
    const requestedBranch = typeof req.query.branch === 'string' ? req.query.branch : '';
    if (requestedBranch.length > 255 || /[\u0000-\u001f]/.test(requestedBranch)) return res.status(400).json({ error: 'Invalid branch name.' });
    const snapshot = await getGitTreeSnapshot(configured.owner, configured.repo, requestedBranch || undefined);
    const existing = await db.listWorkspaceFiles(roomId);
    const names = new Set(existing.map((file) => file.name.toLocaleLowerCase('en-US')));
    const eligible = snapshot.tree.filter((entry) => entry.type === 'blob' && (entry.mode === '100644' || entry.mode === '100755') &&
      sec.validFileName(entry.path) && !entry.path.split('/').some((part) => /^\.env(?:\.|$)/i.test(part)) && importLanguage(entry.path) && Number.isSafeInteger(entry.size) && entry.size <= GIT_IMPORT_FILE_BYTES);
    const availableSlots = Math.max(0, 100 - existing.length);
    const nonColliding = eligible.filter((entry) => !names.has(entry.path.toLocaleLowerCase('en-US')));
    const selected = nonColliding.slice(0, Math.min(GIT_IMPORT_FILE_CAP, availableSlots));
    const loaded = new Array(selected.length);
    let cursor = 0; let reservedBytes = 0;
    async function worker() {
      while (cursor < selected.length) {
        const index = cursor++;
        const entry = selected[index];
        if (reservedBytes + entry.size > GIT_IMPORT_TOTAL_BYTES) continue;
        reservedBytes += entry.size;
        const content = await fetchGitBlob(snapshot.base, entry.sha);
        const bytes = Buffer.byteLength(content, 'utf8');
        if (bytes > GIT_IMPORT_TOTAL_BYTES) continue;
        loaded[index] = { name: entry.path, language: importLanguage(entry.path), content, size: bytes };
      }
    }
    await Promise.all(Array.from({ length: 4 }, worker));
    const files = loaded.filter(Boolean);
    const previewId = crypto.randomBytes(24).toString('base64url');
    const now = Date.now();
    for (const [key, value] of gitImportPreviews) if (value.expiresAt <= now) gitImportPreviews.delete(key);
    if (gitImportPreviews.size >= 200) gitImportPreviews.delete(gitImportPreviews.keys().next().value);
    gitImportPreviews.set(previewId, { roomId, userId: String(req.user.id), branch: snapshot.branch, sha: snapshot.sha, files, expiresAt: now + 10 * 60 * 1000 });
    const supportedBlobs = snapshot.tree.filter((entry) => entry.type === 'blob' && (entry.mode === '100644' || entry.mode === '100755') && sec.validFileName(entry.path) && !entry.path.split('/').some((part) => /^\.env(?:\.|$)/i.test(part)) && importLanguage(entry.path));
    const skipped = supportedBlobs.length - files.length;
    res.json({ previewId, branch: snapshot.branch, sha: snapshot.sha, files: files.map(({ name, language, size }) => ({ name, language, size })),
      totalEligible: eligible.length, existingCount: existing.length, availableSlots,
      skippedCount: Math.max(0, skipped), tooManyFiles: eligible.length > GIT_IMPORT_FILE_CAP,
      truncatedBySize: supportedBlobs.some((entry) => Number(entry.size) > GIT_IMPORT_FILE_BYTES) });
  } catch (err) {
    const status = err.code === 'GITHUB_TREE_TRUNCATED' ? 413 : gitApiStatus(err);
    res.status(status).json({ error: err.message || 'Could not preview repository files.' });
  }
}));

app.post('/api/rooms/:id/git/import', requireAuth, wrap(async (req, res) => {
  const roomId = req.params.id;
  if (!sec.validRoomId(roomId)) return res.status(400).json({ error: 'Invalid room.' });
  if ((await db.getRole(req.user.id, roomId)) !== 'owner') return res.status(403).json({ error: 'Only the room owner can import repository files.' });
  const previewId = req.body && req.body.previewId;
  const preview = typeof previewId === 'string' ? gitImportPreviews.get(previewId) : null;
  if (!preview || preview.expiresAt <= Date.now() || preview.roomId !== roomId || preview.userId !== String(req.user.id)) {
    if (previewId) gitImportPreviews.delete(previewId);
    return res.status(410).json({ error: 'That preview expired. Preview the repository again.' });
  }
  const selectedPaths = req.body && req.body.selectedPaths;
  if (!Array.isArray(selectedPaths) || selectedPaths.length < 1 || selectedPaths.length > GIT_IMPORT_FILE_CAP ||
      selectedPaths.some((path) => typeof path !== 'string') || new Set(selectedPaths).size !== selectedPaths.length) {
    return res.status(400).json({ error: 'Select at least one file from the preview.' });
  }
  const selected = selectedPaths.map((path) => preview.files.find((file) => file.name === path));
  if (selected.some((file) => !file)) return res.status(400).json({ error: 'The selection does not match this preview.' });
  gitImportPreviews.delete(previewId);
  const added = await db.importWorkspaceFiles(roomId, selected);
  await Promise.all(added.map(ensureFile));
  const files = await sendWorkspaceFiles(roomId);
  res.json({ importedCount: added.length, skippedCount: selected.length - added.length, files });
}));

app.post('/api/rooms/:id/git/repository', requireAuth, wrap(async (req, res) => {
  const roomId = req.params.id;
  if (!sec.validRoomId(roomId)) return res.status(400).json({ error: 'Invalid room.' });
  if ((await db.getRole(req.user.id, roomId)) !== 'owner') return res.status(403).json({ error: 'Only the room owner can connect a GitHub repository.' });
  if (!gitApiLimiter(req.user.id)) return res.status(429).json({ error: 'Too many GitHub requests. Wait a moment and try again.' });
  const repository = parseGithubRepository(req.body && req.body.repository);
  if (!repository) return res.status(400).json({ error: 'Enter a GitHub URL like https://github.com/owner/repository.' });
  try {
    const details = await githubPublicGet('/repos/' + encodeURIComponent(repository.owner) + '/' + encodeURIComponent(repository.repo));
    if (details.private) return res.status(403).json({ error: 'Private repositories need GitHub account authorization, which is a later integration step.' });
    await db.setRoomGitRepository(roomId, details.owner.login, details.name, req.user.id);
    gitStatusCache.delete(roomId);
    res.json({ connected: true, repository: { owner: details.owner.login, name: details.name, fullName: details.full_name, url: 'https://github.com/' + details.full_name } });
  } catch (err) {
    const status = err.code === 'GITHUB_RATE_LIMIT' ? 429 : err.code === 'GITHUB_NOT_FOUND' ? 404 : 502;
    res.status(status).json({ error: err.message || 'Could not connect that GitHub repository.' });
  }
}));

app.delete('/api/rooms/:id/git/repository', requireAuth, wrap(async (req, res) => {
  const roomId = req.params.id;
  if (!sec.validRoomId(roomId)) return res.status(400).json({ error: 'Invalid room.' });
  if ((await db.getRole(req.user.id, roomId)) !== 'owner') return res.status(403).json({ error: 'Only the room owner can disconnect a GitHub repository.' });
  await db.deleteRoomGitRepository(roomId);
  gitStatusCache.delete(roomId);
  res.json({ connected: false });
}));

app.get('/api/rooms/:id/files', requireAuth, wrap(async (req, res) => {
  const roomId = req.params.id;
  if (!sec.validRoomId(roomId)) return res.status(400).json({ error: 'Invalid room.' });
  if (!(await db.getRole(req.user.id, roomId))) return res.status(403).json({ error: 'You do not have access to this room.' });
  await ensureRoom(roomId);
  const files = await db.listWorkspaceFiles(roomId);
  await Promise.all(files.map(ensureFile));
  res.json({ files });
}));

app.get('/api/rooms/:id/files/:fileId/history', requireAuth, wrap(async (req, res) => {
  const { id: roomId, fileId } = req.params;
  if (!sec.validRoomId(roomId) || !sec.validFileId(fileId)) return res.status(400).json({ error: 'Invalid room or file.' });
  if (!(await db.getRole(req.user.id, roomId))) return res.status(403).json({ error: 'You do not have access to this room.' });
  if (!(await db.getWorkspaceFileForRoom(roomId, fileId))) return res.status(404).json({ error: 'File not found.' });
  res.json({ versions: await db.listWorkspaceFileVersions(roomId, fileId, 200) });
}));

app.get('/api/rooms/:id/files/:fileId/history/:versionId', requireAuth, wrap(async (req, res) => {
  const { id: roomId, fileId, versionId } = req.params;
  if (!sec.validRoomId(roomId) || !sec.validFileId(fileId) || !/^\d{1,18}$/.test(versionId)) return res.status(400).json({ error: 'Invalid room, file, or version.' });
  if (!(await db.getRole(req.user.id, roomId))) return res.status(403).json({ error: 'You do not have access to this room.' });
  const version = await db.getWorkspaceFileVersion(roomId, fileId, versionId);
  if (!version) return res.status(404).json({ error: 'That saved version was not found.' });
  res.json({ version });
}));

app.post('/api/rooms/:id/files/:fileId/history', requireAuth, wrap(async (req, res) => {
  const { id: roomId, fileId } = req.params;
  if (!sec.validRoomId(roomId) || !sec.validFileId(fileId)) return res.status(400).json({ error: 'Invalid room or file.' });
  const role = await db.getRole(req.user.id, roomId);
  if (!role) return res.status(403).json({ error: 'You do not have access to this room.' });
  if (role === 'viewer') return res.status(403).json({ error: 'This room is read-only for your account.' });
  if (!fileWriteLimiter(req.user.id)) return res.status(429).json({ error: 'Too many file changes. Try again later.' });
  const file = await db.getWorkspaceFileForRoom(roomId, fileId);
  if (!file) return res.status(404).json({ error: 'File not found.' });
  await ensureFile(file);
  await flushDirtyRooms();
  const content = internalConn.get('documents', file.docId).data;
  const meta = internalConn.get('room_meta', file.docId).data;
  const version = await db.createWorkspaceFileVersion(roomId, fileId, typeof content === 'string' ? content : '',
    meta && access.LANG_SET.has(meta.language) ? meta.language : file.language,
    req.user.id, req.user.name, 'checkpoint', true);
  res.status(201).json({ version });
}));

app.post('/api/rooms/:id/files/:fileId/history/:versionId/restore', requireAuth, wrap(async (req, res) => {
  const { id: roomId, fileId, versionId } = req.params;
  if (!sec.validRoomId(roomId) || !sec.validFileId(fileId) || !/^\d{1,18}$/.test(versionId)) return res.status(400).json({ error: 'Invalid room, file, or version.' });
  const role = await db.getRole(req.user.id, roomId);
  if (!role) return res.status(403).json({ error: 'You do not have access to this room.' });
  if (role === 'viewer') return res.status(403).json({ error: 'This room is read-only for your account.' });
  if (!fileWriteLimiter(req.user.id)) return res.status(429).json({ error: 'Too many file changes. Try again later.' });
  const file = await db.getWorkspaceFileForRoom(roomId, fileId);
  if (!file) return res.status(404).json({ error: 'File not found.' });
  const target = await db.getWorkspaceFileVersion(roomId, fileId, versionId);
  if (!target) return res.status(404).json({ error: 'That saved version was not found.' });
  await ensureFile(file);
  const doc = internalConn.get('documents', file.docId);
  const current = typeof doc.data === 'string' ? doc.data : '';
  const meta = internalConn.get('room_meta', file.docId).data;
  const language = meta && access.LANG_SET.has(meta.language) ? meta.language : file.language;
  await db.createWorkspaceFileVersion(roomId, fileId, current, language, req.user.id, req.user.name, 'before restore', true);
  if (current !== target.content) {
    const op = [];
    if (current.length) op.push({ d: current.length });
    if (target.content.length) op.push(target.content);
    await new Promise((resolve, reject) => doc.submitOp(op, (err) => err ? reject(err) : resolve()));
  }
  await db.saveWorkspaceDocument(file.docId, target.content, target.language);
  const restored = await db.createWorkspaceFileVersion(roomId, fileId, target.content, target.language,
    req.user.id, req.user.name, 'restore', true);
  res.json({ restored, content: target.content, language: target.language });
}));

app.get('/api/rooms/:id/search', requireAuth, wrap(async (req, res) => {
  const roomId = req.params.id;
  const query = typeof req.query.q === 'string' ? req.query.q.trim() : '';
  if (!sec.validRoomId(roomId)) return res.status(400).json({ error: 'Invalid room.' });
  if (!(await db.getRole(req.user.id, roomId))) return res.status(403).json({ error: 'You do not have access to this room.' });
  if (!workspaceSearchLimiter(req.user.id)) return res.status(429).json({ error: 'Too many searches. Wait a moment and try again.' });
  if (!query || query.length > 120) return res.status(400).json({ error: 'Search text must be between 1 and 120 characters.' });
  await ensureRoom(roomId);
  const files = await db.listWorkspaceFiles(roomId);
  const needle = query.toLocaleLowerCase();
  const matches = [];
  let scannedChars = 0;
  for (const file of files) {
    const source = internalConn.get('documents', file.docId).data;
    if (typeof source !== 'string') continue;
    scannedChars += source.length;
    if (scannedChars > 20000000) return res.status(413).json({ error: 'This workspace is too large to search at once. Narrow the workspace and try again.' });
    const lines = source.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].toLocaleLowerCase().includes(needle)) {
        matches.push({ fileId: file.id, docId: file.docId, name: file.name, line: i + 1, text: lines[i].slice(0, 300) });
        if (matches.length >= 100) return res.json({ matches, truncated: true });
      }
    }
  }
  res.json({ matches, truncated: false });
}));

app.post('/api/rooms/:id/files', requireAuth, wrap(async (req, res) => {
  const roomId = req.params.id;
  if (!sec.validRoomId(roomId)) return res.status(400).json({ error: 'Invalid room.' });
  const role = await db.getRole(req.user.id, roomId);
  if (!role) return res.status(403).json({ error: 'You do not have access to this room.' });
  if (role === 'viewer') return res.status(403).json({ error: 'This room is read-only for your account.' });
  if (!fileWriteLimiter(req.user.id)) return res.status(429).json({ error: 'Too many file changes. Try again later.' });
  const rawName = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  if (!sec.validFileName(rawName)) return res.status(400).json({ error: 'Use a file name or relative path with letters, numbers, dots, dashes, underscores, and folders separated by /.' });
  const leaf = rawName.split('/').pop();
  const suffix = leaf.includes('.') ? leaf.split('.').pop().toLowerCase() : 'js';
  const language = FILE_EXTENSIONS[suffix];
  if (!language) return res.status(400).json({ error: 'Supported file types: js, py, java, cpp, html, css, json, and rs.' });
  const name = leaf.includes('.') ? rawName : `${rawName}.${LANGUAGE_EXTENSIONS[language]}`;
  try {
    await ensureRoom(roomId);
    const file = await db.createWorkspaceFile(roomId, name, language);
    await ensureFile(file);
    const files = await sendWorkspaceFiles(roomId);
    res.status(201).json({ file, files });
  } catch (e) {
    if (e.message === 'FILE_NAME_TAKEN') return res.status(409).json({ error: 'A file with that name already exists in this room.' });
    if (e.message === 'FILE_LIMIT') return res.status(409).json({ error: 'This room has reached its file limit.' });
    throw e;
  }
}));

app.post('/api/rooms/:id/files/recover', requireAuth, wrap(async (req, res) => {
  const roomId = req.params.id;
  if (!sec.validRoomId(roomId)) return res.status(400).json({ error: 'Invalid room.' });
  const role = await db.getRole(req.user.id, roomId);
  if (!role) return res.status(403).json({ error: 'You do not have access to this room.' });
  if (role === 'viewer') return res.status(403).json({ error: 'This room is read-only for your account. Download the local draft instead.' });
  if (!fileWriteLimiter(req.user.id)) return res.status(429).json({ error: 'Too many file changes. Try again later.' });
  const sourceName = typeof req.body?.sourceName === 'string' ? req.body.sourceName : '';
  const content = req.body?.content;
  const language = req.body?.language;
  if (!sec.validFileName(sourceName) || !access.LANG_SET.has(language) || typeof content !== 'string' ||
      content.length > access.MAX_OP_CHARS || Buffer.byteLength(content, 'utf8') > 1000000) {
    return res.status(400).json({ error: 'The local recovery draft is invalid or too large to restore.' });
  }
  const leaf = sourceName.split('/').pop();
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
  const name = 'recovered/' + stamp + '-' + leaf;
  try {
    await ensureRoom(roomId);
    const file = await db.createWorkspaceFile(roomId, name, language);
    await ensureFile(file);
    if (content.length) {
      const doc = internalConn.get('documents', file.docId);
      await new Promise((resolve, reject) => doc.submitOp([content], (err) => err ? reject(err) : resolve()));
    }
    const files = await sendWorkspaceFiles(roomId);
    res.status(201).json({ file, files });
  } catch (err) {
    if (err.message === 'FILE_NAME_TAKEN') return res.status(409).json({ error: 'A recovery file with that name already exists. Try again.' });
    if (err.message === 'FILE_LIMIT') return res.status(409).json({ error: 'This room has reached its file limit.' });
    throw err;
  }
}));

app.patch('/api/rooms/:id/files/:fileId', requireAuth, wrap(async (req, res) => {
  const roomId = req.params.id, fileId = req.params.fileId;
  if (!sec.validRoomId(roomId) || !sec.validFileId(fileId)) return res.status(400).json({ error: 'Invalid room or file.' });
  const role = await db.getRole(req.user.id, roomId);
  if (!role) return res.status(403).json({ error: 'You do not have access to this room.' });
  if (role === 'viewer') return res.status(403).json({ error: 'This room is read-only for your account.' });
  if (!fileWriteLimiter(req.user.id)) return res.status(429).json({ error: 'Too many file changes. Try again later.' });
  const current = await db.getWorkspaceFileForRoom(roomId, fileId);
  if (!current) return res.status(404).json({ error: 'File not found.' });
  const language = req.body?.language;
  const rawName = typeof req.body?.name === 'string' ? req.body.name.trim() : current.name;
  if (!access.LANG_SET.has(language) || !sec.validFileName(rawName)) return res.status(400).json({ error: 'Invalid file name or language.' });
  const name = normalizedFileName(rawName, language);
  try {
    const file = await db.updateWorkspaceFile(roomId, fileId, name, language);
    if (!file) return res.status(404).json({ error: 'File not found.' });
    await getOrCreateRoom(file.docId);
    const metaDoc = internalConn.get('room_meta', file.docId);
    const oldLanguage = metaDoc.data && metaDoc.data.language || 'javascript';
    if (oldLanguage !== language) {
      await new Promise((resolve, reject) => metaDoc.submitOp([{ p: ['language'], od: oldLanguage, oi: language }], (err) => err ? reject(err) : resolve()));
    }
    const files = await sendWorkspaceFiles(roomId);
    res.json({ file, files });
  } catch (e) {
    if (e.message === 'FILE_NAME_TAKEN') return res.status(409).json({ error: 'A file with that name already exists in this room.' });
    throw e;
  }
}));

app.delete('/api/rooms/:id/files/:fileId', requireAuth, wrap(async (req, res) => {
  const roomId = req.params.id, fileId = req.params.fileId;
  if (!sec.validRoomId(roomId) || !sec.validFileId(fileId)) return res.status(400).json({ error: 'Invalid room or file.' });
  const role = await db.getRole(req.user.id, roomId);
  if (!role) return res.status(403).json({ error: 'You do not have access to this room.' });
  if (role === 'viewer') return res.status(403).json({ error: 'This room is read-only for your account.' });
  if (!fileWriteLimiter(req.user.id)) return res.status(429).json({ error: 'Too many file changes. Try again later.' });
  const file = await db.getWorkspaceFileForRoom(roomId, fileId);
  if (!file) return res.status(404).json({ error: 'File not found.' });
  let files;
  try {
    await db.deleteWorkspaceFile(roomId, fileId);
    dirtyFiles.delete(file.docId);
    dirtyVersionFiles.delete(file.docId);
    lastEditorByDoc.delete(file.docId);
    fileInit.delete(file.docId);
    versionCaptureAt.delete(file.docId);
    await deleteShareDbDocument('documents', file.docId).catch((e) => console.error('[workspace] ShareDB document cleanup failed:', e.message));
    await deleteShareDbDocument('room_meta', file.docId).catch((e) => console.error('[workspace] ShareDB metadata cleanup failed:', e.message));
    dirtyFiles.delete(file.docId);
    files = await sendWorkspaceFiles(roomId);
  } catch (e) {
    if (e.message === 'LAST_FILE') return res.status(409).json({ error: 'A room must keep at least one file.' });
    throw e;
  }
  res.json({ files });
}));

app.get('/api/rooms/:id', requireAuth, wrap(async (req, res) => {
  if (!sec.validRoomId(req.params.id)) return res.status(400).json({ error: 'Invalid room.' });
  const role = await db.getRole(req.user.id, req.params.id);
  if (!role) return res.status(403).json({ error: 'You do not have access to this room.' });
  const out = { id: req.params.id, role };
  if (role === 'owner') out.inviteCode = await db.getInviteForOwner(req.params.id, req.user.id);
  res.json(out);
}));

app.post('/api/rooms/:id/invite/regenerate', requireAuth, wrap(async (req, res) => {
  if (!sec.validRoomId(req.params.id)) return res.status(400).json({ error: 'Invalid room.' });
  const code = await db.regenerateInvite(req.params.id, req.user.id);
  if (!code) return res.status(403).json({ error: 'Only the room owner can do that.' });
  res.json({ inviteCode: code });
}));

const lastRunAt = new Map();
const runningRooms = new Set();
app.post('/api/run', requireAuth, wrap(async (req, res) => {
  const roomId = req.body && req.body.roomId;
  const fileId = req.body && req.body.fileId;
  if (!sec.validRoomId(roomId)) return res.status(400).json({ error: 'Invalid room id.' });
  const role = await db.getRole(req.user.id, roomId);
  if (!role) return res.status(403).json({ error: 'You do not have access to this room.' });
  if (role === 'viewer') return res.status(403).json({ error: 'Viewers cannot run room code.' });
  const file = sec.validFileId(fileId) ? await db.getWorkspaceFileForRoom(roomId, fileId) : null;
  if (!file) return res.status(404).json({ error: 'The selected file no longer exists.' });
  const now = Date.now();
  if (now - (lastRunAt.get(req.user.id) || 0) < RUN_COOLDOWN_MS) return res.status(429).json({ error: 'Slow down — wait a few seconds between runs.' });
  if (runningRooms.has(roomId)) return res.status(409).json({ error: 'A run is already in progress in this room.' });
  lastRunAt.set(req.user.id, now);
  runningRooms.add(roomId);
  try {
    await getOrCreateRoom(file.docId);
    const code = internalConn.get('documents', file.docId).data || '';
    const meta = internalConn.get('room_meta', file.docId).data;
    const language = meta && access.LANG_SET.has(meta.language) ? meta.language : 'javascript';
    broadcastToRoom(roomId, { type: 'run-start', by: req.user.name, language, fileName: file.name });
    const result = await runCode(language, code);
    broadcastToRoom(roomId, { type: 'run-result', by: req.user.name, language, fileName: file.name, ...result });
    res.json({ ok: true });
  } catch (err) {
    console.error('[run] failed:', err);
    broadcastToRoom(roomId, { type: 'run-result', by: req.user.name, error: 'Internal error while running code.' });
    res.status(500).json({ error: 'Internal error.' });
  } finally {
    runningRooms.delete(roomId);
  }
}));

app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  if (res.headersSent) return next(err);
  const status = err.status && err.status < 500 ? err.status : 500;
  if (status === 500) console.error('[http] error:', err.message);
  res.status(status).json({ error: status === 500 ? 'Internal error.' : 'Bad request.' });
});

const server = http.createServer(app);

// ---------------------------------------------------------------- WebSockets
const shareDbWss = new WebSocket.Server({ noServer: true, maxPayload: MAX_WS_PAYLOAD });
const presenceWss = new WebSocket.Server({ noServer: true, maxPayload: 16 * 1024 });

function rejectUpgrade(socket, code, text) {
  try { socket.write(`HTTP/1.1 ${code} ${text}\r\nConnection: close\r\n\r\n`); } catch (e) { /* ignore */ }
  socket.destroy();
}

server.on('upgrade', async (req, socket, head) => {
  socket.on('error', () => {});
  let pathname;
  try { pathname = url.parse(req.url).pathname; } catch (e) { return socket.destroy(); }
  const target = pathname === '/sharedb' ? shareDbWss : pathname === '/presence' ? presenceWss : null;
  if (!target) return rejectUpgrade(socket, 404, 'Not Found');
  if (!sec.isAllowedOrigin(req.headers.origin, ALLOWED_ORIGINS)) return rejectUpgrade(socket, 403, 'Forbidden');

  const ipKey = 'ip:' + sec.clientIp(req, TRUST_PROXY);
  if (!acquireConn(ipKey, MAX_CONN_PER_IP)) return rejectUpgrade(socket, 429, 'Too Many Requests');
  let released = false;
  const release = () => { if (!released) { released = true; releaseConn(ipKey); } };
  socket.on('close', release);

  let user = null;
  try { user = await authenticate(req); } catch (e) { return socket.destroy(); }
  if (socket.destroyed) return;
  try {
    target.handleUpgrade(req, socket, head, (ws) => { req.user = user; target.emit('connection', ws, req); });
  } catch (e) { socket.destroy(); }
});

// Common per-socket checks: logged in, connection cap, close when the session expires.
function adopt(ws, req) {
  const user = req.user;
  if (!user) { ws.close(4001, 'login required'); return false; }
  const key = 'u:' + user.id;
  if (!acquireConn(key, MAX_CONN_PER_USER)) { ws.close(4009, 'too many connections'); return false; }
  if (!userSockets.has(user.id)) userSockets.set(user.id, new Set());
  userSockets.get(user.id).add(ws);
  const timer = setTimeout(() => ws.close(4001, 'session expired'), Math.max(0, user.expMs - Date.now()));
  ws.on('close', () => {
    clearTimeout(timer);
    releaseConn(key);
    const set = userSockets.get(user.id);
    if (set) { set.delete(ws); if (!set.size) userSockets.delete(user.id); }
  });
  return true;
}

shareDbWss.on('connection', (ws, req) => {
  if (!adopt(ws, req)) return;
  const shareQuery = url.parse(req.url, true).query;
  ws.collabRoomId = sec.validRoomId(shareQuery.room) ? shareQuery.room : null;
  const bytes = access.createBucket(8 * 1024 * 1024, 2 * 1024 * 1024); // 2 MB/s sustained
  const stream = new Duplex({
    objectMode: true,
    write(chunk, enc, cb) { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(chunk)); cb(); },
    read() {},
  });
  ws.on('message', (m) => {
    if (!bytes.take(m.length)) { ws.close(4008, 'rate limit'); return; }
    try { stream.push(JSON.parse(m)); } catch (e) { /* ignore malformed frame */ }
  });
  ws.on('close', () => stream.push(null));
  ws.on('error', () => stream.push(null));
  req.collabWs = ws;
  backend.listen(stream, req);
});

presenceWss.on('connection', async (ws, req) => {
  if (!adopt(ws, req)) return;
  const user = req.user;
  const { query } = url.parse(req.url, true);
  const roomId = query.room;
  if (!sec.validRoomId(roomId)) return ws.close(4003, 'invalid room');
  ws.collabRoomId = roomId;

  let joined = false;
  const leave = () => { if (joined) { joined = false; presenceLeave(roomId, user.id, ws); } };
  ws.on('close', leave);
  ws.on('error', leave);

  let role = null;
  try { role = await db.getRole(user.id, roomId); } catch (e) { return ws.close(1011, 'server error'); }
  if (!role) return ws.close(4003, 'no access to this room');

  // chat: validate, rate-limit, save, fan out
  ws.on('message', async (raw) => {
    if (!joined) return;
    let msg;
    try { msg = JSON.parse(raw); } catch (e) { return; }
    if (!msg || typeof msg !== 'object') return;
    const reject = (error) => ws.readyState === WebSocket.OPEN && ws.send(JSON.stringify({ type: 'chat-error', error }));
    let currentRole;
    try { currentRole = await db.getRole(user.id, roomId); }
    catch (err) { return reject('Could not verify your room access. Try again.'); }
    if (!currentRole) return ws.close(4003, 'no access to this room');
    if (currentRole === 'viewer' && (msg.type === 'chat' || msg.type === 'chat-delete')) return reject('This room is read-only for your account.');
    if (msg.type === 'chat-delete') {
      const messageId = Number(msg.id);
      if (!Number.isSafeInteger(messageId) || messageId < 1) return reject('That message could not be deleted.');
      try {
        const deleted = await db.deleteChatMessage(roomId, messageId, user.id);
        if (!deleted) return reject('You can delete only your own messages.');
        broadcastToRoom(roomId, { type: 'chat-deleted', id: String(messageId), userId: String(user.id) });
      } catch (err) { console.error('[chat] failed to delete message:', err.message); reject('Could not delete the message.'); }
      return;
    }
    if (msg.type !== 'chat') return;
    const text = typeof msg.text === 'string' ? msg.text.trim() : '';
    if (!text) return;
    if (text.length > CHAT_MAX_LEN) return reject(`Message too long (max ${CHAT_MAX_LEN} characters).`);
    if (!chatLimiter(user.id)) return reject('Slow down — too many messages.');
    let saved = null;
    try { saved = await db.saveMessage(roomId, user.id, user.name, text); }
    catch (err) { console.error('[chat] failed to save message:', err.message); }
    broadcastToRoom(roomId, {
      type: 'chat', id: saved ? String(saved.id) : null, userId: user.id, name: user.name,
      color: colorForUser(user.id), text, ts: saved ? saved.created_at : new Date().toISOString(),
    });
  });

  try { await getOrCreateRoom(roomId); } catch (err) { console.error(`[room] failed to initialize "${roomId}":`, err.message); }
  if (ws.readyState !== WebSocket.OPEN) return;
  presenceJoin(roomId, user.id, user.name, ws);
  joined = true;

  try {
    await ensureRoom(roomId);
    const files = await db.listWorkspaceFiles(roomId);
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'workspace-files', files }));
  } catch (err) { console.error(`[workspace] failed to list files for "${roomId}":`, err.message); }

  try {
    const rows = await db.loadRecentMessages(roomId, CHAT_HISTORY);
    const messages = rows.map((m) => ({ ...m, id: String(m.id), color: colorForUser(m.userId) }));
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'chat-history', messages }));
  } catch (err) { console.error('[chat] failed to load history:', err.message); }
});

// ---------------------------------------------------------------- startup self-test
// Proves the access rules really work in THIS ShareDB version. If they don't,
// refuse to start rather than run with a silent hole.
async function selfTest() {
  const closeQuietly = (c) => { try { c.close(); } catch (e) { /* ignore */ } };

  // 1. a logged-in user with NO membership must be denied
  const outsider = backend.connect(null, { user: { id: '-1', name: 'selftest' } });
  const r1 = await access.probeAccess(outsider, 'documents', 'selftest-no-access');
  closeQuietly(outsider);
  if (r1 !== 'denied') throw new Error('SELF-TEST FAILED: a user with no membership could read a room. Refusing to start.');

  // 2. the server's own connection must still work
  const r2 = await access.probeAccess(internalConn, 'documents', 'selftest-internal', 5000);
  if (r2 !== 'allowed') throw new Error('SELF-TEST FAILED: the internal connection is blocked (ShareDB did not pass the "internal" flag through). Refusing to start.');

  // 3. a connection with no user at all must be denied
  const anon = backend.connect(null, {});
  const r3 = await access.probeAccess(anon, 'documents', 'selftest-anon');
  closeQuietly(anon);
  if (r3 !== 'denied') throw new Error('SELF-TEST FAILED: an unauthenticated connection could read a room. Refusing to start.');
}

// ---------------------------------------------------------------- lifecycle
const INSTANCE = process.env.INSTANCE_NAME || `pid-${process.pid}`;

async function start() {
  await db.initSchema();
  await selfTest();
  setInterval(() => flushDirtyRooms().catch((e) => console.error('[flush] unexpected error:', e)), FLUSH_INTERVAL_MS);
  setInterval(() => checkpointDirtyFiles().catch((e) => console.error('[history] unexpected error:', e)), 10000);
  server.listen(PORT, HOST, () => {
    console.log(`[${INSTANCE}] Collab editor on http://${HOST}:${PORT}  (secure cookies: ${COOKIE_SECURE ? 'yes' : 'no'}, trust proxy: ${TRUST_PROXY ? 'yes' : 'no'})`);
    console.log(`[${INSTANCE}] access-control self-test passed | allowed origins: ${ALLOWED_ORIGINS.join(', ')}`);
  });
}

let shuttingDown = false;
async function shutdown(code) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`\n[${INSTANCE}] Shutting down, flushing pending changes...`);
  try { await Promise.race([flushDirtyRooms(), new Promise((r) => setTimeout(r, 3000))]); } catch (e) { /* ignore */ }
  process.exit(code);
}
process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));
process.on('uncaughtException', (err) => { console.error('[fatal] uncaughtException:', err); shutdown(1); });
process.on('unhandledRejection', (err) => { console.error('[fatal] unhandledRejection:', err); shutdown(1); });

start().catch((err) => { console.error('Failed to start server:', err.message || err); process.exit(1); });
