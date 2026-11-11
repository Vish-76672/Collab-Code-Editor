'use strict';
// access.js -- pure rules for what a ShareDB client may do (unit-tested in test-security.js).
// Used from ShareDB middleware in server.js.

const ALLOWED_COLLECTIONS = new Set(['documents', 'room_meta']);
const ALLOWED_LANGS = ['javascript', 'python', 'java', 'cpp', 'html', 'css', 'json', 'rust', 'plaintext'];
const LANG_SET = new Set(ALLOWED_LANGS);
const ROOM_ID_RE = /^[\w-]{1,64}$/;

const MAX_DOC_CHARS = 2000000;     // ~40k lines
const MAX_OP_CHARS = 1000000;      // largest single paste/insert
const MAX_OP_COMPONENTS = 50000;

// Decide whether one client->server ShareDB message is allowed.
// data: the raw message; custom: per-connection info {user}; getRole(roomId) -> Promise<role|null>.
// Resolves to the list of room ids the message touches, or rejects with an Error.
async function checkMessage(data, custom, getRole) {
  if (!custom || !custom.user) throw new Error('Not authenticated');
  if (!data || typeof data !== 'object') return [];
  const action = data.a;
  if (typeof action === 'string' && action[0] === 'q') throw new Error('Queries are not allowed');

  const touchesDoc = data.c !== undefined || data.d !== undefined || data.b !== undefined;
  if (!touchesDoc) return []; // handshake / ping

  if (!ALLOWED_COLLECTIONS.has(data.c)) throw new Error('Forbidden collection');

  const ids = [];
  if (typeof data.d === 'string') ids.push(data.d);
  if (data.b !== undefined) {
    const list = Array.isArray(data.b) ? data.b : (data.b && typeof data.b === 'object' ? Object.keys(data.b) : null);
    if (!list) throw new Error('Malformed message');
    ids.push(...list);
  }
  if (ids.length === 0) throw new Error('Malformed message');
  if (ids.length > 50) throw new Error('Too many documents in one request');

  for (const id of ids) {
    if (typeof id !== 'string' || !ROOM_ID_RE.test(id)) throw new Error('Invalid room id');
    const role = await getRole(id);
    if (!role) throw new Error('No access to this room');
    if (role === 'viewer' && action === 'op') throw new Error('Read-only room access');
  }
  return ids;
}

function insertedChars(op) {
  let n = 0;
  for (const c of op) if (typeof c === 'string') n += c.length;
  return n;
}

// Validate a submitted op BEFORE it is applied. Throws Error on rejection.
function validateSubmit(collection, op) {
  if (!op || typeof op !== 'object') throw new Error('Malformed op');
  if (op.del) throw new Error('Deleting documents is not allowed');
  if (op.create) throw new Error('Creating documents is not allowed');
  if (collection === 'documents' && Array.isArray(op.op)) {
    if (op.op.length > MAX_OP_COMPONENTS) throw new Error('Edit too complex');
    if (insertedChars(op.op) > MAX_OP_CHARS) throw new Error('Edit too large');
  }
  if (collection === 'room_meta' && Array.isArray(op.op) && op.op.length > 10) {
    throw new Error('Edit too complex');
  }
}

// Validate the document as it WILL be after the op. Throws Error on rejection.
function validateSnapshot(collection, data) {
  if (collection === 'documents') {
    if (typeof data !== 'string') throw new Error('Invalid document');
    if (data.length > MAX_DOC_CHARS) throw new Error('Document too large');
    return;
  }
  if (collection === 'room_meta') {
    const keys = data && typeof data === 'object' ? Object.keys(data) : [];
    if (keys.length !== 1 || !LANG_SET.has(data.language)) throw new Error('Invalid room settings');
    return;
  }
  throw new Error('Forbidden collection');
}

// Token bucket: allows bursts up to `capacity`, refills `refillPerSec` per second.
function createBucket(capacity, refillPerSec) {
  let tokens = capacity;
  let last = Date.now();
  return {
    take(cost) {
      const now = Date.now();
      tokens = Math.min(capacity, tokens + ((now - last) / 1000) * refillPerSec);
      last = now;
      const c = cost === undefined ? 1 : cost;
      if (tokens >= c) { tokens -= c; return true; }
      return false;
    },
  };
}

// Self-test helper: try to fetch a doc over `conn`. Resolves 'allowed' only if the
// fetch completes without error; ANY error, connection 'error' event or silence
// (timeout) counts as 'denied'. Never throws, never leaves an unhandled 'error'.
function probeAccess(conn, collection, id, timeoutMs) {
  return new Promise((resolve) => {
    let done = false;
    let timer = null;
    const finish = (v) => { if (!done) { done = true; clearTimeout(timer); resolve(v); } };
    conn.on('error', () => finish('denied'));
    timer = setTimeout(() => finish('denied'), timeoutMs || 2000);
    try {
      conn.get(collection, id).fetch((err) => finish(err ? 'denied' : 'allowed'));
    } catch (e) { finish('denied'); }
  });
}

module.exports = {
  probeAccess,
  ALLOWED_LANGS, LANG_SET, MAX_DOC_CHARS, MAX_OP_CHARS,
  checkMessage, validateSubmit, validateSnapshot, createBucket,
};
