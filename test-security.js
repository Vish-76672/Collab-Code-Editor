// node test-security.js  -- unit tests for security.js and access.js
const assert = require('assert');
const sec = require('./security');
const acc = require('./access');
let passed = 0;
const t = async (name, fn) => { try { await fn(); passed++; } catch (e) { console.error('FAIL:', name, '\n  ', e.message); process.exitCode = 1; } };
const rejects = async (p, re) => { try { await p; } catch (e) { if (re && !re.test(e.message)) throw new Error('wrong error: ' + e.message); return; } throw new Error('expected rejection'); };

(async () => {
  await t('password hash round-trip', async () => {
    const h = await sec.hashPassword('correct horse battery');
    assert(h.startsWith('scrypt$'));
    assert.strictEqual(await sec.verifyPassword('correct horse battery', h), true);
    assert.strictEqual(await sec.verifyPassword('wrong password', h), false);
  });
  await t('same password hashes differently (salted)', async () => {
    assert.notStrictEqual(await sec.hashPassword('abcdefgh1'), await sec.hashPassword('abcdefgh1'));
  });
  await t('malformed stored hash is rejected, never throws', async () => {
    for (const bad of ['', 'x', 'scrypt$1$2', null, undefined, 'scrypt$a$b$c$zz$yy'])
      assert.strictEqual(await sec.verifyPassword('abc', bad), false);
  });
  await t('dummy hash verifies false for real passwords', async () => {
    assert.strictEqual(await sec.verifyPassword('anything', await sec.dummyHash()), false);
  });

  await t('username validation', () => {
    for (const ok of ['vish', 'a_b.c-d', 'abc', 'A'.repeat(24)]) assert(sec.validUsername(ok), ok);
    for (const bad of ['ab', 'a b', 'x'.repeat(25), '<script>', '', null, 'a/b', "o'brien"]) assert(!sec.validUsername(bad), String(bad));
  });
  await t('password policy', () => {
    assert.strictEqual(sec.passwordProblem('longenough1', 'vish'), null);
    assert(sec.passwordProblem('short', 'vish'));
    assert(sec.passwordProblem('x'.repeat(129), 'vish'));
    assert(sec.passwordProblem('password', 'vish'));
    assert(sec.passwordProblem('VISHVISH1'.toLowerCase(), 'vishvish1'));
    assert(sec.passwordProblem(12345678, 'v'));
  });
  await t('room id / invite validation', () => {
    assert(sec.validRoomId('abc_123-X')); assert(!sec.validRoomId('../etc')); assert(!sec.validRoomId('a b'));
    assert(sec.validInvite('x'.repeat(16))); assert(!sec.validInvite('short'));
  });

  await t('cookie parse/make', () => {
    const c = sec.parseCookies('a=1; collab_session=abc%3D%3D; b=%zz');
    assert.strictEqual(c.a, '1'); assert.strictEqual(c.collab_session, 'abc==');
    assert(!('b' in c));
    const s = sec.makeCookie('s', 'v', { maxAgeSec: 60, secure: true });
    for (const flag of ['HttpOnly', 'SameSite=Strict', 'Secure', 'Max-Age=60', 'Path=/']) assert(s.includes(flag), flag);
    assert(!sec.makeCookie('s', 'v', {}).includes('Secure'));
    assert.deepStrictEqual(sec.parseCookies(undefined), {});
  });
  await t('origin check', () => {
    const allowed = ['http://localhost:8080'];
    assert(sec.isAllowedOrigin(undefined, allowed));
    assert(sec.isAllowedOrigin('http://localhost:8080', allowed));
    assert(!sec.isAllowedOrigin('https://evil.com', allowed));
    assert(!sec.isAllowedOrigin('http://localhost:8080.evil.com', allowed));
  });
  await t('client ip', () => {
    const req = { headers: { 'x-forwarded-for': '1.2.3.4, 5.6.7.8' }, socket: { remoteAddress: '9.9.9.9' } };
    assert.strictEqual(sec.clientIp(req, true), '1.2.3.4');
    assert.strictEqual(sec.clientIp(req, false), '9.9.9.9');
  });
  await t('rate limiter', () => {
    const hit = sec.createLimiter(3, 60000);
    assert(hit('a') && hit('a') && hit('a')); assert(!hit('a')); assert(hit('b'));
  });

  const user = { id: 1, name: 'v' };
  const roles = { roomA: 'owner', roomB: 'editor' };
  const getRole = async (id) => roles[id] || null;
  await t('access: unauthenticated', () => rejects(acc.checkMessage({ a: 's', c: 'documents', d: 'roomA' }, {}, getRole), /authenticated/));
  await t('access: handshake/ping allowed', async () => { assert.deepStrictEqual(await acc.checkMessage({ a: 'hs', id: 'x' }, { user }, getRole), []); });
  await t('access: member can subscribe/op', async () => {
    assert.deepStrictEqual(await acc.checkMessage({ a: 's', c: 'documents', d: 'roomA' }, { user }, getRole), ['roomA']);
    assert.deepStrictEqual(await acc.checkMessage({ a: 'op', c: 'room_meta', d: 'roomB', v: 1, op: [] }, { user }, getRole), ['roomB']);
  });
  await t('access: non-member denied', () => rejects(acc.checkMessage({ a: 's', c: 'documents', d: 'roomZ' }, { user }, getRole), /No access/));
  await t('access: all query actions denied', async () => {
    for (const a of ['qf', 'qs', 'qu', 'q']) await rejects(acc.checkMessage({ a, c: 'documents', id: 1, q: {} }, { user }, getRole), /Queries/);
  });
  await t('access: bad collection denied', () => rejects(acc.checkMessage({ a: 's', c: 'users', d: 'roomA' }, { user }, getRole), /collection/));
  await t('access: bad / missing room id denied', async () => {
    await rejects(acc.checkMessage({ a: 's', c: 'documents', d: '../x' }, { user }, getRole), /Invalid room/);
    await rejects(acc.checkMessage({ a: 's', c: 'documents' }, { user }, getRole), /Malformed/);
    await rejects(acc.checkMessage({ a: 's', c: 'documents', d: 123 }, { user }, getRole), /Malformed|Invalid/);
  });
  await t('access: bulk messages checked per doc (object and array forms)', async () => {
    assert.deepStrictEqual(await acc.checkMessage({ a: 'bs', c: 'documents', b: { roomA: 1, roomB: 2 } }, { user }, getRole), ['roomA', 'roomB']);
    await rejects(acc.checkMessage({ a: 'bs', c: 'documents', b: { roomA: 1, roomZ: 2 } }, { user }, getRole), /No access/);
    await rejects(acc.checkMessage({ a: 'bf', c: 'documents', b: ['roomA', 'roomZ'] }, { user }, getRole), /No access/);
  });
  await t('access: too many docs in one request', () => rejects(acc.checkMessage({ a: 'bf', c: 'documents', b: Array.from({ length: 51 }, (_, i) => 'room' + i) }, { user }, async () => 'editor'), /Too many/));

  await t('validateSubmit', () => {
    acc.validateSubmit('documents', { op: [5, 'hi', { d: 2 }] });
    assert.throws(() => acc.validateSubmit('documents', { del: true }), /Deleting/);
    assert.throws(() => acc.validateSubmit('documents', { create: { type: 'x', data: '' } }), /Creating/);
    assert.throws(() => acc.validateSubmit('documents', { op: ['x'.repeat(acc.MAX_OP_CHARS + 1)] }), /too large/);
    acc.validateSubmit('documents', { op: ['x'.repeat(acc.MAX_OP_CHARS)] });
    assert.throws(() => acc.validateSubmit('documents', { op: new Array(50001).fill(1) }), /complex/);
    assert.throws(() => acc.validateSubmit('documents', null), /Malformed/);
  });
  await t('validateSnapshot', () => {
    acc.validateSnapshot('documents', 'hello');
    assert.throws(() => acc.validateSnapshot('documents', 'x'.repeat(acc.MAX_DOC_CHARS + 1)), /too large/);
    assert.throws(() => acc.validateSnapshot('documents', { a: 1 }), /Invalid document/);
    acc.validateSnapshot('room_meta', { language: 'python' });
    assert.throws(() => acc.validateSnapshot('room_meta', { language: 'cobol' }), /Invalid room/);
    assert.throws(() => acc.validateSnapshot('room_meta', { language: 'python', extra: 1 }), /Invalid room/);
    assert.throws(() => acc.validateSnapshot('room_meta', null), /Invalid room/);
    assert.throws(() => acc.validateSnapshot('other', 'x'), /Forbidden/);
  });
  await t('token bucket', async () => {
    const b = acc.createBucket(3, 1000);
    assert(b.take() && b.take() && b.take()); assert(!b.take());
    await new Promise((r) => setTimeout(r, 15)); assert(b.take());
    const big = acc.createBucket(100, 0); assert(big.take(60)); assert(!big.take(60));
  });

  await t('probeAccess: fetch ok => allowed', async () => {
    const conn = { on() {}, get: () => ({ fetch: (cb) => cb(null) }) };
    assert.strictEqual(await acc.probeAccess(conn, 'documents', 'x', 200), 'allowed');
  });
  await t('probeAccess: fetch error => denied', async () => {
    const conn = { on() {}, get: () => ({ fetch: (cb) => cb(new Error('Unauthorized')) }) };
    assert.strictEqual(await acc.probeAccess(conn, 'documents', 'x', 200), 'denied');
  });
  await t('probeAccess: connection error event => denied (the crash that happened)', async () => {
    let handler;
    const conn = { on: (ev, fn) => { if (ev === 'error') handler = fn; }, get: () => ({ fetch: () => { setTimeout(() => handler(new Error('Unauthorized')), 5); } }) };
    assert.strictEqual(await acc.probeAccess(conn, 'documents', 'x', 1000), 'denied');
  });
  await t('probeAccess: silence => denied after timeout', async () => {
    const conn = { on() {}, get: () => ({ fetch: () => {} }) };
    assert.strictEqual(await acc.probeAccess(conn, 'documents', 'x', 30), 'denied');
  });
  await t('probeAccess: throwing get => denied', async () => {
    const conn = { on() {}, get: () => { throw new Error('boom'); } };
    assert.strictEqual(await acc.probeAccess(conn, 'documents', 'x', 200), 'denied');
  });

  console.log(process.exitCode ? 'SOME TESTS FAILED' : `PASS: all ${passed} security tests`);
})();