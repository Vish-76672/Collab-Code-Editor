'use strict';
// db.js -- Postgres: documents (write-behind snapshots), chat, users, rooms, members.
const crypto = require('crypto');
const { Pool } = require('pg');

const IS_PROD = process.env.NODE_ENV === 'production';
if (IS_PROD && !process.env.DATABASE_URL) {
  console.error('FATAL: DATABASE_URL must be set in production.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgres://collab:collab@127.0.0.1:5432/collab_editor',
  max: 10,
  idleTimeoutMillis: 30000,
});
// An error on an idle pooled connection would otherwise crash the whole process.
pool.on('error', (err) => console.error('[postgres] idle client error:', err.message));

const MAX_MEMBERS_PER_ROOM = 50;
const MAX_ROOMS_PER_USER = 20;
const MAX_FILES_PER_ROOM = 100;

async function initSchema() {
  await pool.query(`CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    content TEXT NOT NULL DEFAULT '',
    language TEXT NOT NULL DEFAULT 'javascript',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS chat_messages (
    id BIGSERIAL PRIMARY KEY,
    room_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    text TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
  await pool.query('CREATE INDEX IF NOT EXISTS chat_room_idx ON chat_messages (room_id, id)');

  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    token_version INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_pending_secret TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_recovery_hashes JSONB NOT NULL DEFAULT '[]'::jsonb`);
  await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower ON users (lower(username))');
  await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower ON users (lower(email)) WHERE email IS NOT NULL');
  await pool.query(`CREATE TABLE IF NOT EXISTS auth_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK (purpose IN ('verify-email', 'password-reset')),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ)`);
  await pool.query('CREATE INDEX IF NOT EXISTS auth_tokens_user_purpose ON auth_tokens (user_id, purpose)');
  await pool.query(`CREATE TABLE IF NOT EXISTS rooms (
    id TEXT PRIMARY KEY,
    owner_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    invite_code TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS room_members (
    room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'editor',
    joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (room_id, user_id))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS workspace_files (
    id TEXT PRIMARY KEY,
    doc_id TEXT UNIQUE NOT NULL,
    room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    language TEXT NOT NULL DEFAULT 'javascript',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
  await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS workspace_files_name_lower ON workspace_files (room_id, lower(name))');
  await pool.query('CREATE INDEX IF NOT EXISTS workspace_files_room_idx ON workspace_files (room_id, created_at, id)');
  await pool.query(`CREATE TABLE IF NOT EXISTS workspace_file_versions (
    id BIGSERIAL PRIMARY KEY,
    room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    file_id TEXT NOT NULL,
    content TEXT NOT NULL,
    language TEXT NOT NULL DEFAULT 'javascript',
    user_id INT REFERENCES users(id) ON DELETE SET NULL,
    author TEXT NOT NULL DEFAULT 'Collaborator',
    kind TEXT NOT NULL DEFAULT 'checkpoint',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
  await pool.query('CREATE INDEX IF NOT EXISTS workspace_file_versions_file_idx ON workspace_file_versions (room_id,file_id,id DESC)');
  await pool.query(`CREATE TABLE IF NOT EXISTS room_git_repositories (
    room_id TEXT PRIMARY KEY REFERENCES rooms(id) ON DELETE CASCADE,
    owner TEXT NOT NULL,
    repo TEXT NOT NULL,
    connected_by INT REFERENCES users(id) ON DELETE SET NULL,
    connected_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
}

// ---- documents / chat ----
async function loadDocument(id) {
  const r = await pool.query('SELECT content, language FROM documents WHERE id = $1', [id]);
  return r.rows[0] || null;
}
async function saveDocument(id, content, language) {
  await pool.query(
    `INSERT INTO documents (id, content, language, updated_at) VALUES ($1,$2,$3,now())
     ON CONFLICT (id) DO UPDATE SET content=$2, language=$3, updated_at=now()`,
    [id, content, language]);
}
const extensionForLanguage = {
  javascript: 'js', python: 'py', java: 'java', cpp: 'cpp', html: 'html', css: 'css', json: 'json', rust: 'rs',
};
async function ensureDefaultWorkspaceFile(roomId, language) {
  const lang = extensionForLanguage[language] ? language : 'javascript';
  const name = `main.${extensionForLanguage[lang]}`;
  await pool.query(`INSERT INTO workspace_files (id,doc_id,room_id,name,language)
    SELECT $1,$1,$1,$2,$3 WHERE NOT EXISTS (SELECT 1 FROM workspace_files WHERE room_id=$1)
    ON CONFLICT DO NOTHING`, [roomId, name, lang]);
  const r = await pool.query('SELECT id,doc_id AS "docId",room_id AS "roomId",name,language,created_at AS "createdAt" FROM workspace_files WHERE room_id=$1 ORDER BY created_at,id LIMIT 1', [roomId]);
  return r.rows[0] || null;
}
async function listWorkspaceFiles(roomId) {
  const r = await pool.query('SELECT id,doc_id AS "docId",room_id AS "roomId",name,language,created_at AS "createdAt" FROM workspace_files WHERE room_id=$1 ORDER BY created_at,id', [roomId]);
  return r.rows;
}
async function getWorkspaceFile(fileId) {
  const r = await pool.query('SELECT id,doc_id AS "docId",room_id AS "roomId",name,language,created_at AS "createdAt" FROM workspace_files WHERE id=$1', [fileId]);
  return r.rows[0] || null;
}
async function getWorkspaceFileForRoom(roomId, fileId) {
  const r = await pool.query('SELECT id,doc_id AS "docId",room_id AS "roomId",name,language,created_at AS "createdAt" FROM workspace_files WHERE room_id=$1 AND id=$2', [roomId, fileId]);
  return r.rows[0] || null;
}
async function getWorkspaceRoomForDoc(docId) {
  const r = await pool.query('SELECT room_id FROM workspace_files WHERE doc_id=$1', [docId]);
  return r.rows[0] ? r.rows[0].room_id : null;
}
async function getWorkspaceDocRole(userId, docId) {
  const r = await pool.query(`SELECT m.role FROM workspace_files f
    JOIN room_members m ON m.room_id=f.room_id
    WHERE f.doc_id=$1 AND m.user_id=$2`, [docId, toInt(userId)]);
  return r.rows[0] ? r.rows[0].role : null;
}
async function createWorkspaceFile(roomId, name, language) {
  const id = 'f_' + crypto.randomBytes(18).toString('base64url');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT id FROM rooms WHERE id=$1 FOR UPDATE', [roomId]);
    const count = await client.query('SELECT count(*)::int AS n FROM workspace_files WHERE room_id=$1', [roomId]);
    if (count.rows[0].n >= MAX_FILES_PER_ROOM) { await client.query('ROLLBACK'); throw new Error('FILE_LIMIT'); }
    const r = await client.query(`INSERT INTO workspace_files (id,doc_id,room_id,name,language)
      VALUES ($1,$1,$2,$3,$4) RETURNING id,doc_id AS "docId",room_id AS "roomId",name,language,created_at AS "createdAt"`,
      [id, roomId, name, language]);
    await client.query('COMMIT');
    return r.rows[0];
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    if (err.code === '23505' && err.constraint === 'workspace_files_name_lower') throw new Error('FILE_NAME_TAKEN');
    throw err;
  } finally { client.release(); }
}
async function importWorkspaceFiles(roomId, files) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT id FROM rooms WHERE id=$1 FOR UPDATE', [roomId]);
    const existing = await client.query('SELECT lower(name) AS name FROM workspace_files WHERE room_id=$1', [roomId]);
    const names = new Set(existing.rows.map((row) => row.name));
    const count = await client.query('SELECT count(*)::int AS n FROM workspace_files WHERE room_id=$1', [roomId]);
    let slots = Math.max(0, MAX_FILES_PER_ROOM - count.rows[0].n);
    const added = [];
    for (const file of files) {
      const key = file.name.toLocaleLowerCase('en-US');
      if (!slots || names.has(key)) continue;
      const id = 'f_' + crypto.randomBytes(18).toString('base64url');
      const result = await client.query(`INSERT INTO workspace_files (id,doc_id,room_id,name,language)
        VALUES ($1,$1,$2,$3,$4) RETURNING id,doc_id AS "docId",room_id AS "roomId",name,language,created_at AS "createdAt"`,
        [id, roomId, file.name, file.language]);
      await client.query('INSERT INTO documents (id,content,language) VALUES ($1,$2,$3) ON CONFLICT (id) DO NOTHING',
        [id, file.content, file.language]);
      names.add(key); slots--;
      added.push(result.rows[0]);
    }
    await client.query('COMMIT');
    return added;
  } catch (err) { await client.query('ROLLBACK').catch(() => {}); throw err; }
  finally { client.release(); }
}
async function updateWorkspaceFile(roomId, fileId, name, language) {
  try {
    const r = await pool.query(`UPDATE workspace_files SET name=$3,language=$4 WHERE room_id=$1 AND id=$2
      RETURNING id,doc_id AS "docId",room_id AS "roomId",name,language,created_at AS "createdAt"`, [roomId, fileId, name, language]);
    return r.rows[0] || null;
  } catch (err) {
    if (err.code === '23505' && err.constraint === 'workspace_files_name_lower') throw new Error('FILE_NAME_TAKEN');
    throw err;
  }
}
async function deleteWorkspaceFile(roomId, fileId) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const count = await client.query('SELECT count(*)::int AS n FROM workspace_files WHERE room_id=$1', [roomId]);
    if (count.rows[0].n <= 1) { await client.query('ROLLBACK'); throw new Error('LAST_FILE'); }
    const r = await client.query('DELETE FROM workspace_files WHERE room_id=$1 AND id=$2 RETURNING doc_id', [roomId, fileId]);
    if (!r.rowCount) { await client.query('ROLLBACK'); return null; }
    await client.query('DELETE FROM workspace_file_versions WHERE room_id=$1 AND file_id=$2', [roomId, fileId]);
    await client.query('DELETE FROM documents WHERE id=$1', [r.rows[0].doc_id]);
    await client.query('COMMIT');
    return r.rows[0].doc_id;
  } catch (err) { await client.query('ROLLBACK').catch(() => {}); throw err; }
  finally { client.release(); }
}
async function getRoomGitRepository(roomId) {
  const r = await pool.query(`SELECT owner,repo,connected_by AS "connectedBy",connected_at AS "connectedAt"
    FROM room_git_repositories WHERE room_id=$1`, [roomId]);
  return r.rows[0] || null;
}
async function setRoomGitRepository(roomId, owner, repo, userId) {
  const r = await pool.query(`INSERT INTO room_git_repositories (room_id,owner,repo,connected_by)
    VALUES ($1,$2,$3,$4) ON CONFLICT (room_id) DO UPDATE SET owner=$2,repo=$3,connected_by=$4,connected_at=now()
    RETURNING owner,repo,connected_by AS "connectedBy",connected_at AS "connectedAt"`, [roomId, owner, repo, toInt(userId)]);
  return r.rows[0];
}
async function deleteRoomGitRepository(roomId) {
  await pool.query('DELETE FROM room_git_repositories WHERE room_id=$1', [roomId]);
}
async function saveWorkspaceDocument(docId, content, language) {
  await saveDocument(docId, content, language);
  await pool.query('UPDATE workspace_files SET language=$2 WHERE doc_id=$1', [docId, language]);
}
async function createWorkspaceFileVersion(roomId, fileId, content, language, userId, author, kind, force) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const file = await client.query('SELECT id FROM workspace_files WHERE room_id=$1 AND id=$2 FOR UPDATE', [roomId, fileId]);
    if (!file.rowCount) { await client.query('ROLLBACK'); return null; }
    const latest = await client.query('SELECT content FROM workspace_file_versions WHERE room_id=$1 AND file_id=$2 ORDER BY id DESC LIMIT 1', [roomId, fileId]);
    if (!force && latest.rows[0] && latest.rows[0].content === content) { await client.query('COMMIT'); return null; }
    const saved = await client.query(`INSERT INTO workspace_file_versions
      (room_id,file_id,content,language,user_id,author,kind) VALUES ($1,$2,$3,$4,$5,$6,$7)
      RETURNING id,author,kind,created_at AS "createdAt"`,
      [roomId, fileId, content, language, toInt(userId), String(author || 'Collaborator').slice(0, 24), kind || 'checkpoint']);
    await client.query(`DELETE FROM workspace_file_versions WHERE id IN (
      SELECT id FROM (
        SELECT id, row_number() OVER (ORDER BY id DESC) AS position,
          sum(octet_length(content)) OVER (ORDER BY id DESC) AS saved_bytes
        FROM workspace_file_versions WHERE room_id=$1 AND file_id=$2
      ) ranked WHERE position > 200 OR saved_bytes > 41943040
    )`, [roomId, fileId]);
    await client.query(`DELETE FROM workspace_file_versions WHERE id IN (
      SELECT id FROM (
        SELECT id, row_number() OVER (ORDER BY id DESC) AS position,
          sum(octet_length(content)) OVER (ORDER BY id DESC) AS saved_bytes
        FROM workspace_file_versions WHERE room_id=$1
      ) ranked WHERE position > 2000 OR saved_bytes > 209715200
    )`, [roomId]);
    await client.query('COMMIT');
    return saved.rows[0];
  } catch (err) { await client.query('ROLLBACK').catch(() => {}); throw err; }
  finally { client.release(); }
}
async function listWorkspaceFileVersions(roomId, fileId, limit) {
  const r = await pool.query(`SELECT id,author,kind,created_at AS "createdAt",length(content) AS "contentLength"
    FROM workspace_file_versions WHERE room_id=$1 AND file_id=$2 ORDER BY id DESC LIMIT $3`, [roomId, fileId, limit || 200]);
  return r.rows;
}
async function getWorkspaceFileVersion(roomId, fileId, versionId) {
  const r = await pool.query(`SELECT id,content,language,author,kind,created_at AS "createdAt"
    FROM workspace_file_versions WHERE room_id=$1 AND file_id=$2 AND id=$3`, [roomId, fileId, versionId]);
  return r.rows[0] || null;
}
async function saveMessage(roomId, userId, name, text) {
  const r = await pool.query(
    'INSERT INTO chat_messages (room_id, user_id, name, text) VALUES ($1,$2,$3,$4) RETURNING id, created_at',
    [roomId, String(userId), name, text]);
  return r.rows[0];
}
async function deleteChatMessage(roomId, messageId, userId) {
  const r = await pool.query('DELETE FROM chat_messages WHERE room_id=$1 AND id=$2 AND user_id=$3 RETURNING id',
    [roomId, messageId, String(userId)]);
  return r.rowCount > 0;
}
async function loadRecentMessages(roomId, limit) {
  const r = await pool.query(
    `SELECT id, user_id AS "userId", name, text, created_at AS ts
       FROM chat_messages WHERE room_id=$1 ORDER BY id DESC LIMIT $2`, [roomId, limit]);
  return r.rows.reverse();
}

// ---- users ----
const toInt = (v) => { const n = Number(v); return Number.isInteger(n) ? n : null; };

async function createUser(username, passwordHash, email) {
  try {
    const r = await pool.query(
      'INSERT INTO users (username, password_hash, email) VALUES ($1,$2,$3) RETURNING id, username, token_version, email, email_verified',
      [username, passwordHash, email]);
    return r.rows[0];
  } catch (err) {
    if (err.code === '23505' && err.constraint === 'users_username_lower') throw new Error('USERNAME_TAKEN');
    if (err.code === '23505' && err.constraint === 'users_email_lower') throw new Error('EMAIL_TAKEN');
    throw err;
  }
}
async function getUserByName(username) {
  const r = await pool.query('SELECT * FROM users WHERE lower(username)=lower($1)', [username]);
  return r.rows[0] || null;
}
async function getUserById(id) {
  const n = toInt(id);
  if (n === null) return null;
  const r = await pool.query('SELECT * FROM users WHERE id=$1', [n]);
  return r.rows[0] || null;
}
async function bumpTokenVersion(id) {
  await pool.query('UPDATE users SET token_version = token_version + 1 WHERE id=$1', [toInt(id)]);
}
async function getUserByEmail(email) {
  const r = await pool.query('SELECT * FROM users WHERE lower(email)=lower($1)', [email]);
  return r.rows[0] || null;
}
async function setUserEmail(id, email) {
  try {
    const r = await pool.query('UPDATE users SET email=$2, email_verified=FALSE WHERE id=$1 RETURNING id', [toInt(id), email]);
    return !!r.rowCount;
  } catch (err) {
    if (err.code === '23505' && err.constraint === 'users_email_lower') throw new Error('EMAIL_TAKEN');
    throw err;
  }
}
async function createAuthToken(userId, purpose, tokenHash, expiresAt) {
  await pool.query('DELETE FROM auth_tokens WHERE user_id=$1 AND purpose=$2 AND consumed_at IS NULL', [toInt(userId), purpose]);
  await pool.query('INSERT INTO auth_tokens (token_hash,user_id,purpose,expires_at) VALUES ($1,$2,$3,$4)',
    [tokenHash, toInt(userId), purpose, expiresAt]);
}
async function consumeEmailToken(tokenHash) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const r = await client.query(`UPDATE auth_tokens SET consumed_at=now()
      WHERE token_hash=$1 AND purpose='verify-email' AND consumed_at IS NULL AND expires_at>now() RETURNING user_id`, [tokenHash]);
    if (!r.rowCount) { await client.query('ROLLBACK'); return false; }
    await client.query('UPDATE users SET email_verified=TRUE WHERE id=$1 AND email IS NOT NULL', [r.rows[0].user_id]);
    await client.query('COMMIT');
    return true;
  } catch (err) { await client.query('ROLLBACK').catch(() => {}); throw err; }
  finally { client.release(); }
}
async function resetPasswordWithToken(tokenHash, passwordHash) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const r = await client.query(`UPDATE auth_tokens SET consumed_at=now()
      WHERE token_hash=$1 AND purpose='password-reset' AND consumed_at IS NULL AND expires_at>now() RETURNING user_id`, [tokenHash]);
    if (!r.rowCount) { await client.query('ROLLBACK'); return false; }
    await client.query('UPDATE users SET password_hash=$2, token_version=token_version+1 WHERE id=$1', [r.rows[0].user_id, passwordHash]);
    await client.query('COMMIT');
    return true;
  } catch (err) { await client.query('ROLLBACK').catch(() => {}); throw err; }
  finally { client.release(); }
}
async function consumeRecoveryCode(userId, hash) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const r = await client.query('SELECT mfa_recovery_hashes FROM users WHERE id=$1 FOR UPDATE', [toInt(userId)]);
    const codes = r.rows[0] && r.rows[0].mfa_recovery_hashes;
    if (!Array.isArray(codes) || !codes.includes(hash)) { await client.query('ROLLBACK'); return false; }
    await client.query('UPDATE users SET mfa_recovery_hashes=$2::jsonb WHERE id=$1',
      [toInt(userId), JSON.stringify(codes.filter((code) => code !== hash))]);
    await client.query('COMMIT');
    return true;
  } catch (err) { await client.query('ROLLBACK').catch(() => {}); throw err; }
  finally { client.release(); }
}

// ---- rooms ----
const newRoomId = () => crypto.randomBytes(9).toString('base64url');      // 12 chars
const newInvite = () => crypto.randomBytes(18).toString('base64url');     // 24 chars

async function createRoom(ownerId) {
  const owner = toInt(ownerId);
  const owned = await pool.query('SELECT count(*)::int AS n FROM rooms WHERE owner_id=$1', [owner]);
  if (owned.rows[0].n >= MAX_ROOMS_PER_USER) throw new Error('ROOM_LIMIT');
  const id = newRoomId();
  const invite = newInvite();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('INSERT INTO rooms (id, owner_id, invite_code) VALUES ($1,$2,$3)', [id, owner, invite]);
    await client.query("INSERT INTO room_members (room_id, user_id, role) VALUES ($1,$2,'owner')", [id, owner]);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
  return { id, inviteCode: invite };
}

async function getRole(userId, roomId) {
  const n = toInt(userId);
  if (n === null) return null;
  const r = await pool.query('SELECT role FROM room_members WHERE room_id=$1 AND user_id=$2', [roomId, n]);
  return r.rows[0] ? r.rows[0].role : null;
}
async function listRooms(userId) {
  const r = await pool.query(
    `SELECT r.id, m.role, r.created_at AS "createdAt"
       FROM room_members m JOIN rooms r ON r.id = m.room_id
      WHERE m.user_id=$1 ORDER BY r.created_at DESC LIMIT 100`, [toInt(userId)]);
  return r.rows;
}
async function listRoomMembers(roomId) {
  const r = await pool.query(`SELECT u.id, u.username, m.role, m.joined_at AS "joinedAt"
    FROM room_members m JOIN users u ON u.id=m.user_id WHERE m.room_id=$1
    ORDER BY CASE m.role WHEN 'owner' THEN 0 ELSE 1 END, lower(u.username)`, [roomId]);
  return r.rows;
}
async function removeRoomMember(roomId, targetUserId, ownerId) {
  const target = toInt(targetUserId); const owner = toInt(ownerId);
  if (target === null || owner === null) return null;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const room = await client.query('SELECT owner_id FROM rooms WHERE id=$1 FOR UPDATE', [roomId]);
    if (!room.rows[0] || room.rows[0].owner_id !== owner) { await client.query('ROLLBACK'); return null; }
    const member = await client.query('SELECT role FROM room_members WHERE room_id=$1 AND user_id=$2 FOR UPDATE', [roomId, target]);
    if (!member.rows[0] || member.rows[0].role === 'owner' || target === owner) { await client.query('ROLLBACK'); return null; }
    await client.query('DELETE FROM room_members WHERE room_id=$1 AND user_id=$2', [roomId, target]);
    const inviteCode = newInvite();
    await client.query('UPDATE rooms SET invite_code=$1 WHERE id=$2', [inviteCode, roomId]);
    await client.query('COMMIT');
    return { inviteCode, userId: String(target) };
  } catch (err) { await client.query('ROLLBACK').catch(() => {}); throw err; }
  finally { client.release(); }
}
async function updateRoomMemberRole(roomId, targetUserId, role) {
  if (!['editor', 'viewer'].includes(role)) return false;
  const target = toInt(targetUserId);
  if (target === null) return false;
  const r = await pool.query(`UPDATE room_members m SET role=$3 FROM rooms r
    WHERE m.room_id=$1 AND m.user_id=$2 AND r.id=m.room_id AND r.owner_id<>m.user_id
    RETURNING m.user_id`, [roomId, target, role]);
  return r.rowCount > 0;
}
async function leaveRoom(roomId, userId) {
  const uid = toInt(userId);
  if (uid === null) return false;
  const r = await pool.query(`DELETE FROM room_members m USING rooms r
    WHERE m.room_id=$1 AND m.user_id=$2 AND m.role <> 'owner' AND r.id=m.room_id RETURNING m.user_id`, [roomId, uid]);
  return r.rowCount > 0;
}
async function getInviteForOwner(roomId, userId) {
  const r = await pool.query('SELECT invite_code FROM rooms WHERE id=$1 AND owner_id=$2', [roomId, toInt(userId)]);
  return r.rows[0] ? r.rows[0].invite_code : null;
}
async function regenerateInvite(roomId, ownerId) {
  const code = newInvite();
  const r = await pool.query(
    'UPDATE rooms SET invite_code=$1 WHERE id=$2 AND owner_id=$3 RETURNING invite_code',
    [code, roomId, toInt(ownerId)]);
  return r.rows[0] ? r.rows[0].invite_code : null;
}
// returns room id, or null for an unknown code; throws Error('ROOM_FULL')
async function joinByCode(userId, code) {
  const r = await pool.query('SELECT id FROM rooms WHERE invite_code=$1', [code]);
  if (!r.rows[0]) return null;
  const roomId = r.rows[0].id;
  const uid = toInt(userId);
  const existing = await pool.query('SELECT 1 FROM room_members WHERE room_id=$1 AND user_id=$2', [roomId, uid]);
  if (existing.rows[0]) return roomId;
  const count = await pool.query('SELECT count(*)::int AS n FROM room_members WHERE room_id=$1', [roomId]);
  if (count.rows[0].n >= MAX_MEMBERS_PER_ROOM) throw new Error('ROOM_FULL');
  await pool.query(
    "INSERT INTO room_members (room_id, user_id, role) VALUES ($1,$2,'editor') ON CONFLICT DO NOTHING",
    [roomId, uid]);
  return roomId;
}

module.exports = {
  pool, initSchema, loadDocument, saveDocument, saveMessage, loadRecentMessages,
  ensureDefaultWorkspaceFile, listWorkspaceFiles, getWorkspaceFile, getWorkspaceFileForRoom,
  getWorkspaceRoomForDoc, getWorkspaceDocRole, createWorkspaceFile, importWorkspaceFiles, updateWorkspaceFile, deleteWorkspaceFile, saveWorkspaceDocument,
  createWorkspaceFileVersion, listWorkspaceFileVersions, getWorkspaceFileVersion,
  getRoomGitRepository, setRoomGitRepository, deleteRoomGitRepository,
  createUser, getUserByName, getUserById, bumpTokenVersion, getUserByEmail,
  setUserEmail, createAuthToken, consumeEmailToken, resetPasswordWithToken, consumeRecoveryCode,
  createRoom, getRole, listRooms, listRoomMembers, removeRoomMember, updateRoomMemberRole, leaveRoom, getInviteForOwner, regenerateInvite, joinByCode, deleteChatMessage,
};
