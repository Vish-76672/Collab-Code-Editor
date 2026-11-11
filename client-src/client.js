// client-src/client.js -- Phase 7
// Screens: sign in / sign up -> rooms lobby -> room (editor + run + chat).
// The session lives in an HttpOnly cookie, so this code never sees or stores the token.

import { EditorState, Compartment, StateEffect, StateField } from '@codemirror/state';
import { EditorView, keymap, lineNumbers, Decoration, WidgetType } from '@codemirror/view';
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands';
import { oneDark } from '@codemirror/theme-one-dark';
import { javascript } from '@codemirror/lang-javascript';
import { python } from '@codemirror/lang-python';
import { java } from '@codemirror/lang-java';
import { cpp } from '@codemirror/lang-cpp';
import { html } from '@codemirror/lang-html';
import { css } from '@codemirror/lang-css';
import { json } from '@codemirror/lang-json';
import { rust } from '@codemirror/lang-rust';

var ReconnectingWebSocket = require('reconnecting-websocket');
var ShareDBClient = require('sharedb/lib/client');
var ShareDBConnection = ShareDBClient.Connection;
var richText = require('ot-text');
var QRCode = require('qrcode');
var enableTextPresence = require('../text-presence');
enableTextPresence(richText.type);
ShareDBClient.types.register(richText.type);
var ops = require('./ops');

var setRemoteCursors = StateEffect.define();
var RemoteCursorLabel = class extends WidgetType {
  constructor(name) { super(); this.name = name; }
  eq(other) { return other.name === this.name; }
  toDOM() {
    var label = document.createElement('span');
    label.className = 'remote-cursor-label';
    label.dataset.name = this.name;
    return label;
  }
  ignoreEvent() { return true; }
};
var remoteCursorField = StateField.define({
  create: function () { return Decoration.none; },
  update: function (decorations, transaction) {
    decorations = decorations.map(transaction.changes);
    transaction.effects.forEach(function (effect) {
      if (effect.is(setRemoteCursors)) decorations = buildRemoteCursorDecorations(effect.value, transaction.state.doc.length);
    });
    return decorations;
  },
  provide: function (field) { return EditorView.decorations.from(field); },
});
function buildRemoteCursorDecorations(cursors, docLength) {
  var ranges = [];
  cursors.forEach(function (cursor) {
    var anchor = Math.max(0, Math.min(docLength, cursor.anchor));
    var head = Math.max(0, Math.min(docLength, cursor.head));
    if (anchor !== head) ranges.push(Decoration.mark({ class: 'remote-selection', attributes: { style: '--remote-cursor-color:' + cursor.color } }).range(Math.min(anchor, head), Math.max(anchor, head)));
    ranges.push(Decoration.widget({ widget: new RemoteCursorLabel(cursor.name), side: 1, attributes: { style: '--remote-cursor-color:' + cursor.color } }).range(head));
  });
  return Decoration.set(ranges, true);
}

var LANGUAGES = {
  javascript: javascript(), python: python(), java: java(), cpp: cpp(),
  html: html(), css: css(), json: json(), rust: rust(),
  plaintext: [],
};
var RUNNABLE = { javascript: true, python: true };

var $ = function (id) { return document.getElementById(id); };
var theme = localStorage.getItem('collab-editor-theme') === 'light' ? 'light' : 'dark';
function applyTheme(next) {
  theme = next === 'light' ? 'light' : 'dark';
  document.documentElement.dataset.theme = theme;
  var button = $('theme-toggle');
  if (button) { button.textContent = theme === 'dark' ? 'Light' : 'Dark'; button.setAttribute('aria-label', 'Switch to ' + (theme === 'dark' ? 'light' : 'dark') + ' theme'); }
  if (currentRoom && currentRoom.setTheme) currentRoom.setTheme(theme);
  localStorage.setItem('collab-editor-theme', theme);
}
function codeMirrorTheme(mode) {
  if (mode === 'dark') return oneDark;
  return EditorView.theme({
    '&': { color: '#202833', backgroundColor: '#ffffff' },
    '.cm-content': { caretColor: '#27836f' },
    '.cm-cursor, .cm-dropCursor': { borderLeftColor: '#27836f' },
    '.cm-activeLine': { backgroundColor: '#f3f6f8' },
    '.cm-gutters': { color: '#7a8794', backgroundColor: '#f7f9fb', border: 'none' },
    '.cm-activeLineGutter': { backgroundColor: '#edf1f4' },
  }, { dark: false });
}
applyTheme(theme);
$('theme-toggle').onclick = function () { applyTheme(theme === 'dark' ? 'light' : 'dark'); };
var SCREENS = ['auth-screen', 'recovery-screen', 'lobby-screen', 'room-screen'];
function show(id) { SCREENS.forEach(function (s) { $(s).style.display = s === id ? 'flex' : 'none'; }); }
function setMobileView(name) {
  $('room-screen').dataset.mobileView = name;
  document.querySelectorAll('[data-mobile-view]').forEach(function (button) {
    var active = button.getAttribute('data-mobile-view') === name;
    button.classList.toggle('active', active);
    button.setAttribute('aria-pressed', String(active));
  });
}
document.querySelectorAll('[data-mobile-view]').forEach(function (button) {
  button.onclick = function () { setMobileView(button.getAttribute('data-mobile-view')); };
});

async function api(path, method, body) {
  var res = await fetch(path, {
    method: method || 'GET',
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'same-origin',
  });
  var data = {};
  try { data = await res.json(); } catch (e) { /* no body */ }
  if (!res.ok) { var err = new Error(data.error || 'Request failed (' + res.status + ')'); err.status = res.status; throw err; }
  return data;
}

var me = null;
var currentRoom = null;
var notice = '';

// ------------------------------------------------------------------ auth screen
var authMode = 'login';
var mfaChallenge = null;
var resetToken = null;
function setAuthMode(mode) {
  authMode = mode;
  mfaChallenge = null;
  $('auth-mfa-field').style.display = 'none';
  $('auth-email-field').style.display = mode === 'register' ? 'flex' : 'none';
  $('forgot-password').style.display = mode === 'login' ? 'block' : 'none';
  $('tab-login').classList.toggle('active', mode === 'login');
  $('tab-register').classList.toggle('active', mode === 'register');
  $('auth-submit').textContent = mode === 'login' ? 'Log in' : 'Create account';
  $('auth-password').autocomplete = mode === 'login' ? 'current-password' : 'new-password';
  $('auth-hint').textContent = mode === 'register' ? '3–24 characters for the username; password at least 8.' : '';
  $('auth-error').textContent = '';
}
$('tab-login').onclick = function () { setAuthMode('login'); };
$('tab-register').onclick = function () { setAuthMode('register'); };
$('forgot-password').onclick = function () { location.hash = '#/forgot'; };
$('back-to-login').onclick = function () { location.hash = ''; setAuthMode('login'); showAuth(''); };

$('forgot-form').onsubmit = async function (e) {
  e.preventDefault(); $('forgot-error').textContent = 'Sending…';
  try {
    var result = await api('/api/password/forgot', 'POST', { email: $('forgot-email').value.trim() });
    $('forgot-error').textContent = result.message;
  } catch (err) { $('forgot-error').textContent = err.message; }
};
$('reset-form').onsubmit = async function (e) {
  e.preventDefault(); $('reset-error').textContent = '';
  var password = $('reset-password').value;
  if (password !== $('reset-password-confirm').value) { $('reset-error').textContent = 'Passwords do not match.'; return; }
  try {
    await api('/api/password/reset', 'POST', { token: resetToken, password: password });
    resetToken = null; location.hash = ''; showAuth('Password updated. Log in with your new password.');
  } catch (err) { $('reset-error').textContent = err.message; }
};

$('auth-form').onsubmit = async function (e) {
  e.preventDefault();
  $('auth-error').textContent = '';
  $('auth-submit').disabled = true;
  try {
    var data;
    if (mfaChallenge) {
      data = await api('/api/login/mfa', 'POST', { challenge: mfaChallenge, code: $('auth-mfa-code').value.trim() });
      mfaChallenge = null;
      $('auth-mfa-code').value = '';
      $('auth-mfa-field').style.display = 'none';
      $('auth-submit').textContent = 'Log in';
    } else {
      var payload = { username: $('auth-username').value.trim(), password: $('auth-password').value };
      if (authMode === 'register') payload.email = $('auth-email').value.trim();
      data = await api(authMode === 'login' ? '/api/login' : '/api/register', 'POST', payload);
      if (data.mfaRequired) {
        mfaChallenge = data.challenge;
        $('auth-submit').textContent = 'Verify code';
        $('auth-mfa-field').style.display = 'flex';
        $('auth-mfa-code').focus();
        $('auth-error').textContent = 'Enter the code from your authenticator app, or a recovery code.';
        return;
      }
      if (data.emailVerificationSent === false) notice = 'Account created. Set up SMTP email delivery and verify your recovery address in Account security.';
      else if (authMode === 'register') notice = 'Account created. Check your email to verify the recovery address.';
    }
    me = data.user;
    $('auth-password').value = '';
    route();
  } catch (err) {
    $('auth-error').textContent = err.message;
  } finally {
    $('auth-submit').disabled = false;
  }
};

function showAuth(message) {
  leaveRoom();
  me = null;
  show('auth-screen');
  $('auth-error').textContent = message || '';
}

// ------------------------------------------------------------------ lobby
async function showLobby() {
  leaveRoom();
  show('lobby-screen');
  $('lobby-user').textContent = me.username;
  $('lobby-notice').textContent = notice;
  notice = '';
  var list = $('room-list');
  list.textContent = 'Loading…';
  try {
    loadSecuritySettings();
    var data = await api('/api/rooms');
    list.textContent = '';
    if (!data.rooms.length) list.textContent = 'No rooms yet — create one or paste an invite link.';
    data.rooms.forEach(function (r) {
      var row = document.createElement('button');
      row.className = 'room-row';
      var id = document.createElement('span'); id.className = 'room-row-id'; id.textContent = r.id;
      var role = document.createElement('span'); role.className = 'room-row-role'; role.textContent = r.role;
      row.appendChild(id); row.appendChild(role);
      row.onclick = function () { location.hash = '#/room/' + r.id; };
      list.appendChild(row);
    });
  } catch (err) {
    if (err.status === 401) return showAuth('Please log in again.');
    list.textContent = err.message;
  }
}

async function loadSecuritySettings() {
  try {
    var s = await api('/api/account/security');
    $('security-email').value = s.email || '';
    $('security-status').textContent = (s.email ? (s.emailVerified ? 'Recovery email verified.' : 'Recovery email not verified.') : 'Add and verify a recovery email.') + (s.mfaEnabled ? ' Authenticator 2FA is on.' : ' Authenticator 2FA is off.');
    $('mfa-setup-btn').style.display = s.mfaEnabled ? 'none' : 'inline-block';
    $('mfa-disable-area').style.display = s.mfaEnabled ? 'block' : 'none';
  } catch (e) { $('security-status').textContent = 'Could not load account security settings.'; }
}
$('save-security-email').onclick = async function () {
  $('security-message').textContent = '';
  try {
    var result = await api('/api/account/email', 'POST', { email: $('security-email').value.trim(), password: $('security-password').value });
    $('security-password').value = '';
    $('security-message').textContent = result.emailSent ? 'Verification email sent. Open the link to confirm this address.' : 'Email saved, but verification email could not be sent. Check the server email settings.';
    loadSecuritySettings();
  } catch (e) { $('security-message').textContent = e.message; }
};
$('mfa-setup-btn').onclick = async function () {
  $('security-message').textContent = '';
  try {
    var result = await api('/api/account/mfa/setup', 'POST', { password: $('security-password').value });
    $('security-password').value = '';
    $('mfa-secret').textContent = result.secret;
    $('mfa-setup-area').style.display = 'block';
    $('mfa-enable-code').value = '';
    QRCode.toCanvas($('mfa-qr'), result.uri, {
      width: 220, margin: 2,
      color: { dark: '#241443', light: '#ffffff' },
      errorCorrectionLevel: 'M',
    }, function (err) {
      if (err) $('security-message').textContent = 'Could not render the QR code. Use the setup key below instead.';
    });
  } catch (e) { $('security-message').textContent = e.message; }
};
$('chat-tab').onclick = function () {
  $('chat-pane').style.display = 'flex'; $('ai-pane').style.display = 'none';
  $('chat-tab').classList.add('active'); $('chat-tab').setAttribute('aria-selected', 'true');
  $('ai-tab').classList.remove('active'); $('ai-tab').setAttribute('aria-selected', 'false');
};
$('ai-tab').onclick = function () {
  $('chat-pane').style.display = 'none'; $('ai-pane').style.display = 'flex';
  $('ai-tab').classList.add('active'); $('ai-tab').setAttribute('aria-selected', 'true');
  $('chat-tab').classList.remove('active'); $('chat-tab').setAttribute('aria-selected', 'false');
};
document.querySelectorAll('[data-explorer]').forEach(function (button) {
  button.onclick = function () {
    var active = button.getAttribute('data-explorer');
    document.querySelectorAll('[data-explorer]').forEach(function (tab) { tab.classList.toggle('active', tab === button); });
    ['files', 'search', 'git'].forEach(function (name) {
      $('explorer-' + name).style.display = name === active ? 'block' : 'none';
    });
  };
});
$('mfa-enable-btn').onclick = async function () {
  try {
    var result = await api('/api/account/mfa/enable', 'POST', { code: $('mfa-enable-code').value.trim() });
    $('mfa-setup-area').style.display = 'none';
    $('mfa-recovery-codes').textContent = 'Save these one-time recovery codes somewhere safe. They are shown only once.\n\n' + result.recoveryCodes.join('\n');
    $('mfa-recovery-codes').style.display = 'block';
    $('security-message').textContent = 'Authenticator 2FA enabled.';
    loadSecuritySettings();
  } catch (e) { $('security-message').textContent = e.message; }
};
$('mfa-disable-btn').onclick = async function () {
  try {
    await api('/api/account/mfa/disable', 'POST', { password: $('security-password').value, code: $('mfa-disable-code').value.trim() });
    $('security-password').value = ''; $('mfa-disable-code').value = '';
    $('security-message').textContent = 'Authenticator 2FA disabled.';
    loadSecuritySettings();
  } catch (e) { $('security-message').textContent = e.message; }
};

$('create-room').onclick = async function () {
  $('lobby-notice').textContent = '';
  try {
    var r = await api('/api/rooms', 'POST', {});
    location.hash = '#/room/' + r.id;
  } catch (err) { $('lobby-notice').textContent = err.message; }
};

$('join-form').onsubmit = async function (e) {
  e.preventDefault();
  var m = $('join-input').value.trim().match(/([\w-]{16,64})\/?$/);
  if (!m) { $('lobby-notice').textContent = 'Paste a full invite link or code.'; return; }
  $('join-input').value = '';
  location.hash = '#/join/' + m[1];
};

$('logout-btn').onclick = async function () {
  try { await api('/api/logout', 'POST', {}); } catch (e) { /* already logged out */ }
  location.hash = '';
  showAuth('');
};

// ------------------------------------------------------------------ routing
async function route() {
  var hash = location.hash;
  var resetMatch = hash.match(/^#\/reset-password\/([\w-]+)$/);
  var verifyMatch = hash.match(/^#\/verify-email\/([\w-]+)$/);
  if (hash === '#/forgot') {
    show('recovery-screen'); $('forgot-form').style.display = 'flex'; $('reset-form').style.display = 'none'; return;
  }
  if (resetMatch) {
    resetToken = resetMatch[1]; show('recovery-screen'); $('forgot-form').style.display = 'none'; $('reset-form').style.display = 'flex'; return;
  }
  if (verifyMatch) {
    try { await api('/api/account/email/verify', 'POST', { token: verifyMatch[1] }); location.hash = ''; showAuth('Email verified. You can now use it for password recovery.'); }
    catch (e) { location.hash = ''; showAuth(e.message); }
    return;
  }
  if (!me) {
    try { me = (await api('/api/me')).user; } catch (e) { me = null; }
  }
  if (!me) return showAuth('');

  hash = location.hash;
  var join = hash.match(/^#\/join\/([\w-]{16,64})$/);
  var room = hash.match(/^#\/room\/([\w-]{1,64})$/);
  if (join) {
    try {
      var r = await api('/api/rooms/join', 'POST', { code: join[1] });
      location.hash = '#/room/' + r.roomId;
    } catch (err) {
      notice = err.message;
      location.hash = '';
    }
    return;
  }
  if (room) return enterRoom(room[1]);
  showLobby();
}
window.addEventListener('hashchange', route);

// ------------------------------------------------------------------ room
function leaveRoom() {
  if (currentRoom) { currentRoom.dispose(); currentRoom = null; }
}

async function enterRoom(roomId) {
  leaveRoom();
  var info;
  try {
    info = await api('/api/rooms/' + roomId);
  } catch (err) {
    if (err.status === 401) return showAuth('Please log in again.');
    notice = err.message;
    location.hash = '';
    return;
  }
  show('room-screen');
  currentRoom = startRoom(roomId, info);
}

function startRoom(roomId, info) {
  setMobileView('editor');
  var canEdit = info.role !== 'viewer';
  var disposed = false;
  var permissionRefreshStarted = false;
  var roleEventSequence = 0;
  var applyingRemote = false;
  var applyingRemoteLang = false;
  var presenceSocket = null;
  var shareSocket = null;
  var connection = null;
  var view = null;
  var activeDocPresence = null;
  var localDocPresence = null;
  var cursorPublishTimer = null;
  var remoteCursors = new Map();
  var themeConf = new Compartment();
  var editabilityConf = new Compartment();
  var roomFiles = [];
  var openTabs = [];
  var workspaceInitialized = false;
  var selectedFile = null;
  var openWorkspaceFile = function () {};
  var beginCreateFile = function () {};
  var pendingWorkspaceFiles = null;
  var pendingLineJump = null;
  var renderWorkspaceFiles = function (files) { pendingWorkspaceFiles = files; };

  var statusEl = $('status');
  var dot = $('status-dot');
  var langSelect = $('lang-select');
  var runBtn = $('run-btn');
  var outputBody = $('output-body');
  var outputMeta = $('output-meta');
  var outputPanel = $('output');
  var outputToggle = $('output-toggle');
  var chatList = $('chat-list');
  var chatInput = $('chat-input');
  var chatNote = $('chat-note');

  $('room-id-label').textContent = roomId;
  $('workspace-root-name').textContent = roomId;
  $('output-body').textContent = '';
  $('chat-list').textContent = '';
  $('presence-list').textContent = '';
  statusEl.textContent = 'connecting…';
  dot.classList.remove('live');
  function resizeChatInput() {
    chatInput.style.height = '42px';
    var height = Math.min(150, Math.max(42, chatInput.scrollHeight));
    chatInput.style.height = height + 'px';
    chatInput.style.overflowY = chatInput.scrollHeight > 150 ? 'auto' : 'hidden';
  }
  function setOutputCollapsed(collapsed) {
    outputPanel.classList.toggle('output-collapsed', !!collapsed);
    outputToggle.textContent = collapsed ? '▸' : '▾';
    outputToggle.setAttribute('aria-expanded', String(!collapsed));
    outputToggle.title = (collapsed ? 'Expand' : 'Collapse') + ' Run Output (Ctrl+J)';
  }
  function updateEditorPosition(editorView) {
    if (!editorView || !selectedFile) return;
    var head = editorView.state.selection.main.head;
    var line = editorView.state.doc.lineAt(head);
    $('editor-position').textContent = 'Ln ' + line.number + ', Col ' + (head - line.from + 1);
  }
  outputToggle.onclick = function () { setOutputCollapsed(!outputPanel.classList.contains('output-collapsed')); };
  setOutputCollapsed(false);
  chatInput.addEventListener('input', resizeChatInput);
  resizeChatInput();

  function setStatus(text) {
    statusEl.textContent = text;
    dot.classList.toggle('live', /connected/.test(text));
  }
  function draftKey(file) { return 'collab-editor-draft:v1:' + me.id + ':' + roomId + ':' + file.id; }
  function readLocalDraft(file) {
    try {
      var value = JSON.parse(localStorage.getItem(draftKey(file)) || 'null');
      return value && typeof value.content === 'string' ? value : null;
    } catch (e) { return null; }
  }
  function saveLocalDraft(file, content) {
    try {
      localStorage.setItem(draftKey(file), JSON.stringify({ content: content, sourceName: file.name, language: file.language, savedAt: Date.now() }));
      return true;
    } catch (e) { return false; }
  }
  function clearLocalDraft(file, expectedContent) {
    var draft = readLocalDraft(file);
    if (!draft || (expectedContent !== undefined && draft.content !== expectedContent)) return;
    try { localStorage.removeItem(draftKey(file)); } catch (e) { /* retain status if storage is unavailable */ }
  }
  function downloadLocalDraft(file, draft) {
    var leaf = file.name.split('/').pop().replace(/[^A-Za-z0-9._-]/g, '_');
    var blob = new Blob([draft.content], { type: 'text/plain;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var link = document.createElement('a'); link.href = url; link.download = leaf + '.recovery.txt';
    document.body.appendChild(link); link.click(); link.remove(); setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }
  function offerDraftRecovery(file, draft) {
    if (!draft || draft.content === '' || disposed) return;
    var message = 'A recovery copy saved in this browser differs from the shared file. It will not overwrite the shared version.';
    if (canEdit) {
      showAppDialog('Unsynced local draft found', message + ' Restore it as a separate file in the room?', 'Recover as new file', async function () {
        try {
          var result = await api('/api/rooms/' + roomId + '/files/recover', 'POST', {
            sourceName: file.name, content: draft.content, language: file.language,
          });
          clearLocalDraft(file, draft.content);
          renderWorkspaceFiles(result.files); openWorkspaceFile(result.file); renderWorkspaceFiles(roomFiles);
          setStatus('connected — recovered as a new file');
        } catch (err) { showChatNote('Recovery copy kept in this browser. ' + err.message); }
      });
    } else {
      showAppDialog('Unsynced local draft found', message + ' Download a copy to this device?', 'Download draft', function () { downloadLocalDraft(file, draft); });
    }
  }

  function refreshRoomAfterPermissionChange() {
    if (disposed || permissionRefreshStarted) return;
    permissionRefreshStarted = true;
    setStatus('permissions changed — updating access');
    api('/api/rooms/' + roomId).then(function (result) {
      if (!disposed) applyRoomRole(result.role, true);
    }).catch(function (err) {
      if (!disposed) showChatNote(err.message || 'Could not refresh room access.');
    }).finally(function () { permissionRefreshStarted = false; });
  }

  function handleRoleChanged(roleHint) {
    var sequence = ++roleEventSequence;
    api('/api/rooms/' + roomId).then(function (result) {
      if (!disposed && sequence === roleEventSequence) applyRoomRole(result.role, true);
    }).catch(function () {
      if (!disposed && sequence === roleEventSequence) applyRoomRole(roleHint, true);
    });
  }

  function showAppDialog(title, message, confirmText, onConfirm) {
    var modal = $('app-dialog');
    $('app-dialog-title').textContent = title;
    $('app-dialog-message').textContent = message;
    $('app-dialog-confirm').textContent = confirmText || 'OK';
    $('app-dialog-cancel').hidden = !onConfirm;
    modal.hidden = false;
    $('app-dialog-cancel').onclick = function () { modal.hidden = true; };
    $('app-dialog-confirm').onclick = function () { modal.hidden = true; if (onConfirm) onConfirm(); };
    modal.onclick = function (event) { if (event.target === modal) modal.hidden = true; };
    $('app-dialog-confirm').focus();
  }

  function applyRoomRole(role, showNotice) {
    if (role !== 'owner' && role !== 'editor' && role !== 'viewer') return;
    var wasEditable = canEdit;
    canEdit = role !== 'viewer';
    if (wasEditable === canEdit) return;
    $('workspace-add-file').hidden = !canEdit;
    $('lang-select').disabled = !canEdit;
    document.querySelector('.lang-select-wrap').hidden = !canEdit;
    $('run-btn').hidden = !canEdit;
    $('chat-form').hidden = !canEdit;
    $('chat-head').textContent = canEdit ? 'Room conversation' : 'Room conversation · view only';
    if (view) view.dispatch({ effects: editabilityConf.reconfigure([
      EditorState.readOnly.of(!canEdit), EditorView.editable.of(canEdit),
    ]) });
    renderWorkspaceFiles(roomFiles);
    $('history-checkpoint').hidden = !canEdit;
    $('history-restore').disabled = !canEdit || !selectedVersionId;
    if (showNotice) showAppDialog('Access changed', canEdit
      ? 'The room owner changed your access to Can edit. You can now edit files and use the room tools.'
      : 'The room owner changed your access to View only. You can still read the files, but editing and room tools are disabled.');
  }

  function clearActiveCursor(onDone) {
    if (cursorPublishTimer) { clearTimeout(cursorPublishTimer); cursorPublishTimer = null; }
    if (activeDocPresence) {
      if (localDocPresence) localDocPresence.submit(null, function (err) { if (err) console.warn('Could not clear cursor presence:', err.message); });
      try { activeDocPresence.destroy(function (err) { if (err) console.warn('Could not clear cursor presence:', err.message); if (onDone) onDone(); }); }
      catch (e) { console.warn('Could not clear cursor presence:', e.message); if (onDone) onDone(); }
    }
    else if (onDone) onDone();
    activeDocPresence = null;
    localDocPresence = null;
    remoteCursors.clear();
  }

  var commandPalette = $('command-palette');
  var commandInput = $('command-palette-input');
  function renderQuickOptions(query) {
    var results = $('command-palette-results');
    results.textContent = '';
    var needle = (query || '').trim().toLowerCase();
    var options = [
      { label: 'New File', hint: 'Create a shared file', run: function () { setMobileView('files'); beginCreateFile(); } },
      { label: 'Toggle Color Theme', hint: 'Switch dark / light', run: function () { applyTheme(theme === 'dark' ? 'light' : 'dark'); } },
      { label: 'Search in Files', hint: 'Find text in this workspace', run: function () { setMobileView('files'); document.querySelector('[data-explorer="search"]').click(); $('workspace-search-input').focus(); } },
      { label: 'Open Chat', hint: 'Room conversation', run: function () { setMobileView('chat'); $('chat-tab').click(); } },
    ];
    if (!canEdit) options = options.filter(function (option) { return option.label !== 'New File'; });
    options = options.filter(function (option) { return !needle || (option.label + ' ' + option.hint).toLowerCase().includes(needle); });
    roomFiles.forEach(function (file) {
      if (!needle || file.name.toLowerCase().includes(needle)) options.push({ label: file.name, hint: 'Open shared file', run: function () { openWorkspaceFile(file); renderWorkspaceFiles(roomFiles); } });
    });
    if (!options.length) { results.textContent = 'No matching files or commands.'; return; }
    options.forEach(function (option) {
      var button = document.createElement('button'); button.type = 'button'; button.className = 'command-option';
      var label = document.createElement('span'); label.textContent = option.label;
      var hint = document.createElement('small'); hint.textContent = option.hint;
      button.append(label, hint);
      button.onclick = function () { commandPalette.hidden = true; option.run(); };
      results.appendChild(button);
    });
  }
  function openCommandPalette() {
    commandPalette.hidden = false;
    commandInput.value = '';
    renderQuickOptions('');
    commandInput.focus();
  }
  commandInput.oninput = function () { renderQuickOptions(commandInput.value); };
  commandInput.onkeydown = function (event) {
    if (event.key === 'Escape') { commandPalette.hidden = true; event.stopPropagation(); }
    if (event.key === 'Enter') {
      var first = $('command-palette-results').querySelector('button');
      if (first) { event.preventDefault(); first.click(); }
    }
  };
  $('command-search-open').onclick = openCommandPalette;
  $('command-search-open').onkeydown = function (event) { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); openCommandPalette(); } };
  commandPalette.onclick = function (event) { if (event.target === commandPalette) commandPalette.hidden = true; };
  function onRoomShortcut(event) {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'p') { event.preventDefault(); openCommandPalette(); }
    else if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'j') { event.preventDefault(); setOutputCollapsed(!outputPanel.classList.contains('output-collapsed')); }
    else if (event.key === 'Escape' && !commandPalette.hidden) commandPalette.hidden = true;
  }
  document.addEventListener('keydown', onRoomShortcut);

  // ----- invite (owner only) -----
  var inviteCode = info.inviteCode || null;
  $('invite-wrap').style.display = info.role === 'owner' ? 'flex' : 'none';
  $('workspace-add-file').hidden = !canEdit;
  $('workspace-create-form').hidden = true;
  $('lang-select').disabled = !canEdit;
  document.querySelector('.lang-select-wrap').hidden = !canEdit;
  $('run-btn').hidden = !canEdit;
  $('chat-form').hidden = !canEdit;
  if (!canEdit) $('chat-head').textContent = 'Room conversation · read only';
  $('invite-copy').textContent = 'Copy invite link';
  $('invite-copy').onclick = function () {
    if (!inviteCode) return;
    var link = location.origin + '/#/join/' + inviteCode;
    navigator.clipboard.writeText(link).then(function () {
      $('invite-copy').textContent = 'Copied!';
      setTimeout(function () { $('invite-copy').textContent = 'Copy invite link'; }, 1800);
    }, function () { window.prompt('Copy this invite link:', link); });
  };
  $('invite-reset').onclick = async function () {
    if (!window.confirm('Reset the invite link? The old link will stop working. People already in the room keep access.')) return;
    try {
      inviteCode = (await api('/api/rooms/' + roomId + '/invite/regenerate', 'POST', {})).inviteCode;
      $('invite-copy').textContent = 'New link ready — copy';
    } catch (err) { window.alert(err.message); }
  };
  var membersDialog = $('members-dialog');
  var membersNote = $('members-note');
  var membersList = $('members-list');
  var memberRefreshSequence = 0;
  async function refreshMembers() {
    var sequence = ++memberRefreshSequence;
    membersNote.textContent = 'Loading members…'; membersList.textContent = '';
    try {
      var result = await api('/api/rooms/' + roomId + '/members');
      if (sequence !== memberRefreshSequence) return;
      membersList.textContent = '';
      membersNote.textContent = result.members.length + ' member(s) have access to this room.';
      $('members-leave').hidden = result.role === 'owner';
      result.members.forEach(function (member) {
        var row = document.createElement('div'); row.className = 'member-row';
        var main = document.createElement('div'); main.className = 'member-main';
        var name = document.createElement('div'); name.className = 'member-name'; name.textContent = member.username + (String(member.id) === String(me.id) ? ' (you)' : '');
        var role = document.createElement('div'); role.className = 'member-role'; role.textContent = (member.role === 'viewer' ? 'Can view' : 'Can edit') + (member.joinedAt ? ' · joined ' + new Date(member.joinedAt).toLocaleDateString() : '');
        main.append(name, role); row.appendChild(main);
        if (result.role === 'owner' && member.role !== 'owner') {
          var accessToggle = document.createElement('button'); accessToggle.type = 'button'; accessToggle.className = 'member-access-toggle' + (member.role === 'editor' ? ' enabled' : '');
          accessToggle.setAttribute('role', 'switch'); accessToggle.setAttribute('aria-checked', String(member.role === 'editor'));
          accessToggle.setAttribute('aria-label', 'Allow ' + member.username + ' to edit');
          var accessLabel = document.createElement('span'); accessLabel.className = 'member-access-label'; accessLabel.textContent = member.role === 'editor' ? 'Can edit' : 'View only';
          var accessTrack = document.createElement('span'); accessTrack.className = 'member-access-track'; accessTrack.setAttribute('aria-hidden', 'true');
          var accessThumb = document.createElement('span'); accessThumb.className = 'member-access-thumb'; accessTrack.appendChild(accessThumb);
          accessToggle.append(accessLabel, accessTrack);
          function displayMemberRole(nextRole) {
            member.role = nextRole;
            var canEditMember = nextRole === 'editor';
            accessToggle.classList.toggle('enabled', canEditMember);
            accessToggle.setAttribute('aria-checked', String(canEditMember));
            accessToggle.setAttribute('aria-label', 'Access for ' + member.username + ': ' + (canEditMember ? 'Can edit' : 'View only'));
            accessLabel.textContent = canEditMember ? 'Can edit' : 'View only';
            role.textContent = (canEditMember ? 'Can edit' : 'Can view') + (member.joinedAt ? ' · joined ' + new Date(member.joinedAt).toLocaleDateString() : '');
          }
          accessToggle.onclick = async function () {
            var nextRole = member.role === 'viewer' ? 'editor' : 'viewer';
            memberRefreshSequence++;
            accessToggle.disabled = true;
            try {
              var result = await api('/api/rooms/' + roomId + '/members/' + member.id, 'PATCH', { role: nextRole });
              displayMemberRole(result.role);
              membersNote.textContent = member.username + ' is now ' + (result.role === 'editor' ? 'allowed to edit' : 'view only') + '. They were notified.';
              accessToggle.disabled = false;
            } catch (err) { membersNote.textContent = err.message; accessToggle.disabled = false; }
          };
          row.appendChild(accessToggle);
          var remove = document.createElement('button'); remove.type = 'button'; remove.className = 'member-remove'; remove.textContent = 'Remove';
          remove.onclick = async function () {
            if (!window.confirm('Remove ' + member.username + ' from this room? Their live connections will close, and the current invite link will be reset.')) return;
            remove.disabled = true;
            try {
              var removed = await api('/api/rooms/' + roomId + '/members/' + member.id, 'DELETE');
              inviteCode = removed.inviteCode;
              $('invite-copy').textContent = 'Invite link reset';
              refreshMembers();
            } catch (err) { membersNote.textContent = err.message; remove.disabled = false; }
          };
          row.appendChild(remove);
        }
        membersList.appendChild(row);
      });
    } catch (err) { if (sequence === memberRefreshSequence) membersNote.textContent = err.message; }
  }
  $('members-open').onclick = function () { membersDialog.hidden = false; refreshMembers(); $('members-close').focus(); };
  $('members-close').onclick = function () { membersDialog.hidden = true; };
  membersDialog.onclick = function (event) { if (event.target === membersDialog) membersDialog.hidden = true; };
  $('members-leave').onclick = async function () {
    if (!window.confirm('Leave this room? You will no longer see it in your rooms. A still-active invite link may let you join again.')) return;
    try {
      await api('/api/rooms/' + roomId + '/members/me', 'DELETE');
      membersDialog.hidden = true; notice = 'You left the room.'; location.hash = '';
    } catch (err) { membersNote.textContent = err.message; }
  };
  $('back-btn').onclick = function () { location.hash = ''; };

  // ----- output panel (textContent only: program output is untrusted) -----
  function addOutput(text, cls) {
    var span = document.createElement('span');
    span.className = cls || '';
    span.textContent = text;
    outputBody.appendChild(span);
    outputBody.scrollTop = outputBody.scrollHeight;
  }
  function resetOutput() { outputBody.textContent = ''; outputMeta.textContent = ''; }
  $('output-clear').onclick = resetOutput;

  function showRunStart(msg) {
    resetOutput();
    runBtn.disabled = true;
    outputMeta.textContent = 'running ' + (msg.fileName || msg.language) + ' · ' + msg.language + ' (started by ' + msg.by + ')…';
  }
  function showRunResult(msg) {
    runBtn.disabled = false;
    if (msg.error) { outputMeta.textContent = 'could not run'; addOutput(msg.error + '\n', 'out-err'); return; }
    outputMeta.textContent = [msg.fileName || msg.language, 'by ' + msg.by, 'exit ' + msg.exitCode, msg.durationMs + 'ms'].join(' · ');
    if (msg.stdout) addOutput(msg.stdout, 'out-ok');
    if (msg.stderr) addOutput(msg.stderr, 'out-err');
    if (!msg.stdout && !msg.stderr) addOutput('(no output)\n', 'out-note');
    if (msg.timedOut) addOutput('\n⏱ Killed: exceeded the 5 second time limit.\n', 'out-note');
    if (msg.truncated) addOutput('\n✂ Killed: output exceeded the 64 KB limit.\n', 'out-note');
    if (msg.exitCode === 137 && !msg.timedOut && !msg.truncated) addOutput('\n💥 Killed: likely ran out of memory (128 MB limit).\n', 'out-note');
  }

  runBtn.disabled = false;
  runBtn.onclick = async function () {
    runBtn.disabled = true;
    try {
      if (!selectedFile) throw new Error('Select a file to run.');
      await api('/api/run', 'POST', { roomId: roomId, fileId: selectedFile.id }); // results arrive over the presence socket
    } catch (err) {
      resetOutput();
      outputMeta.textContent = 'could not run';
      addOutput(err.message + '\n', 'out-err');
      runBtn.disabled = false;
    }
  };
  function updateRunButton(lang) {
    runBtn.title = RUNNABLE[lang] ? "Run this room's code in a sandbox" : lang + " can't be run yet (JavaScript and Python only)";
    runBtn.classList.toggle('unsupported', !RUNNABLE[lang]);
  }

  // ----- chat -----
  function nearBottom() { return chatList.scrollHeight - chatList.scrollTop - chatList.clientHeight < 60; }
  function addChat(m) {
    var stick = nearBottom();
    var row = document.createElement('div');
    var mine = String(m.userId) === String(me.id);
    row.className = 'chat-msg' + (mine ? ' me' : '');
    if (m.id) row.dataset.messageId = String(m.id);
    var head = document.createElement('div'); head.className = 'chat-head';
    var who = document.createElement('span'); who.className = 'chat-name'; who.style.color = m.color; who.textContent = m.name;
    var when = document.createElement('span'); when.className = 'chat-time';
    var d = new Date(m.ts);
    when.textContent = isNaN(d) ? '' : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    head.appendChild(who); head.appendChild(when);
    var body = document.createElement('div'); body.className = 'chat-text'; body.textContent = m.text;
    row.appendChild(head); row.appendChild(body);
    if (canEdit && mine && m.id) {
      var remove = document.createElement('button'); remove.type = 'button'; remove.className = 'chat-delete'; remove.title = 'Delete message';
      remove.setAttribute('aria-label', 'Delete your message');
      remove.innerHTML = '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M4.5 6h11M8 6V4.5h4V6m2.8 0-.6 9.3a1.2 1.2 0 0 1-1.2 1.1H7a1.2 1.2 0 0 1-1.2-1.1L5.2 6m3 3v4.6m3.6-4.6v4.6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
      remove.onclick = function () { showAppDialog('Delete message?', 'This message will be removed for everyone in the room.', 'Delete', function () { presenceSocket.send(JSON.stringify({ type: 'chat-delete', id: String(m.id) })); }); };
      row.appendChild(remove);
    }
    chatList.appendChild(row);
    if (stick || m.userId === me.id) chatList.scrollTop = chatList.scrollHeight;
  }
  function showChatNote(text) {
    chatNote.textContent = text;
    setTimeout(function () { if (chatNote.textContent === text) chatNote.textContent = ''; }, 3500);
  }
  function sendChat() {
    if (!canEdit) return;
    var text = chatInput.value.trim();
    if (!text) return;
    presenceSocket.send(JSON.stringify({ type: 'chat', text: text }));
    chatInput.value = '';
    resizeChatInput();
  }
  $('chat-form').onsubmit = function (e) { e.preventDefault(); sendChat(); };
  chatInput.onkeydown = function (e) { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChat(); } };

  function renderPresence(users) {
    var el = $('presence-list');
    el.textContent = '';
    var visibleUsers = users.slice(0, 2);
    visibleUsers.forEach(function (u) {
      var chip = document.createElement('div');
      chip.className = 'presence-chip' + (u.status === 'stale' ? ' stale' : '');
      var isYou = me && String(u.userId) === String(me.id);
      var displayName = String(u.name || 'Collaborator') + (isYou ? ' (you)' : '');
      chip.title = u.status === 'stale' ? displayName + ' (reconnecting…)' : displayName;
      var d = document.createElement('span'); d.className = 'presence-dot'; d.style.background = u.color;
      var l = document.createElement('span'); l.textContent = displayName;
      chip.appendChild(d); chip.appendChild(l);
      el.appendChild(chip);
    });
    if (users.length > visibleUsers.length) {
      var more = document.createElement('span');
      more.className = 'presence-chip presence-more';
      more.textContent = '+' + (users.length - visibleUsers.length);
      more.title = 'Also here: ' + users.slice(visibleUsers.length).map(function (u) { return u.name; }).join(', ');
      el.appendChild(more);
    }
  }

  // ----- sockets (session cookie rides along automatically) -----
  function watchClose(sock) {
    sock.addEventListener('close', function (e) {
      if (disposed) return;
      if (e.code === 4001) { sock.close(); showAuth('Your session ended. Please log in again.'); }
      else if (e.code === 4003) { sock.close(); notice = 'You do not have access to that room.'; location.hash = ''; }
      else if (e.code === 4004) refreshRoomAfterPermissionChange();
      else if (e.code === 4008 || e.code === 4009) { sock.close(); setStatus('disconnected (' + (e.reason || 'limit reached') + ') — reload to retry'); }
    });
  }

  var proto = location.protocol === 'https:' ? 'wss://' : 'ws://';
  presenceSocket = new ReconnectingWebSocket(proto + location.host + '/presence?room=' + encodeURIComponent(roomId));
  watchClose(presenceSocket);

  var shareDbStarted = false;
  presenceSocket.addEventListener('message', function (event) {
    var msg;
    try { msg = JSON.parse(event.data); } catch (e) { return; }
    if (msg.type === 'presence') renderPresence(msg.users);
    else if (msg.type === 'role-changed') handleRoleChanged(msg.role);
    else if (msg.type === 'run-start') showRunStart(msg);
    else if (msg.type === 'run-result') showRunResult(msg);
    else if (msg.type === 'chat') addChat(msg);
    else if (msg.type === 'chat-history') { chatList.textContent = ''; msg.messages.forEach(addChat); chatList.scrollTop = chatList.scrollHeight; }
    else if (msg.type === 'chat-deleted') {
      var row = Array.from(chatList.children).find(function (item) { return item.dataset.messageId === String(msg.id); });
      if (row) row.remove();
    }
    else if (msg.type === 'chat-error') showChatNote(msg.error);
    else if (msg.type === 'workspace-files') renderWorkspaceFiles(msg.files || []);
    if (!shareDbStarted) { shareDbStarted = true; startShareDb(); }
  });

  function startShareDb() {
    if (disposed) return;
  shareSocket = new ReconnectingWebSocket(proto + location.host + '/sharedb?room=' + encodeURIComponent(roomId));
    watchClose(shareSocket);
    connection = new ShareDBConnection(shareSocket);
    function syncError(where, err, rejectedDoc, editorView) {
      console.error(where, err);
      var detail = err && (err.message || err.code) ? (err.message || err.code) : 'unknown error';
      if (where.indexOf('submitOp') >= 0 && /read-only room access|permission/i.test(detail)) {
        applyRoomRole('viewer', canEdit);
        if (rejectedDoc && editorView && view === editorView && typeof rejectedDoc.data === 'string') {
          applyingRemote = true;
          try { editorView.dispatch({ changes: { from: 0, to: editorView.state.doc.length, insert: rejectedDoc.data } }); }
          finally { applyingRemote = false; }
        }
        return;
      }
      setStatus('sync error — ' + where.replace(/ error:?$/, ''));
      statusEl.title = detail;
      showChatNote('Sync failed at ' + where.replace(/ error:?$/, '') + '. Your changes may not be shared yet.');
    }

    function renderWorkspaceFilesLocal(files) {
      roomFiles = Array.isArray(files) ? files : [];
      openTabs = openTabs.map(function (tab) { return roomFiles.find(function (file) { return file.id === tab.id; }); }).filter(Boolean);
      var list = $('workspace-file-list'); list.textContent = '';
      var previousId = selectedFile && selectedFile.id;
      if (previousId) selectedFile = roomFiles.find(function (f) { return f.id === previousId; }) || roomFiles[0] || null;
      else if (!workspaceInitialized) selectedFile = roomFiles[0] || null;
      workspaceInitialized = true;
      var tree = { folders: Object.create(null), files: [] };
      roomFiles.forEach(function (file) {
        var parts = file.name.split('/'); var node = tree;
        parts.slice(0, -1).forEach(function (part) { node.folders[part] = node.folders[part] || { folders: Object.create(null), files: [] }; node = node.folders[part]; });
        node.files.push({ file: file, label: parts[parts.length - 1] });
      });
      function renderTree(node, depth) {
        Object.keys(node.folders).sort().forEach(function (folder) {
          var folderButton = document.createElement('button'); folderButton.type = 'button'; folderButton.className = 'tree-folder';
          folderButton.style.paddingLeft = (8 + depth * 13) + 'px'; folderButton.textContent = '▾  ' + folder; folderButton.setAttribute('aria-expanded', 'true');
          var children = document.createElement('div');
          folderButton.onclick = function () { children.hidden = !children.hidden; folderButton.setAttribute('aria-expanded', String(!children.hidden)); folderButton.textContent = (children.hidden ? '▸  ' : '▾  ') + folder; };
          list.append(folderButton, children); var oldList = list; list = children; renderTree(node.folders[folder], depth + 1); list = oldList;
        });
        node.files.forEach(function (entry) {
        var file = entry.file;
        var row = document.createElement('div'); row.className = 'tree-file-row';
        row.style.paddingLeft = (depth * 13) + 'px';
        var open = document.createElement('button'); open.type = 'button'; open.className = 'tree-file' + (selectedFile && selectedFile.id === file.id ? ' active' : '');
        var dotEl = document.createElement('span'); dotEl.className = 'file-dot'; dotEl.textContent = '●';
        var name = document.createElement('span'); name.className = 'tree-file-name'; name.textContent = entry.label; open.append(dotEl, name);
        open.onclick = function () { openWorkspaceFile(file); renderWorkspaceFiles(roomFiles); };
        var rename = document.createElement('button'); rename.type = 'button'; rename.className = 'file-rename'; rename.title = 'Rename ' + file.name; rename.setAttribute('aria-label', 'Rename ' + file.name);
        rename.hidden = !canEdit;
        rename.innerHTML = '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="m12.8 3.6 3.6 3.6M4 16l3.3-.7L16 6.6a1.8 1.8 0 0 0-2.6-2.6l-8.7 8.7L4 16Z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
        rename.onclick = function () {
          open.hidden = true;
          rename.hidden = true;
          var form = document.createElement('form'); form.className = 'workspace-create-form workspace-rename-form';
          var icon = document.createElement('span'); icon.className = 'file-dot'; icon.textContent = '●';
          var input = document.createElement('input'); input.type = 'text'; input.required = true; input.maxLength = 240; input.autocomplete = 'off'; input.setAttribute('aria-label', 'New file name'); input.value = file.name;
          form.append(icon, input); row.insertBefore(form, rename); input.focus(); input.select();
          form.onsubmit = async function (event) {
            event.preventDefault();
            var nextName = input.value.trim();
            if (!nextName) { input.focus(); return; }
            try {
              var result = await api('/api/rooms/' + roomId + '/files/' + file.id, 'PATCH', { name: nextName, language: file.language });
              renderWorkspaceFiles(result.files);
            } catch (err) {
              showAppDialog('Could not rename file', err.message);
              input.focus(); input.select();
            }
          };
          input.onkeydown = function (event) {
            if (event.key === 'Escape') { event.preventDefault(); renderWorkspaceFiles(roomFiles); }
          };
        };
        var del = document.createElement('button'); del.type = 'button'; del.className = 'file-delete'; del.textContent = '×'; del.title = 'Delete ' + file.name; del.setAttribute('aria-label', 'Delete ' + file.name);
        del.hidden = !canEdit;
        del.onclick = async function () {
          if (roomFiles.length <= 1) { showAppDialog('Keep one workspace file', 'Every room needs at least one file. Create another file before deleting this one.'); return; }
          showAppDialog('Delete ' + file.name + '?', 'This shared file will be removed for everyone in the room.', 'Delete', async function () {
            try { var result = await api('/api/rooms/' + roomId + '/files/' + file.id, 'DELETE'); renderWorkspaceFiles(result.files); }
            catch (err) { showAppDialog(err.message.indexOf('at least one') >= 0 ? 'Keep one workspace file' : 'Could not delete file', err.message); }
          });
        };
        var historyButton = document.createElement('button'); historyButton.type = 'button'; historyButton.className = 'file-history';
        historyButton.title = 'File history for ' + file.name; historyButton.setAttribute('aria-label', 'File history for ' + file.name);
        historyButton.innerHTML = '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M3.2 9a6.8 6.8 0 1 1 .7 4.7M3 4.4v4.8h4.8M10 5.8v4.5l3 1.8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
        historyButton.onclick = function () { openFileHistory(file); };
        row.append(open, rename, historyButton, del); list.appendChild(row);
      });
      }
      renderTree(tree, 0);
      if (selectedFile && previousId !== selectedFile.id) openWorkspaceFile(selectedFile);
      if (selectedFile) {
        langSelect.value = selectedFile.language;
        updateRunButton(selectedFile.language);
      }
      renderOpenTabs();
    }
    renderWorkspaceFiles = renderWorkspaceFilesLocal;
    if (pendingWorkspaceFiles) { renderWorkspaceFiles(pendingWorkspaceFiles); pendingWorkspaceFiles = null; }

    var historyFile = null;
    var selectedVersionId = null;
    var historyVersions = [];
    function setHistoryNote(message, isError) {
      $('history-note').textContent = message || '';
      $('history-note').classList.toggle('error', !!isError);
    }
    async function loadFileHistory(file, preferredId) {
      historyFile = file;
      $('history-file-name').textContent = file.name;
      $('history-preview').textContent = 'Loading saved versions…';
      $('history-version-list').textContent = '';
      $('history-restore').disabled = true;
      try {
        var result = await api('/api/rooms/' + roomId + '/files/' + file.id + '/history');
        historyVersions = result.versions || [];
        var list = $('history-version-list'); list.textContent = '';
        if (!historyVersions.length) $('history-preview').textContent = 'No saved versions yet. Save a checkpoint before a major change, or edit the file to begin automatic history.';
        historyVersions.forEach(function (version) {
          var button = document.createElement('button'); button.type = 'button'; button.className = 'history-version'; button.dataset.versionId = String(version.id);
          var label = document.createElement('strong'); label.textContent = version.kind === 'checkpoint' ? 'Manual checkpoint' : version.kind === 'auto-save' ? 'Automatic save' : version.kind === 'before edit' ? 'Before editing' : version.kind === 'before restore' ? 'Before restore' : version.kind === 'restore' ? 'Restored version' : 'Saved version';
          var meta = document.createElement('small');
          var date = new Date(version.createdAt).toLocaleString();
          meta.textContent = version.author + ' · ' + date + ' · ' + Number(version.contentLength || 0).toLocaleString() + ' characters';
          button.append(label, meta);
          button.onclick = function () { selectHistoryVersion(version.id); };
          list.appendChild(button);
        });
        if (preferredId && historyVersions.some(function (version) { return String(version.id) === String(preferredId); })) await selectHistoryVersion(preferredId);
        else if (historyVersions.length) await selectHistoryVersion(historyVersions[0].id);
        setHistoryNote(historyVersions.length ? 'Versions are saved in this room. Restoring adds another version to history.' : '');
      } catch (err) { $('history-preview').textContent = ''; setHistoryNote(err.message, true); }
    }
    async function selectHistoryVersion(versionId) {
      selectedVersionId = String(versionId);
      Array.from($('history-version-list').children).forEach(function (button) {
        button.classList.toggle('active', button.dataset.versionId === selectedVersionId);
      });
      $('history-restore').disabled = !canEdit;
      $('history-preview').textContent = 'Loading version…';
      try {
        var result = await api('/api/rooms/' + roomId + '/files/' + historyFile.id + '/history/' + selectedVersionId);
        $('history-preview').textContent = result.version.content;
      } catch (err) { $('history-preview').textContent = ''; setHistoryNote(err.message, true); }
    }
    function openFileHistory(file) {
      $('history-dialog').hidden = false;
      $('history-title').textContent = 'File history';
      $('history-preview').textContent = 'Loading saved versions…';
      setHistoryNote('');
      loadFileHistory(file);
    }
    $('history-close').onclick = function () { $('history-dialog').hidden = true; };
    $('history-dialog').onclick = function (event) { if (event.target === $('history-dialog')) $('history-dialog').hidden = true; };
    $('history-checkpoint').hidden = !canEdit;
    $('history-checkpoint').onclick = async function () {
      if (!historyFile) return;
      var button = $('history-checkpoint'); button.disabled = true; setHistoryNote('Saving checkpoint…');
      try {
        var result = await api('/api/rooms/' + roomId + '/files/' + historyFile.id + '/history', 'POST', {});
        await loadFileHistory(historyFile, result.version && result.version.id);
        setHistoryNote('Checkpoint saved.');
      } catch (err) { setHistoryNote(err.message, true); }
      finally { button.disabled = false; }
    };
    $('history-restore').onclick = function () {
      if (!historyFile || !selectedVersionId || !canEdit) return;
      showAppDialog('Restore this version?', 'The current file will be saved to history first, then this version will replace the shared file for everyone in the room.', 'Restore', async function () {
        var button = $('history-restore'); button.disabled = true; setHistoryNote('Restoring shared file…');
        try {
          await api('/api/rooms/' + roomId + '/files/' + historyFile.id + '/history/' + selectedVersionId + '/restore', 'POST', {});
          await loadFileHistory(historyFile);
          setHistoryNote('Version restored and shared with the room.');
        } catch (err) { setHistoryNote(err.message, true); }
      });
    };
    $('history-dialog').addEventListener('keydown', function (event) { if (event.key === 'Escape') $('history-dialog').hidden = true; });

    var gitConnectForm = $('git-connect-form');
    var gitRepoInput = $('git-repository-url');
    var gitStatusView = $('git-status-view');
    var gitPanelNote = $('git-panel-note');
    var gitDisconnectButton = $('git-disconnect');
    var canManageGit = info.role === 'owner';
    function setGitNote(message, isError) {
      gitPanelNote.textContent = message || '';
      gitPanelNote.classList.toggle('error', !!isError);
    }
    function renderGitStatus(result) {
      if (!result.connected) {
        gitStatusView.hidden = true;
        $('git-preview-import').hidden = true;
        $('git-branch-picker').hidden = true;
        clearGitPreview();
        gitConnectForm.hidden = !canManageGit;
        gitDisconnectButton.hidden = true;
        setGitNote(canManageGit ? 'Connect a public repository to view its branch and latest remote changes.' : 'Ask the room owner to connect a public GitHub repository.');
        return;
      }
      gitConnectForm.hidden = true;
      gitStatusView.hidden = false;
      gitDisconnectButton.hidden = !canManageGit;
      $('git-preview-import').hidden = !canManageGit;
      $('git-branch-picker').hidden = !canManageGit;
      setGitNote('');
      var repoLink = $('git-repo-link');
      repoLink.textContent = result.repository.fullName;
      repoLink.href = result.repository.url;
      $('git-branch-name').textContent = result.branch;
      var commitLink = $('git-commit-link');
      commitLink.textContent = result.lastCommit.message || result.lastCommit.sha.slice(0, 7);
      commitLink.href = result.lastCommit.url;
      var dateText = result.lastCommit.date ? new Date(result.lastCommit.date).toLocaleString() : '';
      $('git-commit-meta').textContent = [result.lastCommit.author, dateText, result.lastCommit.sha.slice(0, 7)].filter(Boolean).join(' · ');
      var filesEl = $('git-commit-files'); filesEl.textContent = '';
      var files = result.lastCommit.files || [];
      $('git-empty-files').hidden = files.length > 0;
      files.forEach(function (file) {
        var row = document.createElement('div'); row.className = 'git-commit-file';
        var state = document.createElement('span'); state.className = 'git-file-state';
        state.textContent = file.status;
        var path = document.createElement('span'); path.className = 'git-file-path';
        path.textContent = file.path + '  +' + file.additions + ' / −' + file.deletions;
        row.append(state, path); filesEl.appendChild(row);
      });
      if (result.lastCommit.filesTruncated) {
        var more = document.createElement('div'); more.className = 'git-panel-note'; more.textContent = 'Showing the first 100 files from this commit.'; filesEl.appendChild(more);
      }
    }
    async function refreshGitStatus() {
      if (disposed) return;
      setGitNote('Loading GitHub status…');
      try {
        var result = await api('/api/rooms/' + roomId + '/git/status');
        renderGitStatus(result);
        if (result.connected && canManageGit) {
          var branchResult = await api('/api/rooms/' + roomId + '/git/branches');
          var select = $('git-branch-select'); select.textContent = '';
          if (!branchResult.branches.includes(result.branch)) branchResult.branches.unshift(result.branch);
          branchResult.branches.forEach(function (branch) { var option = document.createElement('option'); option.value = branch; option.textContent = branch; select.appendChild(option); });
          select.value = result.branch;
        }
      }
      catch (err) { setGitNote(err.message, true); }
    }
    $('git-compare').onclick = async function () {
      var button = $('git-compare'); button.disabled = true; $('git-compare-results').hidden = false;
      $('git-compare-detail').hidden = true; $('git-compare-summary').textContent = 'Comparing shared files with GitHub…';
      try {
        var branch = $('git-branch-select').value || $('git-branch-name').textContent;
        var result = await api('/api/rooms/' + roomId + '/git/compare?branch=' + encodeURIComponent(branch));
        var labels = { added: 'New in room', modified: 'Changed in room', unchanged: 'Unchanged', missing: 'Only on GitHub', unavailable: 'Not compared (limit)' };
        var parts = [];
        Object.keys(labels).forEach(function (key) { if (result.counts[key]) parts.push(result.counts[key] + ' ' + labels[key].toLowerCase()); });
        $('git-compare-summary').textContent = result.repository + ' · ' + result.branch + ' · ' + (parts.join(' · ') || 'No supported files found');
        var list = $('git-compare-files'); list.textContent = '';
        result.files.forEach(function (file) {
          var row = document.createElement('button'); row.type = 'button'; row.className = 'git-compare-file';
          var status = document.createElement('span'); status.className = 'git-compare-status'; status.textContent = labels[file.status] || file.status;
          var path = document.createElement('span'); path.textContent = file.path;
          row.append(status, path);
          if (file.status !== 'unavailable') row.onclick = async function () {
            var detail = $('git-compare-detail'); detail.hidden = false; detail.textContent = 'Loading file…';
            try {
              var comparison = await api('/api/rooms/' + roomId + '/git/compare-file?branch=' + encodeURIComponent(result.branch) + '&path=' + encodeURIComponent(file.path));
              detail.textContent = '';
              [[ 'Shared workspace', comparison.workspace ], [ 'GitHub · ' + comparison.branch, comparison.remote ]].forEach(function (column) {
                var section = document.createElement('div'); section.className = 'git-compare-column';
                var heading = document.createElement('strong'); heading.textContent = column[0];
                var pre = document.createElement('pre'); pre.textContent = column[1] === null ? 'File is not present here.' : column[1];
                section.append(heading, pre); detail.appendChild(section);
              });
            } catch (err) { detail.textContent = err.message; }
          };
          list.appendChild(row);
        });
        setGitNote('Comparison is read-only. No changes were sent to GitHub.');
      } catch (err) { $('git-compare-summary').textContent = err.message; setGitNote(err.message, true); }
      finally { button.disabled = false; }
    };
    var activeGitPreview = null;
    function clearGitPreview() {
      activeGitPreview = null;
      $('git-import-preview').hidden = true;
      $('git-import-actions').hidden = true;
      $('git-import-files').textContent = '';
      $('git-import-summary').textContent = '';
    }
    $('git-preview-import').onclick = async function () {
      var button = $('git-preview-import'); button.disabled = true; setGitNote('Reading repository files…'); clearGitPreview();
      try {
        var branch = $('git-branch-select').value;
        var result = await api('/api/rooms/' + roomId + '/git/import-preview?branch=' + encodeURIComponent(branch));
        activeGitPreview = result.previewId;
        $('git-import-preview').hidden = false;
        var summary = 'Branch ' + result.branch + ' · ' + result.files.length + ' file(s) ready · ' + result.availableSlots + ' workspace slots available. Existing room files will be kept.';
        if (result.tooManyFiles) summary += ' Preview is limited to 24 files per import.';
        if (result.truncatedBySize) summary += ' Some files were skipped because they exceeded the size limit.';
        if (!result.files.length) summary += ' No supported new files are available to import.';
        $('git-import-summary').textContent = summary;
        var items = $('git-import-files'); items.textContent = '';
        result.files.forEach(function (file) {
          var row = document.createElement('div'); row.className = 'git-import-file';
          var label = document.createElement('label'); var checkbox = document.createElement('input'); checkbox.type = 'checkbox'; checkbox.checked = true; checkbox.value = file.name;
          var text = document.createElement('span'); text.textContent = file.name + '  ·  ' + Math.ceil(file.size / 1024) + ' KB';
          checkbox.onchange = function () {
            var checked = items.querySelectorAll('input[type="checkbox"]:checked').length;
            $('git-import-confirm').disabled = checked === 0;
            $('git-import-summary').dataset.selected = String(checked);
            $('git-import-summary').textContent = 'Branch ' + result.branch + ' · ' + checked + ' of ' + result.files.length + ' file(s) selected · ' + result.availableSlots + ' workspace slots available. Existing room files will be kept.';
          };
          label.append(checkbox, text); row.appendChild(label); items.appendChild(row);
        });
        $('git-import-actions').hidden = !canManageGit || result.files.length === 0 || result.availableSlots === 0;
        setGitNote('Preview is ready. Import adds files without replacing existing workspace files.');
      } catch (err) { setGitNote(err.message, true); }
      finally { button.disabled = false; }
    };
    $('git-import-cancel').onclick = clearGitPreview;
    $('git-import-confirm').onclick = async function () {
      if (!activeGitPreview) return;
      var button = $('git-import-confirm'); button.disabled = true; setGitNote('Importing repository files…');
      try {
        var selectedPaths = Array.from($('git-import-files').querySelectorAll('input[type="checkbox"]:checked')).map(function (input) { return input.value; });
        if (!selectedPaths.length) { setGitNote('Select at least one file to import.', true); return; }
        var result = await api('/api/rooms/' + roomId + '/git/import', 'POST', { previewId: activeGitPreview, selectedPaths: selectedPaths });
        activeGitPreview = null;
        renderWorkspaceFiles(result.files);
        $('git-import-actions').hidden = true;
        $('git-import-summary').textContent = 'Imported ' + result.importedCount + ' file(s).' + (result.skippedCount ? ' ' + result.skippedCount + ' file(s) were skipped because the room already had them or reached its file limit.' : '');
        setGitNote('Repository files are now in the shared workspace.');
      } catch (err) { setGitNote(err.message, true); }
      finally { button.disabled = false; }
    };
    gitConnectForm.onsubmit = async function (event) {
      event.preventDefault();
      var submit = gitConnectForm.querySelector('button[type="submit"]');
      submit.disabled = true; setGitNote('Checking repository…');
      try {
        await api('/api/rooms/' + roomId + '/git/repository', 'POST', { repository: gitRepoInput.value.trim() });
        await refreshGitStatus();
      } catch (err) { setGitNote(err.message, true); }
      finally { submit.disabled = false; }
    };
    $('git-refresh').onclick = refreshGitStatus;
    gitDisconnectButton.onclick = function () {
      showAppDialog('Disconnect GitHub repository?', 'This removes the repository link from this room. It does not change the repository on GitHub.', 'Disconnect', async function () {
        try {
          await api('/api/rooms/' + roomId + '/git/repository', 'DELETE');
          gitRepoInput.value = '';
          renderGitStatus({ connected: false });
        } catch (err) { setGitNote(err.message, true); }
      });
    };
    var gitExplorerTab = document.querySelector('[data-explorer="git"]');
    var onGitExplorerTab = function () { refreshGitStatus(); };
    gitExplorerTab.addEventListener('click', onGitExplorerTab);

    function renderOpenTabs() {
      var tabs = $('editor-tab-list'); tabs.textContent = '';
      openTabs.forEach(function (file) {
        var tab = document.createElement('div'); tab.className = 'editor-tab' + (selectedFile && selectedFile.id === file.id ? ' active' : '');
        tab.setAttribute('role', 'tab'); tab.setAttribute('aria-selected', String(!!selectedFile && selectedFile.id === file.id)); tab.tabIndex = 0;
        var dot = document.createElement('span'); dot.className = 'file-dot'; dot.textContent = '●';
        var label = document.createElement('span'); label.className = 'editor-tab-name'; label.textContent = file.name;
        var close = document.createElement('button'); close.type = 'button'; close.className = 'editor-tab-close'; close.textContent = '×'; close.title = 'Close ' + file.name; close.setAttribute('aria-label', 'Close ' + file.name);
        tab.append(dot, label, close);
        tab.onclick = function () { openWorkspaceFile(file); renderWorkspaceFiles(roomFiles); };
        tab.onkeydown = function (event) { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); openWorkspaceFile(file); renderWorkspaceFiles(roomFiles); } };
        close.onclick = function (event) {
          event.stopPropagation();
          var wasActive = selectedFile && selectedFile.id === file.id;
          openTabs = openTabs.filter(function (item) { return item.id !== file.id; });
          if (wasActive) {
            var next = openTabs[openTabs.length - 1];
            if (next) openWorkspaceFile(next);
            else {
              clearActiveCursor();
              selectedFile = null;
              if (view) { view.destroy(); view = null; }
              $('editor-container').textContent = '';
              updateRunButton('unsupported');
            }
          }
          renderOpenTabs(); renderWorkspaceFiles(roomFiles);
        };
        tabs.appendChild(tab);
      });
    }
    var createForm = $('workspace-create-form');
    var createName = $('workspace-create-name');
    beginCreateFile = function () {
      if (!canEdit) return;
      setMobileView('files');
      createForm.hidden = false;
      createName.value = '';
      createName.focus();
    };
    $('workspace-add-file').onclick = beginCreateFile;
    createForm.onsubmit = async function (event) {
      event.preventDefault();
      var name = createName.value.trim();
      if (!name) { createName.focus(); return; }
      try {
        var result = await api('/api/rooms/' + roomId + '/files', 'POST', { name: name });
        createForm.hidden = true;
        renderWorkspaceFiles(result.files);
        openWorkspaceFile(result.file); renderWorkspaceFiles(roomFiles);
      } catch (err) { showAppDialog('Could not create file', err.message); createName.focus(); }
    };
    createName.onkeydown = function (event) { if (event.key === 'Escape') { event.preventDefault(); createForm.hidden = true; } };
    openWorkspaceFile = function (file) {
      if (!file || disposed) return;
      setMobileView('editor');
      if (selectedFile && selectedFile.id === file.id && view) { view.focus(); return; }
      clearActiveCursor();
      selectedFile = file;
      if (!openTabs.some(function (tab) { return tab.id === file.id; })) openTabs.push(file);
      openTabs = openTabs.map(function (tab) { return tab.id === file.id ? file : tab; });
      renderOpenTabs();
      if (view) view.destroy();
      var container = $('editor-container'); container.textContent = '';
      var textDoc = connection.get('documents', file.docId);
      var docPresence = connection.getDocPresence('documents', file.docId);
      activeDocPresence = docPresence;
      var presenceId = String(me.id) + ':' + (window.crypto && crypto.randomUUID ? crypto.randomUUID() : Date.now() + '-' + Math.random().toString(16).slice(2));
      localDocPresence = docPresence.create(presenceId);
      docPresence.on('error', function (err) { console.warn('Cursor presence error:', err && err.message || err); });
      docPresence.on('receive', function (id, value) {
        if (view !== thisView || id === presenceId) return;
        if (value === null) remoteCursors.delete(id);
        else if (value && Number.isSafeInteger(value.anchor) && Number.isSafeInteger(value.head)) {
          remoteCursors.set(id, {
            anchor: value.anchor,
            head: value.head,
            name: String(value.name || 'Collaborator').slice(0, 24),
            color: /^hsl\(\d{1,3}, 70%, 60%\)$/.test(value.color || '') ? value.color : 'hsl(160, 70%, 60%)',
          });
        }
        if (view === thisView) view.dispatch({ effects: setRemoteCursors.of(Array.from(remoteCursors.values())) });
      });
      docPresence.subscribe(function (err) { if (err) console.warn('Could not subscribe to cursor presence:', err.message); });
      var metaDoc = connection.get('room_meta', file.docId);
      var languageConf = new Compartment();
      var thisView;
      var pendingLocalOps = 0;
      thisView = new EditorView({
        parent: container,
        state: EditorState.create({
          doc: '',
          extensions: [
          lineNumbers(), history(),
          editabilityConf.of([EditorState.readOnly.of(!canEdit), EditorView.editable.of(canEdit)]),
          keymap.of([...defaultKeymap, ...historyKeymap]),
          themeConf.of(codeMirrorTheme(theme)),
          languageConf.of(LANGUAGES.javascript),
          EditorView.lineWrapping,
          remoteCursorField,
          EditorView.updateListener.of(function (update) {
            if (!selectedFile || selectedFile.id !== file.id || view !== thisView) return;
            if (update.docChanged || update.selectionSet) updateEditorPosition(thisView);
            if (update.docChanged && !applyingRemote) {
              var localContent = update.state.doc.toString();
              if (!saveLocalDraft(file, localContent)) {
                setStatus('local recovery copy unavailable');
                statusEl.title = 'The browser could not save a local recovery copy. Check available browser storage.';
              } else if (!navigator.onLine || connection.state !== 'connected') {
                setStatus('offline — draft saved on this device');
                statusEl.title = 'Your local recovery copy stays in this browser until the changes are confirmed as synced.';
              } else {
                setStatus('saving — local recovery copy kept');
                statusEl.title = 'The browser keeps a local recovery copy until ShareDB confirms these edits.';
              }
              var list = [];
              update.changes.iterChanges(function (fromA, toA, fromB, toB, inserted) {
                list.push({ fromA: fromA, toA: toA, text: inserted.toString() });
              });
              var op = ops.buildOp(list, update.startState.doc.length); // ONE op per transaction
              pendingLocalOps++;
              textDoc.submitOp(op, function (err) {
                pendingLocalOps = Math.max(0, pendingLocalOps - 1);
                if (err) syncError('submitOp error:', err, textDoc, thisView);
                else if (!disposed && pendingLocalOps === 0 && connection.state === 'connected' && view === thisView) {
                  var latest = view.state.doc.toString();
                  if (textDoc.data === latest) {
                    clearLocalDraft(file, latest);
                    setStatus('connected — synced'); statusEl.title = '';
                  }
                }
              });
            }
            if (!applyingRemote && (update.selectionSet || update.docChanged) && localDocPresence) {
              if (cursorPublishTimer) clearTimeout(cursorPublishTimer);
              cursorPublishTimer = setTimeout(function () {
                cursorPublishTimer = null;
                if (view !== thisView || !localDocPresence || !documentReady) return;
                var selection = view.state.selection.main;
                localDocPresence.submit({ anchor: selection.anchor, head: selection.head }, function (err) {
                  if (err) console.warn('Could not publish cursor position:', err.message);
                });
              }, 35);
            }
          }),
        ],
      }),
      });
      view = thisView;
      updateEditorPosition(thisView);
      var documentReady = false;

    textDoc.on('error', function (err) { syncError('textDoc error:', err); });
    metaDoc.on('error', function (err) { syncError('metaDoc error:', err); });
    connection.on('error', function (err) { syncError('connection error:', err); });

    textDoc.subscribe(function (err) {
      if (err) return syncError('subscribe error:', err);
      if (view !== thisView) return;
      applyingRemote = true;
      try { view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: textDoc.data || '' } }); }
      finally { applyingRemote = false; }
      documentReady = true;
      var recoveredDraft = readLocalDraft(file);
      if (recoveredDraft) {
        if (recoveredDraft.content === (textDoc.data || '')) clearLocalDraft(file, recoveredDraft.content);
        else offerDraftRecovery(file, recoveredDraft);
      }
      localDocPresence.submit({ anchor: view.state.selection.main.anchor, head: view.state.selection.main.head }, function (presenceErr) {
        if (presenceErr) console.warn('Could not publish initial cursor:', presenceErr.message);
      });
      if (pendingLineJump && pendingLineJump.fileId === file.id) {
        var targetLine = view.state.doc.line(Math.min(pendingLineJump.line, view.state.doc.lines));
        view.dispatch({ selection: { anchor: targetLine.from }, effects: EditorView.scrollIntoView(targetLine.from, { y: 'center' }) });
        view.focus();
        pendingLineJump = null;
      }
      setStatus('connected — synced');
    });
    textDoc.on('op', function (op, source) {
      if (source || (op && op.del) || view !== thisView) return;
      applyingRemote = true;
      try { view.dispatch({ changes: ops.opToChanges(op) }); }
      finally { applyingRemote = false; }
    });

    function applyLanguage() {
      var lang = (metaDoc.data && metaDoc.data.language) || 'javascript';
      if (view !== thisView) return;
      applyingRemoteLang = true;
      langSelect.value = lang;
      try {
        view.dispatch({ effects: languageConf.reconfigure(LANGUAGES[lang] || LANGUAGES.javascript) });
        if (selectedFile && selectedFile.id === file.id) {
          selectedFile.language = lang;
          updateRunButton(lang);
        }
      } finally { applyingRemoteLang = false; }
    }
      metaDoc.subscribe(function (err) { if (err) return syncError('meta subscribe error:', err); applyLanguage(); });
      metaDoc.on('op', function (op, source) { if (!source) applyLanguage(); });
    };

    if (selectedFile && !view) openWorkspaceFile(selectedFile);

    api('/api/rooms/' + roomId + '/files').then(function (result) { renderWorkspaceFiles(result.files); }).catch(function (err) { syncError('workspace files error:', err); });

    langSelect.onchange = function () {
      if (applyingRemoteLang) return;
      if (!selectedFile) return;
      var newLang = langSelect.value;
      if (newLang === selectedFile.language) return;
      api('/api/rooms/' + roomId + '/files/' + selectedFile.id, 'PATCH', { language: newLang, name: selectedFile.name }).then(function (result) { renderWorkspaceFiles(result.files); }).catch(function (err) { showChatNote(err.message); langSelect.value = selectedFile.language; });
    };

    var searchInput = $('workspace-search-input');
    var searchResults = $('workspace-search-results');
    var searchTimer = null;
    var searchSequence = 0;
    searchInput.oninput = function () {
      var query = searchInput.value.trim();
      clearTimeout(searchTimer);
      var sequence = ++searchSequence;
      searchResults.textContent = '';
      if (!query) { searchResults.textContent = 'Type to search all shared files.'; return; }
      searchResults.textContent = 'Searching…';
      searchTimer = setTimeout(async function () {
        try {
          var result = await api('/api/rooms/' + roomId + '/search?q=' + encodeURIComponent(query));
          if (sequence !== searchSequence) return;
          searchResults.textContent = '';
          if (!result.matches.length) { searchResults.textContent = 'No matches found.'; return; }
          result.matches.forEach(function (match) {
            var button = document.createElement('button'); button.type = 'button'; button.className = 'search-result';
            var fileName = document.createElement('span'); fileName.className = 'search-result-file'; fileName.textContent = match.name + ':' + match.line;
            var snippet = document.createElement('span'); snippet.className = 'search-result-location'; snippet.textContent = match.text;
            button.append(fileName, snippet);
            button.onclick = function () {
              var file = roomFiles.find(function (item) { return item.id === match.fileId; });
              if (!file) return;
              pendingLineJump = { fileId: file.id, line: match.line };
              openWorkspaceFile(file);
              renderWorkspaceFiles(roomFiles);
            };
            searchResults.appendChild(button);
          });
          if (result.truncated) { var note = document.createElement('div'); note.className = 'explorer-note'; note.textContent = 'Showing the first 100 matches.'; searchResults.appendChild(note); }
        } catch (err) {
          if (sequence !== searchSequence) return;
          searchResults.textContent = err.message;
        }
      }, 220);
    };
    searchResults.textContent = 'Type to search all shared files.';

    var onNetworkOffline = function () {
      var draft = selectedFile && readLocalDraft(selectedFile);
      setStatus(draft ? 'offline — draft saved on this device' : 'offline');
      statusEl.title = draft ? 'A recovery copy is saved in this browser.' : 'Waiting for the network connection to return.';
    };
    var onNetworkOnline = function () { setStatus('reconnecting…'); statusEl.title = 'Waiting for the collaboration connection to return.'; };
    window.addEventListener('offline', onNetworkOffline);
    window.addEventListener('online', onNetworkOnline);
    connection.on('state', function (state) {
      if (state !== 'connected') {
        var draft = selectedFile && readLocalDraft(selectedFile);
        setStatus(draft ? 'offline — draft saved on this device' : state);
      } else if (!view) setStatus('connected — opening file');
      else {
        var savedDraft = selectedFile && readLocalDraft(selectedFile);
        setStatus(savedDraft ? 'connected — local draft kept' : 'connected — synced');
      }
    });
  }

  return {
    setTheme: function (mode) { if (view) view.dispatch({ effects: themeConf.reconfigure(codeMirrorTheme(mode)) }); },
    dispose: function () {
      disposed = true;
      clearActiveCursor();
      commandPalette.hidden = true;
      $('app-dialog').hidden = true;
      try { if (presenceSocket) presenceSocket.close(); } catch (e) { /* ignore */ }
      clearActiveCursor(function () {
        try { if (shareSocket) shareSocket.close(); } catch (e) { /* ignore */ }
        try { if (connection) connection.close(); } catch (e) { /* ignore */ }
      });
      try { if (view) view.destroy(); } catch (e) { /* ignore */ }
      document.removeEventListener('keydown', onRoomShortcut);
      window.removeEventListener('offline', onNetworkOffline);
      window.removeEventListener('online', onNetworkOnline);
      gitExplorerTab.removeEventListener('click', onGitExplorerTab);
      $('editor-container').textContent = '';
    },
  };
}

// ------------------------------------------------------------------ boot
setAuthMode('login');
route();
