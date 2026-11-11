# Collab Editor — Phase 8 (room roles and member management)

Everything from Phases 1–6, plus real accounts and access control.

## What changed
| Area | Before | Now |
|---|---|---|
| Login | any name, no password | username + password (scrypt hashed), rate-limited |
| Account recovery | none | verified email links; reset tokens are random, single-use, and expire after one hour |
| Two-factor auth | none | authenticator-app TOTP with a scannable QR code plus one-time recovery codes |
| Session | token in the URL / sessionStorage | HttpOnly + SameSite=Strict cookie; page JS never sees it; logout revokes it everywhere |
| Rooms | anyone with the room id | rooms have owner + members; join only by invite link; owner can reset the link |
| ShareDB | any client could read/write any doc | every message checked against room membership; queries, deletes and client-side creates are blocked |
| Limits | none | per-connection message/byte rate, max edit size (1M chars), max document (2M chars), connection caps, sign-up/login/room/run limits |
| Secrets | hardcoded default JWT secret, no Redis/DB passwords | `npm run setup` generates random ones; production refuses to start without them; Redis/Postgres have passwords and listen on 127.0.0.1 only |
| Web | no headers | CSP, nosniff, no-framing, Origin checks on POST and WebSocket, HSTS when secure |
| Crashes | any bad message could kill the process | crash handlers, safe JSON parsing, optional supervisor (`npm run start:supervised`) |
| Safety net | — | at startup the server tests that its own access rules block an outsider and **refuses to start** if they don't |

## Setup (Ubuntu/WSL, in this folder)
```bash
# old containers use the same ports and have no passwords: stop them
docker stop redis-collab collab-postgres

npm run setup            # creates .env with random secrets (never overwrites)
docker compose up -d     # Redis + Postgres WITH passwords, localhost only
docker pull node:20-alpine && docker pull python:3.12-alpine   # once, for Run

npm install
npm run build
npm start                # expect: "access-control self-test passed"
```
Open http://localhost:8080. If your Windows browser can't reach it, add `HOST=0.0.0.0` to `.env`
(that exposes it on your network — fine at home, not on public WiFi).

## Workspace interface

The room screen has an Explorer, shared file tabs, editor, run output, and a right-side Chat/AI panel.
Room members can create, open, rename, and delete shared files; **Ctrl+P** opens quick file/command
search; the Explorer Search panel searches text across shared files. The Git panel can connect a
public GitHub repository and show its default branch and files in the latest remote commit. The room
owner can choose a branch, preview and select supported text files to import; folder paths are preserved,
existing room files are never overwritten, and each import is limited to 24 files and 8 MB total. Binary/unsupported files and
files over 500 KB are skipped. Private repositories need a later GitHub authorization step. The app does
not yet compare workspace changes against Git or commit/push changes.
The **Members** button shows everyone in a room. Owners can remove an editor; this revokes that room's
live connections and rotates the invite link. Editors can leave a room. Room ownership cannot currently
be transferred, so the owner cannot leave. Owners can also set each non-owner member to **Can edit** or
**Can view**. Viewers can read and select code and see chat, but cannot edit files, create/rename/delete
files, send/delete chat messages, or run code. Role changes update the target member's editor in place,
show a centered notice, and leave the shared document connection open.
When two members open the same file, each sees the other member's named, colored cursor and selected
text; cursor positions follow document edits in real time. Cursor subscriptions and updates are checked
against room membership by the server.
The AI tab is a placeholder and does not send code to an AI provider. Chat is shared in the room, and
users can delete their own persisted messages.

### File history and restore

Use the clock icon beside a file in Explorer to open its saved versions. Editors can save a manual checkpoint
before a risky change, preview a saved version, and restore it. Restoring first saves the current contents
and then publishes the restored contents through ShareDB, so collaborators receive the change live. Viewers
can preview history but cannot create checkpoints or restore. Current file contents are automatically written
to Postgres about every five seconds while the server is running. Changed files also get a history version
about every ten seconds during active editing, with an extra checkpoint before an edit burst. History is
stored in Postgres with the room data and is limited to 200 versions / 40 MB per file and 2,000 versions /
200 MB per room. Older versions are
pruned automatically. Deleting a workspace file still permanently deletes that file and its history; deleted
file recovery is not part of this feature. This is version recovery, not a tested off-site database backup.

2FA setup displays a QR code that can be scanned by Microsoft Authenticator, Google Authenticator,
or another TOTP-compatible app. A manual setup key is also available if scanning is not possible.

### Email delivery for verification and password reset

Configure these values in `.env` using an SMTP account you control. Set `APP_BASE_URL` to the public
HTTPS URL when deployed. Do not commit `.env` or share SMTP credentials.

```dotenv
APP_BASE_URL=https://editor.example.com
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_SECURE=0
SMTP_USER=your-smtp-username
SMTP_PASS=your-smtp-password
SMTP_FROM=Collab Editor <no-reply@example.com>
```

Restart the app after changing `.env`. Without SMTP configured, users can still create accounts and
use authenticator 2FA, but email verification and password reset links cannot be delivered.
Existing accounts can add a recovery email under **Account security** and verify it from the email link.
2FA secrets are encrypted in PostgreSQL; preserve `MFA_ENCRYPTION_KEY` (or, on older `.env` files,
the `JWT_SECRET` used as its fallback) or those authenticators cannot be recovered after a key change.

Old data (rooms like `room1`, old chat) is NOT migrated: Postgres is a fresh volume and old
rooms have no owner, so nobody can open them.

## Verify it yourself (do these before trusting it)
Use two browsers (e.g. normal + incognito), users **alice** and **bob**.
1. alice signs up, creates a room, types code. bob signs up, pastes alice's room URL
   (`#/room/ID`) -> must show "You do not have access".
2. alice copies the invite link; bob opens it -> joins; both edit; chat works.
3. Open the same file in both accounts -> each should see the other person's named caret; select text
   in one window and confirm the other sees the selection move as code is edited.
4. In the Git panel, connect a public GitHub repository -> confirm its default branch and latest
   commit's changed files appear. Try a private repository -> it should explain that authorization is
   not available in this first Git step.
5. alice resets the invite -> the old link must fail ("invalid or has been reset").
6. As alice, set bob to **Can view** in Members. Confirm bob can read and select code but cannot edit,
   create/rename/delete files, send/delete chat, or run code. Change bob back to **Can edit** and
   confirm he must reopen the room before editing resumes.
7. As **bob in an unrelated room**, in DevTools Console (use alice's room id):
   ```js
   var ws = new WebSocket('ws://localhost:8080/sharedb');
   ws.onmessage = e => console.log(e.data);
   ws.onopen = () => ws.send(JSON.stringify({a:'s', c:'documents', d:'ALICES_ROOM_ID'}));
   ```
   -> the reply must contain an error ("No access to this room"), never alice's text.
   **If you ever see her code, stop and tell me.**
8. Log out in one tab -> other tabs for that user drop to the login screen.
9. Wrong password 11 times -> "Too many attempts".
10. Run `while True: pass` and `import urllib.request; urllib.request.urlopen("http://example.com")` -> both contained.
11. `npm test` -> all tests pass.

## Going public (HTTPS)
The app does not do TLS itself. Put Caddy in front (`Caddyfile` included), set in `.env`:
`NODE_ENV=production`, `TRUST_PROXY=1`, `ALLOWED_ORIGINS=https://your.domain`, and open only
ports 80/443 on the firewall (never 8080, 5432, 6379).

Remote collaborators connect over WebSockets. Behind Caddy, use HTTPS/WSS so traffic is encrypted in
transit; the current local `http://127.0.0.1:8080` setup is only for local development.

## Company confidentiality status

This is still a prototype, not ready for confidential company source code. PostgreSQL stores documents
and chat as plaintext, and the app server can read and process code. TLS protects traffic in transit;
it does not encrypt stored documents. Before a company deployment, add encrypted backups and storage,
audit logs, monitoring, retention/deletion controls, organization and user administration, SSO, a security
review and penetration test, and isolate code execution from the application host. The current Docker
code runner is a development sandbox, not an adequate boundary for a public multi-tenant service.

## Honest limits (not done)
- **Not run against real ShareDB/Postgres in my environment.** Unit tests cover the rules; the
  startup self-test covers the access hook. Anything else may need a fix on first run.
- No SSO, account deletion, organization administration, audit log, or enterprise policy controls.
- GitHub supports public repository status and safe, additive import of supported text files; there is no local working-tree comparison, private-repository authorization, commit, or push yet.
- Anyone with an active invite link can join (max 50 members). No organization groups, owner transfer, or room deletion.
- ShareDB keeps every edit and every room in memory; a long-running public server will grow until restarted.
- Rate limits live in memory: reset on restart and are not shared across instances.
- Live chat/presence and ShareDB sync are single-instance safe only.
- Run executes on the same machine as the app. Docker access = host-level power; for public use run code on a separate machine or sandbox runtime (gVisor/Firecracker).
- CSP still allows inline styles and any ws:/wss: host; the Origin check allows requests with no Origin header (non-browser clients).
- No audit log, no monitoring/alerting.
- No AI yet (planned last, behind a provider interface).
