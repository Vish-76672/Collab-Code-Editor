// sandbox.js -- Phase 5: run user code inside a throwaway Docker container.
//
// Every run gets a FRESH container that is destroyed afterwards (--rm).
// Hardening flags used on every run:
//   --network none           no network at all (can't phone home / hit Redis, Postgres)
//   --memory/--memory-swap   hard RAM cap, no swap
//   --cpus                   CPU cap
//   --pids-limit             stops fork bombs
//   --read-only + --tmpfs    read-only root FS, small non-executable scratch space
//   --cap-drop ALL           no Linux capabilities
//   no-new-privileges        can't gain privileges via setuid binaries
//   --user 65534             runs as "nobody", never root
//   code mounted read-only   the run can't modify its own source
// Plus a wall-clock timeout (container is force-killed) and an output cap.
//
// Only languages with small Alpine images are enabled, to keep disk usage low.
// Add compiled languages (C++, Java, Rust) by adding an entry to LANGS --
// their images are much larger (500MB-1GB), so enable them deliberately.

const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const LANGS = {
  javascript: { image: 'node:20-alpine', file: 'main.js', cmd: ['node', '/work/main.js'] },
  python: { image: 'python:3.12-alpine', file: 'main.py', cmd: ['python3', '/work/main.py'] },
};

const TIMEOUT_MS = 5000;
const MAX_OUTPUT_BYTES = 64 * 1024;
const MAX_CODE_BYTES = 100 * 1024;
const MAX_CONCURRENT_RUNS = 2;

let running = 0;

const SUPPORTED = Object.keys(LANGS);

function killContainer(name) {
  const k = spawn('docker', ['kill', name], { stdio: 'ignore' });
  k.on('error', () => {});
}

async function runCode(language, code) {
  const cfg = LANGS[language];
  if (!cfg) {
    return { error: `Running "${language}" isn't supported yet. Supported: ${SUPPORTED.join(', ')}.` };
  }
  if (Buffer.byteLength(code, 'utf8') > MAX_CODE_BYTES) {
    return { error: `Code is too large to run (limit ${MAX_CODE_BYTES / 1024} KB).` };
  }
  if (running >= MAX_CONCURRENT_RUNS) {
    return { error: 'Execution pool is busy. Try again in a few seconds.' };
  }

  running++;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'run-'));
  const name = 'sbx-' + crypto.randomBytes(6).toString('hex');

  try {
    fs.chmodSync(dir, 0o755);
    const filePath = path.join(dir, cfg.file);
    fs.writeFileSync(filePath, code, { mode: 0o644 });

    const args = [
      'run', '--rm', '--name', name,
      '--network', 'none',
      '--memory', '128m', '--memory-swap', '128m',
      '--cpus', '0.5',
      '--pids-limit', '64',
      '--read-only',
      '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m',
      '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges',
      '--user', '65534:65534',
      '-v', `${dir}:/work:ro`,
      cfg.image, ...cfg.cmd,
    ];

    return await new Promise((resolve) => {
      const started = Date.now();
      let stdout = '';
      let stderr = '';
      let bytes = 0;
      let truncated = false;
      let timedOut = false;
      let settled = false;

      const child = spawn('docker', args, { stdio: ['ignore', 'pipe', 'pipe'] });

      const timer = setTimeout(() => {
        timedOut = true;
        killContainer(name);
      }, TIMEOUT_MS);

      function collect(which) {
        return (chunk) => {
          if (truncated) return;
          const s = chunk.toString('utf8');
          bytes += chunk.length;
          if (bytes > MAX_OUTPUT_BYTES) {
            truncated = true;
            killContainer(name);
            return;
          }
          if (which === 'out') stdout += s; else stderr += s;
        };
      }
      child.stdout.on('data', collect('out'));
      child.stderr.on('data', collect('err'));

      function finish(result) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(result);
      }

      child.on('error', (err) => {
        finish({ error: `Could not start Docker (${err.code || err.message}). Is the Docker daemon running?` });
      });

      child.on('close', (exitCode) => {
        finish({
          stdout, stderr, exitCode, timedOut, truncated,
          durationMs: Date.now() - started,
        });
      });
    });
  } finally {
    running--;
    fs.rm(dir, { recursive: true, force: true }, () => {});
  }
}

module.exports = { runCode, SUPPORTED };
