// node supervise.js -- restarts the server if it crashes (gives up after 5 crashes in 60s)
const { spawn } = require('child_process');
let stopping = false;
let crashes = [];
let child = null;
function launch() {
  child = spawn(process.execPath, ['--env-file=.env', 'server.js'], { stdio: 'inherit' });
  child.on('exit', (code) => {
    if (stopping || code === 0) process.exit(code || 0);
    const now = Date.now();
    crashes = crashes.filter((t) => now - t < 60000).concat(now);
    if (crashes.length > 5) { console.error('[supervisor] crashing too often, giving up.'); process.exit(1); }
    console.error(`[supervisor] server exited with code ${code}; restarting in 2s...`);
    setTimeout(launch, 2000);
  });
}
['SIGINT', 'SIGTERM'].forEach((s) => process.on(s, () => { stopping = true; if (child) child.kill(s); }));
launch();
