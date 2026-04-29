// Smoke test: boots pagegate against a temp data dir, hits the routes that
// matter most, and exits non-zero if any of them break. Run via `npm test`.
//
// What "matters most" (per product owner): homepage loads, login is gated,
// uploading + viewing + verifying a page works end-to-end, Stripe checkout
// route is wired up. Runs without Clerk/Stripe (PRO_ENABLED=false) — the
// free-tier paths are what we exercise here.

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

const PORT = process.env.SMOKE_PORT || 4567;
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pagegate-smoke-'));
const env = {
  ...process.env,
  PORT: String(PORT),
  DATA_DIR: path.join(tmpDir, 'data'),
  UPLOADS_DIR: path.join(tmpDir, 'uploads'),
  PRO_ENABLED: 'false',
};

const child = spawn('node', ['server/index.js'], {
  env,
  stdio: ['ignore', 'pipe', 'pipe'],
  cwd: path.join(__dirname, '..'),
});

let serverLog = '';
child.stdout.on('data', (d) => { serverLog += d.toString(); });
child.stderr.on('data', (d) => { serverLog += d.toString(); });
child.on('exit', (code) => {
  if (code !== null && code !== 0 && !shuttingDown) {
    console.error(`Server exited unexpectedly with code ${code}`);
    console.error(serverLog);
    process.exit(2);
  }
});

let shuttingDown = false;
function shutdown(exitCode) {
  shuttingDown = true;
  try { child.kill('SIGTERM'); } catch {}
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  process.exit(exitCode);
}

const base = `http://localhost:${PORT}`;

async function waitForServer() {
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(`${base}/`);
      if (r.status < 500) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 250));
  }
  console.error('Server failed to start within 15s. Logs:\n' + serverLog);
  shutdown(2);
}

const checks = [];
async function check(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    checks.push({ name, ok: true });
  } catch (err) {
    console.log(`  ✗ ${name}\n      ${err.message}`);
    checks.push({ name, ok: false, err: err.message });
  }
}

function assertStatus(actual, expected, label) {
  if (actual !== expected) throw new Error(`${label}: expected ${expected}, got ${actual}`);
}

(async () => {
  console.log('Booting pagegate against a temp DB…');
  await waitForServer();
  console.log('Running smoke checks:\n');

  await check('Homepage loads', async () => {
    const r = await fetch(`${base}/`);
    assertStatus(r.status, 200, 'GET /');
    const html = await r.text();
    if (!/<!doctype html/i.test(html)) throw new Error('homepage did not return HTML');
  });

  await check('Dashboard page loads', async () => {
    const r = await fetch(`${base}/dashboard`);
    assertStatus(r.status, 200, 'GET /dashboard');
  });

  await check('Login is required for /api/me (returns 401)', async () => {
    const r = await fetch(`${base}/api/me`);
    assertStatus(r.status, 401, 'GET /api/me');
  });

  let pageId;
  const password = 'smoke-test-password';

  await check('Upload a page (free tier)', async () => {
    const form = new FormData();
    form.append('file', new Blob(['<!doctype html><h1>smoke</h1>'], { type: 'text/html' }), 'smoke.html');
    form.append('password', password);
    const r = await fetch(`${base}/api/upload`, { method: 'POST', body: form });
    if (r.status !== 201) {
      const body = await r.text();
      throw new Error(`POST /api/upload: expected 201, got ${r.status} (${body.slice(0, 200)})`);
    }
    const j = await r.json();
    if (!j.pageId) throw new Error('no pageId in response');
    pageId = j.pageId;
  });

  await check('Upload rejects mismatched confirm-password (400)', async () => {
    const form = new FormData();
    form.append('file', new Blob(['<!doctype html><h1>nope</h1>'], { type: 'text/html' }), 'nope.html');
    form.append('password', 'one');
    form.append('confirmPassword', 'two');
    const r = await fetch(`${base}/api/upload`, { method: 'POST', body: form });
    assertStatus(r.status, 400, 'POST /api/upload (mismatched confirm)');
  });

  await check('Visit uploaded page URL (password prompt loads)', async () => {
    const r = await fetch(`${base}/${pageId}`);
    assertStatus(r.status, 200, `GET /${pageId}`);
  });

  await check('Wrong password is rejected (401)', async () => {
    const r = await fetch(`${base}/api/verify/${pageId}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: 'definitely-wrong' }),
    });
    assertStatus(r.status, 401, `POST /api/verify/${pageId} (wrong pw)`);
  });

  await check('Correct password unlocks the page', async () => {
    const r = await fetch(`${base}/api/verify/${pageId}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password }),
    });
    assertStatus(r.status, 200, `POST /api/verify/${pageId} (right pw)`);
    const j = await r.json();
    if (!j.html.includes('<h1>smoke</h1>')) throw new Error('decrypted HTML did not match what we uploaded');
  });

  await check('Stripe checkout route is wired up (no 5xx)', async () => {
    const r = await fetch(`${base}/api/checkout`, { method: 'POST' });
    if (r.status >= 500) {
      const body = await r.text();
      throw new Error(`POST /api/checkout returned ${r.status}: ${body.slice(0, 200)}`);
    }
  });

  await check('Unknown URL returns 404 (does not crash)', async () => {
    const r = await fetch(`${base}/this-page-does-not-exist`);
    assertStatus(r.status, 404, 'GET /this-page-does-not-exist');
  });

  const failed = checks.filter((c) => !c.ok);
  console.log();
  if (failed.length === 0) {
    console.log(`✅ All ${checks.length} checks passed.`);
    shutdown(0);
  } else {
    console.log(`❌ ${failed.length} of ${checks.length} checks failed:`);
    for (const f of failed) console.log(`   • ${f.name}: ${f.err}`);
    console.log('\nServer log:\n' + serverLog);
    shutdown(1);
  }
})().catch((err) => {
  console.error('Smoke test crashed:', err);
  shutdown(2);
});
