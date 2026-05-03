// Crypto round-trip tests. Runs without a server. Exercises both paths
// in server/crypto.js — password-derived (Tier 1) and master-key wrapped
// (Tier 2/3).

const crypto = require('crypto');
const assert = require('assert');

// PAGE_KEY_MASTER must be set before crypto.js is required so the cached
// loader sees it the first time it's asked. Use a deterministic 32-byte
// hex value for the test.
process.env.PAGE_KEY_MASTER = crypto.randomBytes(32).toString('hex');

const {
  encryptWithPassword,
  decryptWithPassword,
  generatePageKey,
  wrapPageKey,
  unwrapPageKey,
  encryptWithKey,
  decryptWithKey,
  loadMasterKey,
  KEY_LENGTH,
} = require('../server/crypto');

const checks = [];
function check(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    checks.push({ name, ok: true });
  } catch (err) {
    console.log(`  ✗ ${name}\n      ${err.message}`);
    checks.push({ name, ok: false, err: err.message });
  }
}

console.log('crypto round-trip checks:\n');

const sample = '<!doctype html><h1>hello world</h1>';

check('Path 1 — password-derived round trip', () => {
  const { blob, saltBase64 } = encryptWithPassword(sample, 'correct horse');
  const out = decryptWithPassword(blob, 'correct horse', saltBase64);
  assert.strictEqual(out, sample);
});

check('Path 1 — wrong password fails to decrypt', () => {
  const { blob, saltBase64 } = encryptWithPassword(sample, 'correct horse');
  assert.throws(() => decryptWithPassword(blob, 'wrong password', saltBase64));
});

check('Path 1 — different salts produce different ciphertexts', () => {
  const a = encryptWithPassword(sample, 'pw');
  const b = encryptWithPassword(sample, 'pw');
  assert.notDeepStrictEqual(a.blob, b.blob);
});

check('Master key loads with the right length', () => {
  const k = loadMasterKey();
  assert.strictEqual(k.length, KEY_LENGTH);
});

check('Path 2 — wrap then unwrap recovers the page key', () => {
  const pageKey = generatePageKey();
  const wrapped = wrapPageKey(pageKey);
  const recovered = unwrapPageKey(wrapped);
  assert.strictEqual(Buffer.compare(pageKey, recovered), 0);
});

check('Path 2 — wrapped-key encrypt/decrypt round trip', () => {
  const pageKey = generatePageKey();
  const blob = encryptWithKey(sample, pageKey);
  const out = decryptWithKey(blob, pageKey);
  assert.strictEqual(out, sample);
});

check('Path 2 — wrong page key fails to decrypt', () => {
  const pageKey = generatePageKey();
  const blob = encryptWithKey(sample, pageKey);
  const wrong = generatePageKey();
  assert.throws(() => decryptWithKey(blob, wrong));
});

check('Path 2 — full lifecycle: generate → wrap → store → unwrap → decrypt', () => {
  // Simulates what the upload route does: generate a per-page key, wrap
  // it, persist the wrapped form (here just a string), then later unwrap
  // to decrypt.
  const pageKey = generatePageKey();
  const blob = encryptWithKey(sample, pageKey);
  const wrappedForDb = wrapPageKey(pageKey);
  // ... time passes, original pageKey is gone, only wrappedForDb remains
  const recovered = unwrapPageKey(wrappedForDb);
  const out = decryptWithKey(blob, recovered);
  assert.strictEqual(out, sample);
});

const failed = checks.filter(c => !c.ok);
console.log();
if (failed.length === 0) {
  console.log(`✅ All ${checks.length} crypto checks passed.`);
  process.exit(0);
} else {
  console.log(`❌ ${failed.length} of ${checks.length} crypto checks failed:`);
  for (const f of failed) console.log(`   • ${f.name}: ${f.err}`);
  process.exit(1);
}
