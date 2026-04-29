// Crypto for PageGate. Two paths, picked per tier (see tiers.js / TIERS.md):
//
//   1. Password-derived (Tier 1, anonymous):
//      Page key is derived from the page password via PBKDF2 + a per-page
//      salt. Server can never decrypt without the password — the password
//      is bcrypt-hashed for verification but never stored in a recoverable
//      form. Forgotten password = unrecoverable. Genuinely zero-knowledge.
//
//   2. Master-key wrapped (Tier 2 + Tier 3):
//      Page key is randomly generated, then wrapped (encrypted) with a
//      server master key (PAGE_KEY_MASTER env var). The wrapped key is
//      stored in the DB row; the master key never leaves the server. This
//      means the server *can* decrypt at any time — that is the whole
//      point: it's what makes account-driven password reset and Pro
//      edit-in-place possible. Honest copy lives in the README and PRD.
//
// File envelope on disk is the same for both paths: salt(32) || iv(12) ||
// tag(16) || ciphertext. For path (1), salt is the per-page PBKDF2 salt
// used to derive the page key from the password. For path (2), salt is
// random filler — unused for key derivation but kept in the envelope so
// both paths share one storage format. The `wrapped_key` DB column is the
// real authority for path (2).

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const SALT_LENGTH = 32;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const PBKDF2_ITERATIONS = 100_000;

// === Master key (path 2) ===
//
// Read once at startup from PAGE_KEY_MASTER. Accept either:
//   - 64-hex (32 bytes hex-encoded), or
//   - 44-char base64 (32 bytes base64-encoded)
// Surface a clear error if it's missing or malformed when needed.
let cachedMasterKey = null;
function loadMasterKey() {
  if (cachedMasterKey) return cachedMasterKey;
  const raw = process.env.PAGE_KEY_MASTER;
  if (!raw) {
    throw new Error('PAGE_KEY_MASTER is not set — required for account/Pro page encryption');
  }
  let buf;
  if (/^[0-9a-fA-F]{64}$/.test(raw)) {
    buf = Buffer.from(raw, 'hex');
  } else {
    try { buf = Buffer.from(raw, 'base64'); } catch { buf = null; }
  }
  if (!buf || buf.length !== KEY_LENGTH) {
    throw new Error('PAGE_KEY_MASTER must be 32 bytes (64 hex chars or 44 base64 chars)');
  }
  cachedMasterKey = buf;
  return buf;
}

function hasMasterKey() {
  return !!process.env.PAGE_KEY_MASTER;
}

// === Path 1: password-derived ===

function derivePasswordKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256');
}

// Encrypts `plaintext` (string|Buffer) with a key derived from `password`.
// Returns { blob, saltBase64 } — caller persists both: blob to disk,
// saltBase64 to the DB (`encryption_salt` column).
function encryptWithPassword(plaintext, password) {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const key = derivePasswordKey(password, salt);
  const blob = sealWithKey(plaintext, key, salt);
  return { blob, saltBase64: salt.toString('base64') };
}

function decryptWithPassword(blob, password, saltBase64) {
  const salt = Buffer.from(saltBase64, 'base64');
  const key = derivePasswordKey(password, salt);
  return openWithKey(blob, key);
}

// === Path 2: master-key wrapped ===

// Generate a random per-page key (32 bytes).
function generatePageKey() {
  return crypto.randomBytes(KEY_LENGTH);
}

// Wrap a page key with the server master key. Returns base64 of
// iv(12) || tag(16) || ct(32). Stored in the `wrapped_key` DB column.
function wrapPageKey(pageKey) {
  const master = loadMasterKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, master, iv);
  const ct = Buffer.concat([cipher.update(pageKey), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]).toString('base64');
}

function unwrapPageKey(wrappedBase64) {
  const master = loadMasterKey();
  const buf = Buffer.from(wrappedBase64, 'base64');
  const iv = buf.subarray(0, IV_LENGTH);
  const tag = buf.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const ct = buf.subarray(IV_LENGTH + TAG_LENGTH);
  const decipher = crypto.createDecipheriv(ALGORITHM, master, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

// Encrypt with a raw page key. Same envelope shape as path (1) so the
// storage layer doesn't have to branch — salt is random filler here.
function encryptWithKey(plaintext, pageKey) {
  const filler = crypto.randomBytes(SALT_LENGTH);
  return sealWithKey(plaintext, pageKey, filler);
}

function decryptWithKey(blob, pageKey) {
  return openWithKey(blob, pageKey);
}

// === Internals shared by both paths ===

function sealWithKey(plaintext, key, saltField) {
  const buf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf-8');
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const ct = Buffer.concat([cipher.update(buf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([saltField, iv, tag, ct]);
}

function openWithKey(blob, key) {
  const iv = blob.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const tag = blob.subarray(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
  const ct = blob.subarray(SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf-8');
}

module.exports = {
  // path 1
  encryptWithPassword,
  decryptWithPassword,
  // path 2
  generatePageKey,
  wrapPageKey,
  unwrapPageKey,
  encryptWithKey,
  decryptWithKey,
  // utilities
  hasMasterKey,
  loadMasterKey,
  // constants (exposed for tests)
  KEY_LENGTH,
};
