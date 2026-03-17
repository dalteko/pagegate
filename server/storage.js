const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const UPLOADS_DIR = process.env.UPLOADS_DIR || path.join(__dirname, '..', 'uploads');
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const SALT_LENGTH = 32;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const PBKDF2_ITERATIONS = 100_000;

function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256');
}

function encrypt(plaintext, password) {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);
  const key = deriveKey(password, salt);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Pack as: salt (32) + iv (12) + tag (16) + ciphertext
  return { blob: Buffer.concat([salt, iv, tag, encrypted]), salt };
}

function decrypt(blob, password, salt) {
  const iv = blob.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const tag = blob.subarray(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
  const ciphertext = blob.subarray(SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
  const key = deriveKey(password, salt);
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf-8');
}

function injectViewport(html) {
  if (/name\s*=\s*["']viewport["']/i.test(html)) return html;
  const meta = '<meta name="viewport" content="width=device-width, initial-scale=1">';
  const headMatch = html.match(/<head[^>]*>/i);
  if (headMatch) {
    return html.replace(headMatch[0], headMatch[0] + '\n' + meta);
  }
  return meta + '\n' + html;
}

module.exports = {
  // Encrypted save — returns the salt (needed for DB storage)
  savePageEncrypted(pageId, buffer, password) {
    const html = injectViewport(buffer.toString('utf-8'));
    const { blob, salt } = encrypt(html, password);
    fs.writeFileSync(path.join(UPLOADS_DIR, `${pageId}.bin`), blob);
    return salt.toString('base64');
  },

  // Encrypted read — needs the password and salt
  readPageEncrypted(pageId, password, saltBase64) {
    const filePath = path.join(UPLOADS_DIR, `${pageId}.bin`);
    if (!fs.existsSync(filePath)) return null;
    const blob = fs.readFileSync(filePath);
    const salt = Buffer.from(saltBase64, 'base64');
    return decrypt(blob, password, salt);
  },

  // Legacy plaintext read (for old unencrypted uploads)
  readPagePlaintext(pageId) {
    const filePath = path.join(UPLOADS_DIR, `${pageId}.html`);
    if (!fs.existsSync(filePath)) return null;
    return fs.readFileSync(filePath, 'utf-8');
  },

  deletePage(pageId) {
    // Clean up both encrypted and legacy plaintext files
    for (const ext of ['.bin', '.html']) {
      const filePath = path.join(UPLOADS_DIR, `${pageId}${ext}`);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    }
  },
};
