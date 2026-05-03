// Pure file I/O for page blobs. All crypto lives in crypto.js — this module
// only writes and reads bytes. Routes compose: encrypt → savePageBlob, then
// readPageBlob → decrypt.
//
// Two on-disk file extensions are recognized:
//   - {pageId}.bin   — encrypted blob (current and going forward)
//   - {pageId}.html  — legacy plaintext (pre-encryption uploads)

const fs = require('fs');
const path = require('path');

const UPLOADS_DIR = process.env.UPLOADS_DIR || path.join(__dirname, '..', 'uploads');
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

function blobPath(pageId) {
  return path.join(UPLOADS_DIR, `${pageId}.bin`);
}

function legacyPlaintextPath(pageId) {
  return path.join(UPLOADS_DIR, `${pageId}.html`);
}

// HTML pages uploaded without a viewport meta render badly on mobile.
// Inject one if it's missing. Side effect of upload only — we never
// modify on the read path.
function injectViewport(html) {
  if (/name\s*=\s*["']viewport["']/i.test(html)) return html;
  const meta = '<meta name="viewport" content="width=device-width, initial-scale=1">';
  const headMatch = html.match(/<head[^>]*>/i);
  if (headMatch) return html.replace(headMatch[0], headMatch[0] + '\n' + meta);
  return meta + '\n' + html;
}

module.exports = {
  // Normalize an upload buffer into HTML with a viewport meta. Caller then
  // hands the result to crypto.* and persists with savePageBlob.
  prepareHtml(buffer) {
    return injectViewport(buffer.toString('utf-8'));
  },

  // Persist an already-encrypted blob to disk.
  savePageBlob(pageId, blob) {
    fs.writeFileSync(blobPath(pageId), blob);
  },

  // Read the encrypted blob back. Returns null if missing.
  readPageBlob(pageId) {
    const p = blobPath(pageId);
    if (!fs.existsSync(p)) return null;
    return fs.readFileSync(p);
  },

  // Legacy plaintext read for any pre-encryption uploads still on disk.
  readPagePlaintext(pageId) {
    const p = legacyPlaintextPath(pageId);
    if (!fs.existsSync(p)) return null;
    return fs.readFileSync(p, 'utf-8');
  },

  // Delete both the encrypted blob and any lingering legacy plaintext.
  deletePage(pageId) {
    for (const p of [blobPath(pageId), legacyPlaintextPath(pageId)]) {
      if (fs.existsSync(p)) fs.unlinkSync(p);
    }
  },
};
