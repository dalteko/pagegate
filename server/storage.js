const fs = require('fs');
const path = require('path');

const UPLOADS_DIR = process.env.UPLOADS_DIR || path.join(__dirname, '..', 'uploads');
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

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
  savePage(pageId, buffer) {
    const html = injectViewport(buffer.toString('utf-8'));
    fs.writeFileSync(path.join(UPLOADS_DIR, `${pageId}.html`), html, 'utf-8');
  },
  readPage(pageId) {
    const filePath = path.join(UPLOADS_DIR, `${pageId}.html`);
    if (!fs.existsSync(filePath)) return null;
    return fs.readFileSync(filePath, 'utf-8');
  },
  deletePage(pageId) {
    const filePath = path.join(UPLOADS_DIR, `${pageId}.html`);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  },
};
