const express = require('express');
const multer = require('multer');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const path = require('path');
const db = require('./db');
const storage = require('./storage');

const app = express();
const PORT = process.env.PORT || 3457;
const BASE_URL = process.env.BASE_URL || '';

// Trust proxy (Railway/Cloudflare)
app.set('trust proxy', 1);

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

// Multer: memory storage, 5MB limit
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
});

// Rate limiter for password verification: 10 attempts per IP per page per hour
const verifyLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  keyGenerator: (req) => `${req.ip}-${req.params.pageId}`,
  message: { error: 'Too many attempts. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// POST /api/upload — upload HTML file + password
app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    const file = req.file;
    const password = req.body.password;

    if (!file) return res.status(400).json({ error: 'No file provided' });
    if (!password || !password.trim()) return res.status(400).json({ error: 'Password is required' });

    // Validate HTML file
    const ext = path.extname(file.originalname).toLowerCase();
    if (ext !== '.html' && ext !== '.htm') {
      return res.status(400).json({ error: 'Only .html files are accepted' });
    }

    const pageId = crypto.randomBytes(6).toString('base64url').slice(0, 8);
    const passwordHash = await bcrypt.hash(password.trim(), 10);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

    const encryptionSalt = storage.savePageEncrypted(pageId, file.buffer, password.trim());
    db.insertPage({
      id: pageId,
      password_hash: passwordHash,
      original_filename: file.originalname,
      file_size: file.size,
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
      encryption_salt: encryptionSalt,
    });

    const url = BASE_URL
      ? `${BASE_URL}/${pageId}`
      : `${req.protocol}://${req.get('host')}/${pageId}`;
    res.status(201).json({ pageId, url, expiresAt: expiresAt.toISOString() });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// POST /api/verify/:pageId — verify password and return HTML
app.post('/api/verify/:pageId', verifyLimiter, async (req, res) => {
  try {
    const { pageId } = req.params;
    const { password } = req.body;

    if (!password) return res.status(400).json({ error: 'Password is required' });

    const page = db.getPage(pageId);
    if (!page) return res.status(404).json({ error: 'Page not found or expired' });

    const match = await bcrypt.compare(password, page.password_hash);
    if (!match) return res.status(401).json({ error: 'Wrong password' });

    // Decrypt if encrypted, otherwise fall back to legacy plaintext
    const html = page.encryption_salt
      ? storage.readPageEncrypted(pageId, password, page.encryption_salt)
      : storage.readPagePlaintext(pageId);
    if (!html) return res.status(404).json({ error: 'Page file not found' });

    res.json({ html });
  } catch (err) {
    console.error('Verify error:', err);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// === Feedback API ===

// Rate limiter for feedback submissions
const feedbackLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => req.ip,
  message: { error: 'Too many submissions. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

function hashIp(ip) {
  return crypto.createHash('sha256').update(ip + 'pagegate-salt').digest('hex').slice(0, 16);
}

// POST /api/feedback — submit feedback (public)
app.post('/api/feedback', feedbackLimiter, (req, res) => {
  const { text } = req.body;
  if (!text || !text.trim() || text.trim().length < 3) {
    return res.status(400).json({ error: 'Feedback is too short' });
  }
  if (text.trim().length > 280) {
    return res.status(400).json({ error: 'Feedback is too long (max 280 characters)' });
  }
  const id = crypto.randomBytes(6).toString('base64url').slice(0, 8);
  db.insertFeedback(id, text.trim());
  // Auto-vote for your own submission
  const ipHash = hashIp(req.ip);
  db.voteFeedback(id, ipHash);
  res.status(201).json({ id });
});

// GET /admin/feedback — admin-only view of all feedback (sorted by votes desc)
app.get('/admin/feedback', (req, res) => {
  const adminKey = process.env.ADMIN_KEY;
  if (!adminKey || req.query.key !== adminKey) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const items = db.listFeedback();
  res.json(items.map(item => ({
    id: item.id,
    text: item.text,
    votes: item.votes,
    status: item.status,
    createdAt: item.created_at,
  })));
});

// GET /:pageId — serve view.html for password prompt
app.get('/:pageId', (req, res) => {
  const { pageId } = req.params;

  // Only match nanoid-like IDs (alphanumeric + _- , 8 chars)
  if (!/^[A-Za-z0-9_-]{8}$/.test(pageId)) return res.status(404).send('Not found');

  res.set('X-Frame-Options', 'DENY');
  res.sendFile(path.join(__dirname, '..', 'public', 'view.html'));
});

// Cleanup: delete expired pages from disk + DB on startup and every 24h
function cleanupExpired() {
  const expiredIds = db.getExpiredIds();
  for (const id of expiredIds) {
    storage.deletePage(id);
  }
  db.deleteExpired();
  if (expiredIds.length > 0) {
    console.log(`Cleaned up ${expiredIds.length} expired page(s)`);
  }
}
cleanupExpired();
setInterval(cleanupExpired, 24 * 60 * 60 * 1000);

app.listen(PORT, () => {
  console.log(`PageGate running at http://localhost:${PORT}`);
});
