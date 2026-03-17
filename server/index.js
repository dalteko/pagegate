const express = require('express');
const multer = require('multer');
const bcrypt = require('bcrypt');
const { nanoid } = require('nanoid');
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

    const pageId = nanoid(8);
    const passwordHash = await bcrypt.hash(password.trim(), 10);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

    storage.savePage(pageId, file.buffer);
    db.insertPage({
      id: pageId,
      password_hash: passwordHash,
      original_filename: file.originalname,
      file_size: file.size,
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
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

    const html = storage.readPage(pageId);
    if (!html) return res.status(404).json({ error: 'Page file not found' });

    res.json({ html });
  } catch (err) {
    console.error('Verify error:', err);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// GET /:pageId — serve view.html for password prompt
app.get('/:pageId', (req, res) => {
  const { pageId } = req.params;

  // Only match nanoid-like IDs (alphanumeric + _- , 8 chars)
  if (!/^[A-Za-z0-9_-]{8}$/.test(pageId)) return res.status(404).send('Not found');

  res.set('X-Frame-Options', 'DENY');
  res.sendFile(path.join(__dirname, '..', 'public', 'view.html'));
});

// Lazy cleanup on startup + every 24h
db.deleteExpired();
setInterval(() => db.deleteExpired(), 24 * 60 * 60 * 1000);

app.listen(PORT, () => {
  console.log(`PageGate running at http://localhost:${PORT}`);
});
