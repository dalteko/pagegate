const express = require('express');
const multer = require('multer');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const db = require('./db');
const storage = require('./storage');
const { requireAuth, requirePro, optionalAuth } = require('./auth');
const stripeService = require('./stripe');
const config = require('./config');

const app = express();
const PORT = process.env.PORT || 3457;
const BASE_URL = process.env.BASE_URL || '';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');

// Trust proxy (Railway/Cloudflare)
app.set('trust proxy', 1);

function requireProFeatures(req, res, next) {
  if (!config.proEnabled) {
    return res.status(404).json({ error: 'Pro features are disabled' });
  }
  next();
}

// Stripe webhook needs raw body — must come before express.json()
app.post('/api/stripe/webhook', requireProFeatures, express.raw({ type: 'application/json' }), (req, res) => {
  try {
    const result = stripeService.handleWebhook(req.body, req.headers['stripe-signature']);
    res.json(result);
  } catch (err) {
    console.error('Webhook error:', err.message);
    res.status(400).json({ error: 'Webhook failed' });
  }
});

// Middleware
app.use(express.json());
if (config.proEnabled) {
  app.use(session({
    store: new SQLiteStore({ dir: DATA_DIR, db: 'sessions.db' }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: 30 * 24 * 60 * 60 * 1000,
      sameSite: 'lax',
    },
  }));
}
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
app.post('/api/upload', optionalAuth, upload.single('file'), async (req, res) => {
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

    // Paid users get no expiration; everyone else gets 30 days
    const isSubscribed = req.user && req.user.subscription_status === 'active';
    const expiresAt = isSubscribed
      ? new Date('9999-12-31T23:59:59.000Z')
      : new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

    const encryptionSalt = storage.savePageEncrypted(pageId, file.buffer, password.trim());
    db.insertPage({
      id: pageId,
      password_hash: passwordHash,
      original_filename: file.originalname,
      file_size: file.size,
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
      encryption_salt: encryptionSalt,
      user_id: req.user ? req.user.id : null,
      page_password: isSubscribed ? password.trim() : null,
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

// === Auth API ===

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  keyGenerator: (req) => req.ip,
  message: { error: 'Too many attempts. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.post('/api/auth/register', requireProFeatures, authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

    const trimmedEmail = email.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) {
      return res.status(400).json({ error: 'Invalid email address' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    const existing = db.getUserByEmail(trimmedEmail);
    if (existing) return res.status(409).json({ error: 'Email already registered' });

    const id = crypto.randomBytes(16).toString('hex');
    const passwordHash = await bcrypt.hash(password, 10);
    db.insertUser(id, trimmedEmail, passwordHash);

    req.session.userId = id;
    res.status(201).json({ user: { id, email: trimmedEmail, subscriptionStatus: 'none' } });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', requireProFeatures, authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

    const user = db.getUserByEmail(email.trim().toLowerCase());
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid email or password' });

    req.session.userId = user.id;
    res.json({ user: { id: user.id, email: user.email, subscriptionStatus: user.subscription_status } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/logout', requireProFeatures, (req, res) => {
  req.session.destroy(() => {});
  res.json({ ok: true });
});

app.get('/api/auth/me', (req, res) => {
  if (!config.proEnabled) return res.json({ user: null, proEnabled: false });
  if (!req.session.userId) return res.json({ user: null });
  const user = db.getUserById(req.session.userId);
  if (!user) return res.json({ user: null });
  res.json({
    user: {
      id: user.id,
      email: user.email,
      subscriptionStatus: user.subscription_status,
    },
  });
});

// === Dashboard API ===

app.get('/api/pages', requireAuth, requirePro, (req, res) => {
  const pages = db.getPagesByUser(req.user.id);
  res.json(pages.map(p => ({
    id: p.id,
    filename: p.original_filename,
    fileSize: p.file_size,
    createdAt: p.created_at,
    expiresAt: p.expires_at,
    pagePassword: p.page_password,
  })));
});

app.delete('/api/pages/:pageId', requireAuth, requirePro, (req, res) => {
  const result = db.deletePageByUser(req.params.pageId, req.user.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Page not found' });
  storage.deletePage(req.params.pageId);
  res.json({ ok: true });
});

// === Stripe API ===

app.post('/api/stripe/checkout', requireAuth, async (req, res) => {
  try {
    const baseUrl = BASE_URL || `${req.protocol}://${req.get('host')}`;
    const session = await stripeService.createCheckoutSession(
      req.user.id, req.user.email, req.user.stripe_customer_id, baseUrl
    );
    res.json({ url: session.url });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

app.post('/api/stripe/portal', requireAuth, async (req, res) => {
  try {
    if (!req.user.stripe_customer_id) {
      return res.status(400).json({ error: 'No active subscription' });
    }
    const baseUrl = BASE_URL || `${req.protocol}://${req.get('host')}`;
    const session = await stripeService.createPortalSession(req.user.stripe_customer_id, baseUrl);
    res.json({ url: session.url });
  } catch (err) {
    console.error('Portal error:', err);
    res.status(500).json({ error: 'Failed to create portal session' });
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
