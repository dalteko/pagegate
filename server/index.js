const express = require('express');
const multer = require('multer');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const path = require('path');
const { clerkMiddleware, getAuth } = require('@clerk/express');
const Stripe = require('stripe');
const db = require('./db');
const storage = require('./storage');

const app = express();
const PORT = process.env.PORT || 3457;
const BASE_URL = process.env.BASE_URL || '';

const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

// Trust proxy (Railway/Cloudflare)
app.set('trust proxy', 1);

// Stripe webhook needs raw body — must be before express.json()
app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) {
    return res.status(500).json({ error: 'Stripe not configured' });
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Stripe webhook signature verification failed:', err.message);
    return res.status(400).json({ error: 'Invalid signature' });
  }

  // Idempotency: skip already-processed events
  if (isStripeEventProcessed(event.id)) {
    return res.json({ received: true, skipped: true });
  }
  markStripeEventProcessed(event.id);

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      const clerkId = session.metadata?.clerk_id;
      if (clerkId) {
        db.updateUserPro(clerkId, {
          isPro: true,
          stripeCustomerId: session.customer,
          stripeSubscriptionId: session.subscription,
          proExpiresAt: null,
        });
        console.log(`User ${clerkId} upgraded to Pro`);
      }
      break;
    }
    case 'customer.subscription.deleted': {
      const sub = event.data.object;
      const user = db.getUserByStripeCustomer(sub.customer);
      if (user) {
        // Grace period: 30 days from cancellation
        const grace = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
        db.updateUserPro(user.clerk_id, {
          isPro: false,
          stripeCustomerId: user.stripe_customer_id,
          stripeSubscriptionId: null,
          proExpiresAt: grace,
        });
        console.log(`User ${user.clerk_id} subscription cancelled, grace until ${grace}`);
      }
      break;
    }
    case 'customer.subscription.updated': {
      const sub = event.data.object;
      const user = db.getUserByStripeCustomer(sub.customer);
      if (user) {
        const isActive = sub.status === 'active' || sub.status === 'trialing' || sub.status === 'past_due';
        db.updateUserPro(user.clerk_id, {
          isPro: isActive,
          stripeCustomerId: user.stripe_customer_id,
          stripeSubscriptionId: sub.id,
          proExpiresAt: isActive ? null : user.pro_expires_at,
        });
      }
      break;
    }
  }

  res.json({ received: true });
});

// Middleware
app.use(express.json());

// Inject Clerk publishable key into HTML files at serve time
const CLERK_PUBLISHABLE_KEY = process.env.CLERK_PUBLISHABLE_KEY || '';
const publicDir = path.join(__dirname, '..', 'public');

app.use((req, res, next) => {
  // Only intercept requests for HTML files that need key injection
  if (CLERK_PUBLISHABLE_KEY && (req.path === '/' || req.path === '/index.html' || req.path === '/dashboard.html')) {
    const filePath = req.path === '/' ? path.join(publicDir, 'index.html') : path.join(publicDir, req.path);
    try {
      let html = fs.readFileSync(filePath, 'utf-8');
      html = html.replace('__CLERK_PUBLISHABLE_KEY__', CLERK_PUBLISHABLE_KEY);
      res.type('html').send(html);
    } catch {
      next();
    }
    return;
  }
  next();
});

app.use(express.static(publicDir));

// Clerk auth middleware — populates req.auth for all routes
if (process.env.CLERK_SECRET_KEY) {
  app.use(clerkMiddleware());
}

// Helper: safely get userId from Clerk auth (returns null if not configured)
function getAuthUserId(req) {
  try {
    const { userId } = getAuth(req);
    return userId || null;
  } catch {
    return null;
  }
}

// Helper: check if user has active Pro status (including grace period)
function isUserPro(user) {
  if (!user) return false;
  if (user.is_pro) return true;
  // Grace period: is_pro is false but pro_expires_at is in the future
  if (user.pro_expires_at && new Date(user.pro_expires_at) > new Date()) return true;
  return false;
}

// Track processed Stripe event IDs to prevent duplicate processing
const processedStripeEvents = new Map(); // eventId -> timestamp
const STRIPE_EVENT_TTL = 24 * 60 * 60 * 1000; // 24 hours

function isStripeEventProcessed(eventId) {
  const ts = processedStripeEvents.get(eventId);
  if (!ts) return false;
  if (Date.now() - ts > STRIPE_EVENT_TTL) {
    processedStripeEvents.delete(eventId);
    return false;
  }
  return true;
}

function markStripeEventProcessed(eventId) {
  processedStripeEvents.set(eventId, Date.now());
  // Prune old entries periodically
  if (processedStripeEvents.size > 1000) {
    const cutoff = Date.now() - STRIPE_EVENT_TTL;
    for (const [id, ts] of processedStripeEvents) {
      if (ts < cutoff) processedStripeEvents.delete(id);
    }
  }
}

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

// Slug validation: lowercase, hyphens, no special chars, min 3 chars
const SLUG_REGEX = /^[a-z0-9][a-z0-9-]{1,}[a-z0-9]$/;
const RESERVED_SLUGS = new Set(['admin', 'api', 'dashboard', 'privacy', 'terms', 'favicon', 'style', 'app']);

function validateSlug(slug) {
  if (!slug || slug.length < 3) return 'Slug must be at least 3 characters';
  if (slug.length > 64) return 'Slug must be under 64 characters';
  if (!SLUG_REGEX.test(slug)) return 'Slug must be lowercase letters, numbers, and hyphens only';
  if (RESERVED_SLUGS.has(slug)) return 'This slug is reserved';
  return null;
}

// Expiration options for Pro users (in days, 0 = never)
const EXPIRATION_OPTIONS = { '7': 7, '30': 30, '90': 90, '365': 365, 'never': 0 };

// POST /api/upload — upload HTML file + password
app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    const file = req.file;
    const password = req.body.password;
    const slug = req.body.slug?.trim().toLowerCase();
    const expiration = req.body.expiration;

    if (!file) return res.status(400).json({ error: 'No file provided' });
    if (!password || !password.trim()) return res.status(400).json({ error: 'Password is required' });

    // Validate HTML file
    const ext = path.extname(file.originalname).toLowerCase();
    if (ext !== '.html' && ext !== '.htm') {
      return res.status(400).json({ error: 'Only .html files are accepted' });
    }

    // Check Pro status for slug and custom expiration
    const userId = getAuthUserId(req);
    let user = null;
    if (userId) user = db.getUser(userId);
    const isPro = isUserPro(user);

    // Validate slug (Pro only)
    if (slug) {
      if (!isPro) return res.status(403).json({ error: 'Custom URLs require Pro' });
      const slugError = validateSlug(slug);
      if (slugError) return res.status(400).json({ error: slugError });
      // Check uniqueness
      const existing = db.getPageBySlug(slug);
      if (existing) return res.status(409).json({ error: 'This URL is already taken' });
    }

    // Calculate expiration
    const now = new Date();
    let expiresAt;
    if (expiration && expiration !== '30') {
      if (!isPro) return res.status(403).json({ error: 'Custom expiration requires Pro' });
      if (!(expiration in EXPIRATION_OPTIONS)) return res.status(400).json({ error: 'Invalid expiration option' });
      const days = EXPIRATION_OPTIONS[expiration];
      expiresAt = days === 0
        ? new Date('9999-12-31T23:59:59.999Z') // "never" = far future
        : new Date(now.getTime() + days * 24 * 60 * 60 * 1000);
    } else {
      expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
    }

    const pageId = crypto.randomBytes(6).toString('base64url').slice(0, 8);
    const passwordHash = await bcrypt.hash(password.trim(), 10);

    const encryptionSalt = storage.savePageEncrypted(pageId, file.buffer, password.trim());
    try {
      db.insertPageAtomic({
        id: pageId,
        password_hash: passwordHash,
        original_filename: file.originalname,
        file_size: file.size,
        created_at: now.toISOString(),
        expires_at: expiresAt.toISOString(),
        encryption_salt: encryptionSalt,
        user_id: userId || null,
        slug: slug || null,
      });
    } catch (err) {
      // Clean up the encrypted file since DB insert failed
      storage.deletePage(pageId);
      if (err.code === 'SQLITE_CONSTRAINT_UNIQUE' || err.message?.includes('UNIQUE constraint failed')) {
        return res.status(409).json({ error: 'This URL is already taken' });
      }
      throw err;
    }

    const baseUrl = BASE_URL || `${req.protocol}://${req.get('host')}`;
    const urlPath = slug || pageId;
    const url = `${baseUrl}/${urlPath}`;
    res.status(201).json({ pageId, url, expiresAt: expiresAt.toISOString(), slug: slug || null });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// POST /api/verify/:pageId — verify password and return HTML (supports pageId or slug)
app.post('/api/verify/:pageId', verifyLimiter, async (req, res) => {
  try {
    const { pageId } = req.params;
    const { password } = req.body;

    if (!password) return res.status(400).json({ error: 'Password is required' });

    // Try by ID first, then by slug
    let page = db.getPage(pageId);
    if (!page) page = db.getPageBySlug(pageId);
    if (!page) return res.status(404).json({ error: 'Page not found or expired' });

    const match = await bcrypt.compare(password, page.password_hash);
    if (!match) return res.status(401).json({ error: 'Wrong password' });

    // Decrypt if encrypted, otherwise fall back to legacy plaintext
    const html = page.encryption_salt
      ? storage.readPageEncrypted(page.id, password, page.encryption_salt)
      : storage.readPagePlaintext(page.id);
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

// === Auth & Billing API ===

// GET /api/me — current user info + pro status
app.get('/api/me', (req, res) => {
  const userId = getAuthUserId(req);
  if (!userId) return res.status(401).json({ error: 'Not signed in' });

  const user = db.getUser(userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  res.json({
    clerkId: user.clerk_id,
    email: user.email,
    isPro: isUserPro(user),
    proExpiresAt: user.pro_expires_at,
  });
});

// POST /api/auth/sync — called after Clerk sign-in to ensure user exists in DB
app.post('/api/auth/sync', (req, res) => {
  const userId = getAuthUserId(req);
  if (!userId) return res.status(401).json({ error: 'Not signed in' });

  const { email } = req.body;
  const user = db.getOrCreateUser(userId, email || null);

  res.json({
    clerkId: user.clerk_id,
    email: user.email,
    isPro: isUserPro(user),
    proExpiresAt: user.pro_expires_at,
  });
});

// POST /api/checkout — create Stripe Checkout session
app.post('/api/checkout', async (req, res) => {
  try {
    const userId = getAuthUserId(req);
    if (!userId) return res.status(401).json({ error: 'Not signed in' });
    if (!stripe || !process.env.STRIPE_PRICE_ID) {
      return res.status(500).json({ error: 'Billing not configured' });
    }

    const user = db.getUser(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (isUserPro(user)) return res.status(400).json({ error: 'Already subscribed' });

    const baseUrl = BASE_URL || `${req.protocol}://${req.get('host')}`;

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
      customer_email: user.email || undefined,
      metadata: { clerk_id: userId },
      success_url: `${baseUrl}/?pro=success`,
      cancel_url: `${baseUrl}/?pro=cancel`,
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// POST /api/billing-portal — Stripe Customer Portal for managing subscription
app.post('/api/billing-portal', async (req, res) => {
  try {
    const userId = getAuthUserId(req);
    if (!userId) return res.status(401).json({ error: 'Not signed in' });
    if (!stripe) return res.status(500).json({ error: 'Billing not configured' });

    const user = db.getUser(userId);
    if (!user || !user.stripe_customer_id) {
      return res.status(400).json({ error: 'No billing account found' });
    }

    const baseUrl = BASE_URL || `${req.protocol}://${req.get('host')}`;
    const session = await stripe.billingPortal.sessions.create({
      customer: user.stripe_customer_id,
      return_url: baseUrl,
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Billing portal error:', err);
    res.status(500).json({ error: 'Failed to open billing portal' });
  }
});

// === Dashboard API (Pro) ===

// GET /api/pages — list user's pages
app.get('/api/pages', (req, res) => {
  const userId = getAuthUserId(req);
  if (!userId) return res.status(401).json({ error: 'Not signed in' });

  const pages = db.getUserPages(userId);
  res.json(pages.map(p => ({
    id: p.id,
    filename: p.original_filename,
    fileSize: p.file_size,
    slug: p.slug || null,
    createdAt: p.created_at,
    expiresAt: p.expires_at,
  })));
});

// DELETE /api/pages/:pageId — delete a page (owner only)
app.delete('/api/pages/:pageId', (req, res) => {
  const userId = getAuthUserId(req);
  if (!userId) return res.status(401).json({ error: 'Not signed in' });

  const page = db.getPageById(req.params.pageId);
  if (!page) return res.status(404).json({ error: 'Page not found' });
  if (page.user_id !== userId) return res.status(403).json({ error: 'Not your page' });

  storage.deletePage(page.id);
  db.deletePage(page.id);
  res.json({ ok: true });
});

// PATCH /api/pages/:pageId/password — update password (owner only)
// Requires the old password to re-encrypt the file with the new one.
app.patch('/api/pages/:pageId/password', async (req, res) => {
  try {
    const userId = getAuthUserId(req);
    if (!userId) return res.status(401).json({ error: 'Not signed in' });

    const { oldPassword, password } = req.body;
    if (!password || !password.trim()) return res.status(400).json({ error: 'New password is required' });
    if (!oldPassword || !oldPassword.trim()) return res.status(400).json({ error: 'Current password is required' });

    const page = db.getPageById(req.params.pageId);
    if (!page) return res.status(404).json({ error: 'Page not found' });
    if (page.user_id !== userId) return res.status(403).json({ error: 'Not your page' });

    // Check if page has expired and file may have been cleaned up
    if (new Date(page.expires_at) < new Date()) {
      return res.status(410).json({ error: 'Page has expired' });
    }

    // Verify old password
    const match = await bcrypt.compare(oldPassword.trim(), page.password_hash);
    if (!match) return res.status(401).json({ error: 'Current password is incorrect' });

    // Decrypt with old password, re-encrypt with new password
    if (page.encryption_salt) {
      const html = storage.readPageEncrypted(page.id, oldPassword.trim(), page.encryption_salt);
      if (!html) return res.status(500).json({ error: 'Failed to decrypt page — file may have been cleaned up' });
      const newSalt = storage.savePageEncrypted(page.id, Buffer.from(html, 'utf-8'), password.trim());
      const newHash = await bcrypt.hash(password.trim(), 10);
      db.updatePagePasswordAndSalt(page.id, newHash, newSalt);
    } else {
      // Legacy plaintext — just update the hash
      db.updatePagePassword(page.id, await bcrypt.hash(password.trim(), 10));
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('Password update error:', err);
    res.status(500).json({ error: 'Password update failed' });
  }
});

// GET /dashboard — serve dashboard page (with Clerk key injected)
app.get('/dashboard', (req, res) => {
  const filePath = path.join(publicDir, 'dashboard.html');
  try {
    let html = fs.readFileSync(filePath, 'utf-8');
    if (CLERK_PUBLISHABLE_KEY) {
      html = html.replace('__CLERK_PUBLISHABLE_KEY__', CLERK_PUBLISHABLE_KEY);
    }
    res.type('html').send(html);
  } catch {
    res.status(500).send('Dashboard not found');
  }
});

// GET /:slug — serve view.html for password prompt (supports both pageId and custom slugs)
app.get('/:pageIdOrSlug', (req, res) => {
  const param = req.params.pageIdOrSlug;

  // Match 8-char nanoid IDs
  if (/^[A-Za-z0-9_-]{8}$/.test(param)) {
    res.set('X-Frame-Options', 'DENY');
    return res.sendFile(path.join(publicDir, 'view.html'));
  }

  // Match custom slugs (lowercase, hyphens, 3+ chars)
  if (/^[a-z0-9][a-z0-9-]+[a-z0-9]$/.test(param)) {
    const page = db.getPageBySlug(param);
    if (page) {
      res.set('X-Frame-Options', 'DENY');
      return res.sendFile(path.join(publicDir, 'view.html'));
    }
  }

  res.status(404).send('Not found');
});

// Cleanup: delete expired pages from disk + DB on startup and every 24h
function cleanupExpired() {
  // Delete one at a time: remove from DB first (so no one can look it up), then delete file
  const expiredIds = db.getExpiredIds();
  for (const id of expiredIds) {
    db.deletePageById(id);
    storage.deletePage(id);
  }
  if (expiredIds.length > 0) {
    console.log(`Cleaned up ${expiredIds.length} expired page(s)`);
  }
}
cleanupExpired();
setInterval(cleanupExpired, 24 * 60 * 60 * 1000);

app.listen(PORT, () => {
  console.log(`PageGate running at http://localhost:${PORT}`);
});
