const express = require('express');
const multer = require('multer');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const path = require('path');
const { clerkClient, clerkMiddleware, getAuth } = require('@clerk/express');
const Stripe = require('stripe');
const db = require('./db');
const storage = require('./storage');
const cryptoLib = require('./crypto');
const tiers = require('./tiers');
const config = require('./config');

const app = express();
const PORT = process.env.PORT || 3457;
const BASE_URL = process.env.BASE_URL || '';

const stripe = config.proEnabled ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

// Trust proxy (Railway/Cloudflare)
app.set('trust proxy', 1);

// Stripe webhook needs raw body — must be before express.json()
app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!config.proEnabled || !stripe) {
    return res.status(500).json({ error: 'Stripe not configured' });
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Stripe webhook signature verification failed:', err.message);
    return res.status(400).json({ error: 'Invalid signature' });
  }

  if (!db.claimStripeEvent(event.id, event.type)) {
    return res.json({ received: true, skipped: true });
  }

  try {
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

    db.markStripeEventProcessed(event.id);
    res.json({ received: true });
  } catch (err) {
    db.releaseStripeEvent(event.id);
    console.error('Stripe webhook processing failed:', err);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// Middleware
app.use(express.json());

// Inject Clerk publishable key into HTML files at serve time
const CLERK_PUBLISHABLE_KEY = config.proEnabled ? process.env.CLERK_PUBLISHABLE_KEY : '';
const publicDir = path.join(__dirname, '..', 'public');

app.use((req, res, next) => {
  // Only intercept requests for HTML files that need key injection
  if (req.path === '/' || req.path === '/index.html' || req.path === '/dashboard.html') {
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
if (config.proEnabled) {
  app.use(clerkMiddleware());
}

// Helper: safely get userId from Clerk auth (returns null if not configured)
function getAuthUserId(req) {
  if (!config.proEnabled) return null;
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

// Decrypt a page row to its HTML, picking the crypto path by what's stored
// on the row. Returns null if the on-disk blob is missing.
//
//   wrapped_key  → master-key path (Tier 2/3). Password isn't part of crypto;
//                  caller is responsible for any access gating (bcrypt or
//                  is_public).
//   encryption_salt → password-derived path (Tier 1). `password` required.
//   neither → legacy plaintext upload (pre-encryption).
function decryptPage(page, password) {
  if (page.wrapped_key) {
    const blob = storage.readPageBlob(page.id);
    if (!blob) return null;
    const pageKey = cryptoLib.unwrapPageKey(page.wrapped_key);
    return cryptoLib.decryptWithKey(blob, pageKey);
  }
  if (page.encryption_salt) {
    const blob = storage.readPageBlob(page.id);
    if (!blob) return null;
    return cryptoLib.decryptWithPassword(blob, password, page.encryption_salt);
  }
  return storage.readPagePlaintext(page.id);
}

function getRequiredProUser(req, res) {
  const userId = getAuthUserId(req);
  if (!userId) {
    res.status(401).json({ error: 'Not signed in' });
    return null;
  }

  const user = db.getUser(userId);
  if (!isUserPro(user)) {
    res.status(403).json({ error: 'Pro subscription required' });
    return null;
  }

  return { userId, user };
}

// Any signed-in user — Tier 2 or Tier 3. Used by routes shared between
// account and Pro (dashboard list, password reset). Distinct from
// getRequiredProUser, which gates Pro-only features (delete, slug, etc.).
//
// Async because we lazy-upsert the local users row from Clerk if it's
// missing — same logic as `/api/auth/sync`. Without this, a freshly-
// signed-in user who hits any of these routes before the dashboard's
// auth-sync round trip lands gets a 404 (PR #10 fixed the equivalent
// race for the dashboard's /api/me call by switching it to /api/auth/sync;
// this closes the same gap on the server side so it's fixed once for
// every route, not per-call site).
async function getRequiredAuthUser(req, res) {
  const userId = getAuthUserId(req);
  if (!userId) {
    res.status(401).json({ error: 'Not signed in' });
    return null;
  }
  let user = db.getUser(userId);
  if (!user) {
    try {
      const clerkUser = await clerkClient.users.getUser(userId);
      const email = clerkUser.primaryEmailAddress?.emailAddress
        || clerkUser.emailAddresses?.find((addr) => addr.id === clerkUser.primaryEmailAddressId)?.emailAddress
        || null;
      user = db.getOrCreateUser(userId, email);
    } catch (err) {
      console.error('Lazy user upsert failed:', err);
      res.status(500).json({ error: 'Auth sync failed' });
      return null;
    }
  }
  return { userId, user };
}

// Multer: memory storage. File size cap is 10 MB across all tiers — see
// tiers.js / TIERS.md for the rationale (rich HTML pages are well under
// 1 MB; only base64-embedded media exceeds 10 MB and that's an anti-pattern).
const MAX_FILE_BYTES = tiers.RULES[tiers.TIER.ANONYMOUS].fileSizeMb * 1024 * 1024;
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_BYTES },
});

function findLivePage(pageIdOrSlug) {
  let page = db.getPage(pageIdOrSlug);
  if (!page) page = db.getPageBySlug(pageIdOrSlug);
  return page;
}

function effectiveViewCap(page) {
  if (page.view_cap !== null && page.view_cap !== undefined) return page.view_cap;
  const tierAtCreation = page.tier_at_creation || tiers.TIER.ANONYMOUS;
  const rule = tiers.RULES[tierAtCreation];
  return rule.viewCap ?? rule.viewCapDefault ?? null;
}

// Rate limiter for password verification: 10 attempts per IP per page per hour
const verifyLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  // Public Pro pages have no password to brute-force. They are still gated
  // by the per-page view cap in the handler, but should not trip the
  // password-attempt limiter on normal refreshes.
  skip: (req) => !!findLivePage(req.params.pageId)?.is_public,
  keyGenerator: (req) => `${req.ip}-${req.params.pageId}`,
  message: { error: 'Too many attempts. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Slug validation lives in tiers.js — call `tiers.validateProSlug`
// directly so there's only ever one function in play. The spec rule is
// "3+ hyphenated word groups, each ≥ 2 chars, lowercase alphanumeric,
// ≤ 60 chars total".

// Expiration options for Pro users (in days, 0 = never)
const EXPIRATION_OPTIONS = { '7': 7, '30': 30, '90': 90, '365': 365, 'never': 0 };

// POST /api/upload — upload HTML file + password
app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    const file = req.file;
    const password = req.body.password;
    const confirmPassword = req.body.confirmPassword;
    const slug = req.body.slug?.trim().toLowerCase();
    const expiration = req.body.expiration;
    const isPublic = req.body.isPublic === 'true' || req.body.isPublic === true;
    const viewCapRaw = req.body.viewCap;

    if (!file) return res.status(400).json({ error: 'No file provided' });
    // Public pages skip the password gate entirely. Password-protected
    // pages still require it (and confirm-password if supplied).
    if (!isPublic) {
      if (!password || !password.trim()) return res.status(400).json({ error: 'Password is required' });
      if (confirmPassword !== undefined && confirmPassword !== password) {
        return res.status(400).json({ error: 'Passwords do not match' });
      }
    }

    // Validate HTML file
    const ext = path.extname(file.originalname).toLowerCase();
    if (ext !== '.html' && ext !== '.htm') {
      return res.status(400).json({ error: 'Only .html files are accepted' });
    }

    // Resolve tier upfront — every downstream decision (link cap, default
    // expiry, slug eligibility, crypto path) keys off this.
    const userId = getAuthUserId(req);
    let user = null;
    if (userId) user = db.getUser(userId);
    const isPro = isUserPro(user);
    const tier = tiers.tierFor(user, { isProActive: isUserPro });
    const tierRule = tiers.RULES[tier];

    // Pro-only fields. Returning 403 early so the user gets a precise
    // error rather than something silently dropped.
    if (isPublic && !tierRule.allowPublic) {
      return res.status(403).json({ error: 'Public pages require Pro' });
    }
    let viewCapValue = null;
    if (viewCapRaw !== undefined && viewCapRaw !== null && viewCapRaw !== '') {
      if (!tierRule.viewCapConfigurable) {
        return res.status(403).json({ error: 'Custom view caps require Pro' });
      }
      viewCapValue = parseInt(viewCapRaw, 10);
      if (!Number.isFinite(viewCapValue) || viewCapValue < 1) {
        return res.status(400).json({ error: 'View cap must be a positive integer' });
      }
    }

    // Per-tier link cap. Tier 1 = unlimited (rule is null). Tier 2 = 3,
    // Tier 3 = 100. Cannot delete on Tier 2 by design — user must wait
    // for a page to expire. Archived pages (Phase 5 grace) don't count.
    if (tierRule.maxLinks !== null && userId) {
      const active = db.countActiveUserPages(userId);
      if (active >= tierRule.maxLinks) {
        const tierLabel = tierRule.label;
        return res.status(403).json({
          error: `${tierLabel} is limited to ${tierRule.maxLinks} active link${tierRule.maxLinks === 1 ? '' : 's'}. Wait for one to expire before creating another.`,
          reason: 'link_cap',
        });
      }
    }

    // Validate slug (Pro only)
    if (slug) {
      if (!isPro) return res.status(403).json({ error: 'Custom URLs require Pro' });
      const slugError = tiers.validateProSlug(slug);
      if (slugError) return res.status(400).json({ error: slugError });
      // Check uniqueness
      const existing = db.getPageBySlug(slug);
      if (existing) return res.status(409).json({ error: 'This URL is already taken' });
    }

    // Tier-driven default expiry. Tier 1 = 1 day, Tier 2 = 7 days. Tier 3
    // (Pro) picks from EXPIRATION_OPTIONS or defaults to 30 if not set —
    // pulled from tiers.js so future tweaks live in one place.
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
      const defaultDays = tier === tiers.TIER.PRO
        ? 30  // Pro keeps 30-day default; explicit `expiration` overrides
        : tierRule.expiryDays;
      expiresAt = new Date(now.getTime() + defaultDays * 24 * 60 * 60 * 1000);
    }

    const pageId = crypto.randomBytes(6).toString('base64url').slice(0, 8);
    // Public pages still get a non-null password_hash (the column is NOT
    // NULL) — empty string is a sentinel that the verify route will never
    // reach since is_public short-circuits the bcrypt check.
    const passwordHash = isPublic ? '' : await bcrypt.hash(password.trim(), 10);

    // Pick the crypto path by tier (see crypto.js header for the why).
    // Anonymous → password-derived (zero-knowledge). Account/Pro →
    // master-key wrapped, so account-driven password reset is possible.
    const html = storage.prepareHtml(file.buffer);

    let encryptionSalt = null;
    let wrappedKey = null;
    let blob;
    if (tier === tiers.TIER.ANONYMOUS) {
      const out = cryptoLib.encryptWithPassword(html, password.trim());
      blob = out.blob;
      encryptionSalt = out.saltBase64;
    } else {
      const pageKey = cryptoLib.generatePageKey();
      blob = cryptoLib.encryptWithKey(html, pageKey);
      wrappedKey = cryptoLib.wrapPageKey(pageKey);
    }
    storage.savePageBlob(pageId, blob);

    // Per-link view cap. Pro: user-set, falling back to viewCapDefault
    // (1,000) so analytics work out of the box. Other tiers: leave null
    // and let the read-time tier-rule lookup handle it.
    const viewCapPersisted = tier === tiers.TIER.PRO
      ? (viewCapValue ?? tierRule.viewCapDefault)
      : null;

    try {
      db.insertPageAtomic({
        id: pageId,
        password_hash: passwordHash,
        original_filename: file.originalname,
        file_size: file.size,
        created_at: now.toISOString(),
        expires_at: expiresAt.toISOString(),
        encryption_salt: encryptionSalt,
        wrapped_key: wrappedKey,
        tier_at_creation: tier,
        user_id: userId || null,
        slug: slug || null,
        is_public: isPublic,
        view_cap: viewCapPersisted,
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

// POST /api/verify/:pageId — verify password and return HTML (supports pageId or slug).
// For public pages (Pro feature), the password gate is skipped — the route
// still runs view-cap enforcement and increments the view count, since
// those apply uniformly to all unlocks.
app.post('/api/verify/:pageId', verifyLimiter, async (req, res) => {
  try {
    const { pageId } = req.params;
    const { password } = req.body;

    const page = findLivePage(pageId);
    if (!page) return res.status(404).json({ error: 'Page not found or expired' });

    if (!page.is_public) {
      if (!password) return res.status(400).json({ error: 'Password is required' });
      const match = await bcrypt.compare(password, page.password_hash);
      if (!match) return res.status(401).json({ error: 'Wrong password' });
    }

    // View-cap enforcement. The per-page `view_cap` column wins if set;
    // otherwise fall back to the tier rule/default. A null effective cap
    // means unlimited.
    const cap = effectiveViewCap(page);
    if (cap !== null && cap !== undefined && (page.view_count || 0) >= cap) {
      return res.status(410).json({ error: 'View limit reached', reason: 'view_cap' });
    }

    const html = decryptPage(page, password);
    if (!html) return res.status(404).json({ error: 'Page file not found' });

    db.incrementViewCount(page.id);

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
app.post('/api/auth/sync', async (req, res) => {
  try {
    const userId = getAuthUserId(req);
    if (!userId) return res.status(401).json({ error: 'Not signed in' });

    const clerkUser = await clerkClient.users.getUser(userId);
    const email = clerkUser.primaryEmailAddress?.emailAddress
      || clerkUser.emailAddresses?.find((addr) => addr.id === clerkUser.primaryEmailAddressId)?.emailAddress
      || null;
    const user = db.getOrCreateUser(userId, email);

    res.json({
      clerkId: user.clerk_id,
      email: user.email,
      isPro: isUserPro(user),
      proExpiresAt: user.pro_expires_at,
    });
  } catch (err) {
    console.error('Auth sync error:', err);
    res.status(500).json({ error: 'Auth sync failed' });
  }
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

// === Dashboard API ===
//
// Tier 2 (account) and Tier 3 (Pro) share the same listing endpoint —
// permissions diverge per-action: delete is Pro-only (Tier 2 cannot
// delete by spec); password reset works for both.

// GET /api/pages — list signed-in user's pages
app.get('/api/pages', async (req, res) => {
  const auth = await getRequiredAuthUser(req, res);
  if (!auth) return;

  const isPro = isUserPro(auth.user);
  const pages = db.getUserPages(auth.userId);
  res.json(pages.map(p => {
    const tier = p.tier_at_creation || tiers.TIER.ANONYMOUS;
    const cap = effectiveViewCap(p);
    return {
      id: p.id,
      filename: p.original_filename,
      fileSize: p.file_size,
      slug: p.slug || null,
      createdAt: p.created_at,
      expiresAt: p.expires_at,
      viewCount: p.view_count || 0,
      viewCap: cap,
      // Raw DB value (null when no explicit cap). The edit modal uses this
      // to distinguish "no cap set" from "cap set to the tier default" —
      // a no-op save would otherwise pin the page to the current default.
      viewCapExplicit: p.view_cap,
      isPublic: !!p.is_public,
      tier,
      // Per-action capability flags so the dashboard can render the
      // right buttons without duplicating tier rules. Public pages
      // skip both — there's no password to change or reset on a page
      // that has no password gate.
      hasPassword: !p.is_public,
      // Whether this page supports server-side password reset. Pages
      // created on the password-derived path (legacy) cannot be reset
      // without the old password — the page key is derived from it.
      passwordResettable: !!p.wrapped_key && !p.is_public,
      canDelete: isPro,
      canEdit: isPro,
    };
  }));
});

// DELETE /api/pages/:pageId — delete a page (Pro only; Tier 2 cannot delete)
app.delete('/api/pages/:pageId', (req, res) => {
  const auth = getRequiredProUser(req, res);
  if (!auth) return;

  const page = db.getPageById(req.params.pageId);
  if (!page) return res.status(404).json({ error: 'Page not found' });
  if (page.user_id !== auth.userId) return res.status(403).json({ error: 'Not your page' });

  storage.deletePage(page.id);
  db.deletePage(page.id);
  res.json({ ok: true });
});

// PATCH /api/pages/:pageId/password — change password with the old one.
// Open to any signed-in user (Tier 2 + Tier 3). Tier 1 pages have no
// owner so this never reaches them.
app.patch('/api/pages/:pageId/password', async (req, res) => {
  try {
    const auth = await getRequiredAuthUser(req, res);
    if (!auth) return;

    const { oldPassword, password } = req.body;
    if (!password || !password.trim()) return res.status(400).json({ error: 'New password is required' });
    if (!oldPassword || !oldPassword.trim()) return res.status(400).json({ error: 'Current password is required' });

    const page = db.getPageById(req.params.pageId);
    if (!page) return res.status(404).json({ error: 'Page not found' });
    if (page.user_id !== auth.userId) return res.status(403).json({ error: 'Not your page' });

    // Check if page has expired and file may have been cleaned up
    if (new Date(page.expires_at) < new Date()) {
      return res.status(410).json({ error: 'Page has expired' });
    }

    // Verify old password
    const match = await bcrypt.compare(oldPassword.trim(), page.password_hash);
    if (!match) return res.status(401).json({ error: 'Current password is incorrect' });

    const newHash = await bcrypt.hash(password.trim(), 10);

    if (page.wrapped_key) {
      // Master-key path: password isn't part of crypto, just rotate hash.
      db.updatePagePassword(page.id, newHash);
    } else if (page.encryption_salt) {
      // Password-derived path: decrypt with old password, re-encrypt with new.
      const blob = storage.readPageBlob(page.id);
      if (!blob) return res.status(500).json({ error: 'Failed to decrypt page — file may have been cleaned up' });
      const html = cryptoLib.decryptWithPassword(blob, oldPassword.trim(), page.encryption_salt);
      const out = cryptoLib.encryptWithPassword(html, password.trim());
      storage.savePageBlob(page.id, out.blob);
      db.updatePagePasswordAndSalt(page.id, newHash, out.saltBase64);
    } else {
      // Legacy plaintext — just update the hash
      db.updatePagePassword(page.id, newHash);
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('Password update error:', err);
    res.status(500).json({ error: 'Password update failed' });
  }
});

// POST /api/pages/:pageId/password/reset — reset password without knowing
// the old one. Only works for wrapped-key pages (Tier 2/3 created after
// Phase 1) since the page key is server-held there. For password-derived
// pages, a reset is impossible by design — the key IS the password.
app.post('/api/pages/:pageId/password/reset', async (req, res) => {
  try {
    const auth = await getRequiredAuthUser(req, res);
    if (!auth) return;

    const { password } = req.body;
    if (!password || !password.trim()) return res.status(400).json({ error: 'New password is required' });

    const page = db.getPageById(req.params.pageId);
    if (!page) return res.status(404).json({ error: 'Page not found' });
    if (page.user_id !== auth.userId) return res.status(403).json({ error: 'Not your page' });
    if (new Date(page.expires_at) < new Date()) {
      return res.status(410).json({ error: 'Page has expired' });
    }

    if (!page.wrapped_key) {
      return res.status(400).json({
        error: 'This page was created without a recoverable key and cannot be reset. The original password is the only way to unlock it.',
        reason: 'not_resettable',
      });
    }

    const newHash = await bcrypt.hash(password.trim(), 10);
    db.updatePagePassword(page.id, newHash);
    res.json({ ok: true });
  } catch (err) {
    console.error('Password reset error:', err);
    res.status(500).json({ error: 'Password reset failed' });
  }
});

// PATCH /api/pages/:pageId — Pro edit-in-place. Accepts a multipart body
// so callers can send a new HTML file alongside metadata changes in one
// request. All fields are optional; supply only what you want to change.
//
// Fields:
//   file        — multipart file. Replaces the page HTML. Wrapped-key
//                 pages only (legacy password-derived pages can't be
//                 edited without their old password by design).
//   slug        — new custom slug. Validated via tiers.validateProSlug
//                 and uniqueness-checked.
//   expiration  — option from EXPIRATION_OPTIONS. Recomputes expires_at
//                 from now.
//   isPublic    — 'true' / 'false'. Toggles password gating.
//   viewCap     — positive integer or '' to clear (fall back to default).
app.patch('/api/pages/:pageId', upload.single('file'), async (req, res) => {
  try {
    const auth = getRequiredProUser(req, res);
    if (!auth) return;

    const page = db.getPageById(req.params.pageId);
    if (!page) return res.status(404).json({ error: 'Page not found' });
    if (page.user_id !== auth.userId) return res.status(403).json({ error: 'Not your page' });
    if (new Date(page.expires_at) < new Date()) {
      return res.status(410).json({ error: 'Page has expired' });
    }

    const updates = {};

    // --- HTML replacement ---
    if (req.file) {
      const ext = path.extname(req.file.originalname).toLowerCase();
      if (ext !== '.html' && ext !== '.htm') {
        return res.status(400).json({ error: 'Only .html files are accepted' });
      }
      if (!page.wrapped_key) {
        return res.status(400).json({
          error: 'This page was created without a recoverable key. Editing requires uploading it under a new account/Pro page.',
          reason: 'not_editable',
        });
      }
      const html = storage.prepareHtml(req.file.buffer);
      const pageKey = cryptoLib.unwrapPageKey(page.wrapped_key);
      const blob = cryptoLib.encryptWithKey(html, pageKey);
      storage.savePageBlob(page.id, blob);
      db.updatePageFile(page.id, req.file.size, req.file.originalname);
      updates.html = true;
    }

    // --- Slug ---
    if (req.body.slug !== undefined) {
      const next = req.body.slug ? String(req.body.slug).trim().toLowerCase() : null;
      if (next === null || next === '') {
        // Clear the slug — page falls back to its random ID.
        db.setPageSlug(page.id, null);
      } else if (next !== page.slug) {
        const slugError = tiers.validateProSlug(next);
        if (slugError) return res.status(400).json({ error: slugError });
        const existing = db.getPageBySlug(next);
        if (existing && existing.id !== page.id) {
          return res.status(409).json({ error: 'This URL is already taken' });
        }
        db.setPageSlug(page.id, next);
      }
      updates.slug = next || null;
    }

    // --- Expiration ---
    if (req.body.expiration !== undefined) {
      const exp = String(req.body.expiration);
      if (!(exp in EXPIRATION_OPTIONS)) return res.status(400).json({ error: 'Invalid expiration option' });
      const days = EXPIRATION_OPTIONS[exp];
      const next = days === 0
        ? new Date('9999-12-31T23:59:59.999Z')
        : new Date(Date.now() + days * 24 * 60 * 60 * 1000);
      db.updatePageExpiration(page.id, next.toISOString());
      updates.expiresAt = next.toISOString();
    }

    // --- Public toggle ---
    if (req.body.isPublic !== undefined) {
      const wantsPublic = req.body.isPublic === 'true' || req.body.isPublic === true;
      db.updatePageIsPublic(page.id, wantsPublic);
      updates.isPublic = wantsPublic;
    }

    // --- View cap ---
    if (req.body.viewCap !== undefined) {
      const raw = String(req.body.viewCap).trim();
      if (raw === '') {
        // Empty string clears the cap → fall back to tier default at read time.
        db.updatePageViewCap(page.id, null);
        updates.viewCap = null;
      } else {
        const parsed = parseInt(raw, 10);
        if (!Number.isFinite(parsed) || parsed < 1) {
          return res.status(400).json({ error: 'View cap must be a positive integer' });
        }
        db.updatePageViewCap(page.id, parsed);
        updates.viewCap = parsed;
      }
    }

    res.json({ ok: true, updates });
  } catch (err) {
    console.error('Page edit error:', err);
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE' || err.message?.includes('UNIQUE constraint failed')) {
      return res.status(409).json({ error: 'This URL is already taken' });
    }
    res.status(500).json({ error: 'Edit failed' });
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

// GET /:slug — serve view.html for the password prompt. Looks up the
// page so it can SSR-inject metadata (is_public, hide_footer) into the
// HTML — view.html reads this to auto-unlock public pages and hide the
// "Hosted on PageGate" footer for Pro pages.
//
// Slug regex here is intentionally lenient (matches any plausible slug
// shape), even looser than tiers.PRO_SLUG_REGEX, so older slugs created
// before the spec tightening still resolve.
const VIEW_TEMPLATE_PATH = path.join(publicDir, 'view.html');
let viewTemplate = null;
function renderViewHtml(page) {
  if (!viewTemplate) viewTemplate = fs.readFileSync(VIEW_TEMPLATE_PATH, 'utf-8');
  const tier = page?.tier_at_creation || tiers.TIER.ANONYMOUS;
  const meta = {
    isPublic: !!page?.is_public,
    hideFooter: !!tiers.RULES[tier].footerHidden,
  };
  // JSON.stringify is safe inside a JSON-typed script tag; no HTML
  // escaping needed because the parser treats the contents as opaque.
  return viewTemplate.replace('"__PAGE_META__"', JSON.stringify(meta));
}

app.get('/:pageIdOrSlug', (req, res) => {
  const param = req.params.pageIdOrSlug;
  const looksLikeNanoid = /^[A-Za-z0-9_-]{8}$/.test(param);
  const looksLikeSlug = /^[a-z0-9][a-z0-9-]+[a-z0-9]$/.test(param);

  // Lookup priority: pageId first, then slug. Both are tried because the
  // shapes overlap — the minimum-length valid Pro slug `aa-bb-cc` is also
  // a valid 8-char nanoid shape, and we don't want public pages on those
  // slugs to lose their SSR-injected meta (auto-unlock + hidden footer).
  let page = null;
  if (looksLikeNanoid) page = db.getPage(param);
  if (!page && looksLikeSlug) page = db.getPageBySlug(param);

  if (!page) {
    // Both nanoid- and slug-shaped misses serve view.html so the verify
    // route can surface the standard "no longer available" copy. This
    // matters for expired Pro slugs in particular — `getPageBySlug`
    // filters by expiry, and after the nightly cleanup deletes the row
    // there's no way to distinguish "expired" from "never existed", so
    // we render the same expired-page UX either way (consistent with
    // the long-standing nanoid behavior). True garbage (anything that
    // doesn't match either shape) still 404s.
    if (looksLikeNanoid || looksLikeSlug) {
      res.set('X-Frame-Options', 'DENY');
      return res.type('html').send(renderViewHtml(null));
    }
    return res.status(404).send('Not found');
  }

  res.set('X-Frame-Options', 'DENY');
  res.type('html').send(renderViewHtml(page));
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
