const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'pagegate.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS pages (
    id TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    original_filename TEXT,
    file_size INTEGER,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    encryption_salt TEXT,
    user_id TEXT,
    slug TEXT UNIQUE
  )
`);

// Migration: add encryption_salt column if it doesn't exist (for existing DBs)
try {
  db.exec(`ALTER TABLE pages ADD COLUMN encryption_salt TEXT`);
} catch (e) {
  // Column already exists — ignore
}

// === Tiered-plan migration (added 2026-04-28; see docs/PRD.md, docs/TIERS.md)
//
// Each ALTER is wrapped in try/catch to make this migration idempotent —
// matches the pattern used elsewhere in this file. Adding a new column?
// Append another guarded ALTER below; do not rewrite the CREATE TABLE.
//
//   wrapped_key       — base64 of page key wrapped with PAGE_KEY_MASTER.
//                       null = password-derived (Tier 1 / legacy).
//   tier_at_creation  — 1 (anonymous), 2 (account), 3 (Pro). Informational;
//                       runtime crypto path is decided by `wrapped_key`.
//   view_count        — incremented on each successful unlock.
//   view_cap          — per-page cap. null = use the tier default at read time.
//   is_public         — Pro-only: skip the password gate entirely.
//   archived_at       — Phase 5 (Pro downgrade grace) hook; null = active.
for (const stmt of [
  `ALTER TABLE pages ADD COLUMN wrapped_key TEXT`,
  `ALTER TABLE pages ADD COLUMN tier_at_creation INTEGER`,
  `ALTER TABLE pages ADD COLUMN view_count INTEGER DEFAULT 0`,
  `ALTER TABLE pages ADD COLUMN view_cap INTEGER`,
  `ALTER TABLE pages ADD COLUMN is_public INTEGER DEFAULT 0`,
  `ALTER TABLE pages ADD COLUMN archived_at TEXT`,
]) {
  try { db.exec(stmt); } catch (e) { /* column already exists */ }
}

// Backfill tier_at_creation for legacy rows. Best-effort:
//   - rows with a user_id were created under the existing Pro plumbing → 3
//   - rows without a user_id were anonymous uploads → 1
// Pages that pre-date the tiered plan model don't fit perfectly (their
// limits weren't enforced), but `tier_at_creation` is informational; the
// live crypto path is driven by `wrapped_key`.
db.exec(`
  UPDATE pages SET tier_at_creation = 3
   WHERE tier_at_creation IS NULL AND user_id IS NOT NULL
`);
db.exec(`
  UPDATE pages SET tier_at_creation = 1
   WHERE tier_at_creation IS NULL AND user_id IS NULL
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS feedback (
    id TEXT PRIMARY KEY,
    text TEXT NOT NULL,
    status TEXT DEFAULT 'open',
    votes INTEGER DEFAULT 1,
    created_at TEXT NOT NULL
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS feedback_votes (
    item_id TEXT NOT NULL,
    ip_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (item_id, ip_hash)
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS stripe_events (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    claimed_at TEXT NOT NULL,
    processed_at TEXT,
    last_error TEXT
  )
`);
try {
  db.exec(`ALTER TABLE stripe_events ADD COLUMN claimed_at TEXT`);
} catch (e) {
  // Column already exists — ignore
}
try {
  db.exec(`ALTER TABLE stripe_events ADD COLUMN last_error TEXT`);
} catch (e) {
  // Column already exists — ignore
}
try {
  db.exec(`
    UPDATE stripe_events
    SET claimed_at = COALESCE(NULLIF(claimed_at, ''), NULLIF(processed_at, ''), datetime('now'))
    WHERE claimed_at IS NULL OR claimed_at = ''
  `);
} catch (e) {
  // Best-effort migration for local databases that ran an earlier PR revision.
}

// === Pro tier tables ===
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    clerk_id TEXT PRIMARY KEY,
    email TEXT,
    is_pro INTEGER DEFAULT 0,
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    pro_expires_at TEXT,
    created_at TEXT NOT NULL
  )
`);

// Migration: add user_id column to pages if it doesn't exist
try {
  db.exec(`ALTER TABLE pages ADD COLUMN user_id TEXT REFERENCES users(clerk_id)`);
} catch (e) {
  // Column already exists — ignore
}

// Migration: add slug column to pages
try {
  db.exec(`ALTER TABLE pages ADD COLUMN slug TEXT`);
} catch (e) {
  // Column already exists — ignore
}
db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_pages_slug ON pages(slug) WHERE slug IS NOT NULL`);


const insertStmt = db.prepare(`
  INSERT INTO pages (
    id, password_hash, original_filename, file_size,
    created_at, expires_at, encryption_salt,
    wrapped_key, tier_at_creation, view_cap, is_public
  )
  VALUES (
    @id, @password_hash, @original_filename, @file_size,
    @created_at, @expires_at, @encryption_salt,
    @wrapped_key, @tier_at_creation, @view_cap, @is_public
  )
`);

const updatePagePasswordAndSaltStmt = db.prepare(`
  UPDATE pages SET password_hash = ?, encryption_salt = ? WHERE id = ?
`);

const getStmt = db.prepare(`
  SELECT * FROM pages WHERE id = ? AND expires_at > ?
`);

const incrementViewCountStmt = db.prepare(`
  UPDATE pages SET view_count = view_count + 1 WHERE id = ?
`);

const selectExpiredStmt = db.prepare(`
  SELECT id FROM pages WHERE expires_at < ?
`);
const deleteExpiredStmt = db.prepare(`
  DELETE FROM pages WHERE expires_at < ?
`);

// Feedback statements
const insertFeedbackStmt = db.prepare(`
  INSERT INTO feedback (id, text, created_at) VALUES (?, ?, ?)
`);
const listFeedbackStmt = db.prepare(`
  SELECT * FROM feedback ORDER BY votes DESC, created_at DESC
`);
const getFeedbackStmt = db.prepare(`
  SELECT * FROM feedback WHERE id = ?
`);
const voteFeedbackStmt = db.prepare(`
  UPDATE feedback SET votes = votes + 1 WHERE id = ?
`);
const insertVoteStmt = db.prepare(`
  INSERT OR IGNORE INTO feedback_votes (item_id, ip_hash, created_at) VALUES (?, ?, ?)
`);
const hasVotedStmt = db.prepare(`
  SELECT 1 FROM feedback_votes WHERE item_id = ? AND ip_hash = ?
`);
const updateStatusStmt = db.prepare(`
  UPDATE feedback SET status = ? WHERE id = ?
`);
const deleteFeedbackStmt = db.prepare(`
  DELETE FROM feedback WHERE id = ?
`);
const deleteFeedbackVotesStmt = db.prepare(`
  DELETE FROM feedback_votes WHERE item_id = ?
`);
const listVotedByIpStmt = db.prepare(`
  SELECT item_id FROM feedback_votes WHERE ip_hash = ?
`);

// User statements
const upsertUserStmt = db.prepare(`
  INSERT INTO users (clerk_id, email, created_at) VALUES (?, ?, ?)
  ON CONFLICT(clerk_id) DO UPDATE SET email = excluded.email
`);
const getUserStmt = db.prepare(`SELECT * FROM users WHERE clerk_id = ?`);
const updateUserProStmt = db.prepare(`
  UPDATE users SET is_pro = ?, stripe_customer_id = ?, stripe_subscription_id = ?, pro_expires_at = ? WHERE clerk_id = ?
`);
const getUserByStripeCustomerStmt = db.prepare(`SELECT * FROM users WHERE stripe_customer_id = ?`);
const insertStripeEventStmt = db.prepare(`
  INSERT OR IGNORE INTO stripe_events (id, type, claimed_at, processed_at, last_error)
  VALUES (?, ?, ?, '', NULL)
`);
const reclaimStripeEventStmt = db.prepare(`
  UPDATE stripe_events
  SET type = ?, claimed_at = ?, last_error = NULL
  WHERE id = ?
    AND (processed_at IS NULL OR processed_at = '')
    AND claimed_at < ?
`);
const markStripeEventProcessedStmt = db.prepare(`
  UPDATE stripe_events SET processed_at = ?, last_error = NULL WHERE id = ?
`);
const releaseStripeEventStmt = db.prepare(`
  DELETE FROM stripe_events WHERE id = ? AND (processed_at IS NULL OR processed_at = '')
`);
const getUserPagesStmt = db.prepare(`
  SELECT id, original_filename, file_size, slug, created_at, expires_at,
         view_count, view_cap, is_public, tier_at_creation, archived_at
    FROM pages WHERE user_id = ? ORDER BY created_at DESC
`);
const setPageOwnerStmt = db.prepare(`UPDATE pages SET user_id = ? WHERE id = ?`);
const getPageBySlugStmt = db.prepare(`SELECT * FROM pages WHERE slug = ? AND expires_at > ?`);
const setPageSlugStmt = db.prepare(`UPDATE pages SET slug = ? WHERE id = ?`);
const updatePagePasswordStmt = db.prepare(`UPDATE pages SET password_hash = ? WHERE id = ?`);
const deletePageStmt = db.prepare(`DELETE FROM pages WHERE id = ?`);
const getPageByIdOnlyStmt = db.prepare(`SELECT * FROM pages WHERE id = ?`);
const updatePageExpirationStmt = db.prepare(`UPDATE pages SET expires_at = ? WHERE id = ?`);
const updatePageEncryptionSaltStmt = db.prepare(`UPDATE pages SET encryption_salt = ? WHERE id = ?`);

// Atomic insert with owner and slug in a single transaction.
// New tier-related columns default to safe values when omitted so legacy
// callers (and tests) keep working.
const insertPageAtomicFn = db.transaction((page) => {
  insertStmt.run({
    id: page.id,
    password_hash: page.password_hash,
    original_filename: page.original_filename,
    file_size: page.file_size,
    created_at: page.created_at,
    expires_at: page.expires_at,
    encryption_salt: page.encryption_salt ?? null,
    wrapped_key: page.wrapped_key ?? null,
    tier_at_creation: page.tier_at_creation ?? null,
    view_cap: page.view_cap ?? null,
    is_public: page.is_public ? 1 : 0,
  });
  if (page.user_id) {
    setPageOwnerStmt.run(page.user_id, page.id);
  }
  if (page.slug) {
    setPageSlugStmt.run(page.slug, page.id);
  }
});

const STRIPE_EVENT_CLAIM_TTL = 10 * 60 * 1000;
const claimStripeEventFn = db.transaction((eventId, type) => {
  const now = new Date();
  const claimedAt = now.toISOString();
  const inserted = insertStripeEventStmt.run(eventId, type, claimedAt);
  if (inserted.changes > 0) return true;

  const staleBefore = new Date(now.getTime() - STRIPE_EVENT_CLAIM_TTL).toISOString();
  return reclaimStripeEventStmt.run(type, claimedAt, eventId, staleBefore).changes > 0;
});

module.exports = {
  insertPage(page) {
    return insertStmt.run(page);
  },
  getPage(id) {
    return getStmt.get(id, new Date().toISOString());
  },
  getExpiredIds() {
    return selectExpiredStmt.all(new Date().toISOString()).map(r => r.id);
  },
  deleteExpired() {
    return deleteExpiredStmt.run(new Date().toISOString());
  },
  insertFeedback(id, text) {
    return insertFeedbackStmt.run(id, text, new Date().toISOString());
  },
  listFeedback() {
    return listFeedbackStmt.all();
  },
  getFeedback(id) {
    return getFeedbackStmt.get(id);
  },
  voteFeedback(itemId, ipHash) {
    const inserted = insertVoteStmt.run(itemId, ipHash, new Date().toISOString());
    if (inserted.changes > 0) {
      voteFeedbackStmt.run(itemId);
      return true;
    }
    return false;
  },
  hasVoted(itemId, ipHash) {
    return !!hasVotedStmt.get(itemId, ipHash);
  },
  listVotedByIp(ipHash) {
    return listVotedByIpStmt.all(ipHash).map(r => r.item_id);
  },
  updateFeedbackStatus(id, status) {
    return updateStatusStmt.run(status, id);
  },
  deleteFeedback(id) {
    deleteFeedbackVotesStmt.run(id);
    return deleteFeedbackStmt.run(id);
  },

  // User methods
  getOrCreateUser(clerkId, email) {
    upsertUserStmt.run(clerkId, email, new Date().toISOString());
    return getUserStmt.get(clerkId);
  },
  getUser(clerkId) {
    return getUserStmt.get(clerkId);
  },
  updateUserPro(clerkId, { isPro, stripeCustomerId, stripeSubscriptionId, proExpiresAt }) {
    return updateUserProStmt.run(
      isPro ? 1 : 0,
      stripeCustomerId || null,
      stripeSubscriptionId || null,
      proExpiresAt || null,
      clerkId
    );
  },
  getUserByStripeCustomer(stripeCustomerId) {
    return getUserByStripeCustomerStmt.get(stripeCustomerId);
  },
  claimStripeEvent(eventId, type) {
    return claimStripeEventFn(eventId, type);
  },
  markStripeEventProcessed(eventId) {
    return markStripeEventProcessedStmt.run(new Date().toISOString(), eventId);
  },
  releaseStripeEvent(eventId) {
    return releaseStripeEventStmt.run(eventId);
  },
  getUserPages(clerkId) {
    return getUserPagesStmt.all(clerkId);
  },
  setPageOwner(pageId, clerkId) {
    return setPageOwnerStmt.run(clerkId, pageId);
  },
  getPageBySlug(slug) {
    return getPageBySlugStmt.get(slug, new Date().toISOString());
  },
  setPageSlug(pageId, slug) {
    return setPageSlugStmt.run(slug, pageId);
  },
  updatePagePassword(pageId, passwordHash) {
    return updatePagePasswordStmt.run(passwordHash, pageId);
  },
  deletePage(pageId) {
    return deletePageStmt.run(pageId);
  },
  getPageById(pageId) {
    return getPageByIdOnlyStmt.get(pageId);
  },
  updatePageExpiration(pageId, expiresAt) {
    return updatePageExpirationStmt.run(expiresAt, pageId);
  },
  updatePageEncryptionSalt(pageId, salt) {
    return updatePageEncryptionSaltStmt.run(salt, pageId);
  },
  insertPageAtomic(page) {
    return insertPageAtomicFn(page);
  },
  incrementViewCount(pageId) {
    return incrementViewCountStmt.run(pageId);
  },
  updatePagePasswordAndSalt(pageId, passwordHash, salt) {
    return updatePagePasswordAndSaltStmt.run(passwordHash, salt, pageId);
  },
  deletePageById(pageId) {
    return deletePageStmt.run(pageId);
  },
};
