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
  INSERT INTO pages (id, password_hash, original_filename, file_size, created_at, expires_at, encryption_salt)
  VALUES (@id, @password_hash, @original_filename, @file_size, @created_at, @expires_at, @encryption_salt)
`);

const updatePagePasswordAndSaltStmt = db.prepare(`
  UPDATE pages SET password_hash = ?, encryption_salt = ? WHERE id = ?
`);

const getStmt = db.prepare(`
  SELECT * FROM pages WHERE id = ? AND expires_at > ?
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
const getUserPagesStmt = db.prepare(`
  SELECT id, original_filename, file_size, slug, created_at, expires_at FROM pages WHERE user_id = ? ORDER BY created_at DESC
`);
const setPageOwnerStmt = db.prepare(`UPDATE pages SET user_id = ? WHERE id = ?`);
const getPageBySlugStmt = db.prepare(`SELECT * FROM pages WHERE slug = ? AND expires_at > ?`);
const setPageSlugStmt = db.prepare(`UPDATE pages SET slug = ? WHERE id = ?`);
const updatePagePasswordStmt = db.prepare(`UPDATE pages SET password_hash = ? WHERE id = ?`);
const deletePageStmt = db.prepare(`DELETE FROM pages WHERE id = ?`);
const getPageByIdOnlyStmt = db.prepare(`SELECT * FROM pages WHERE id = ?`);
const updatePageExpirationStmt = db.prepare(`UPDATE pages SET expires_at = ? WHERE id = ?`);
const updatePageEncryptionSaltStmt = db.prepare(`UPDATE pages SET encryption_salt = ? WHERE id = ?`);

// Atomic insert with owner and slug in a single transaction
const insertPageAtomicFn = db.transaction((page) => {
  insertStmt.run({
    id: page.id,
    password_hash: page.password_hash,
    original_filename: page.original_filename,
    file_size: page.file_size,
    created_at: page.created_at,
    expires_at: page.expires_at,
    encryption_salt: page.encryption_salt,
  });
  if (page.user_id) {
    setPageOwnerStmt.run(page.user_id, page.id);
  }
  if (page.slug) {
    setPageSlugStmt.run(page.slug, page.id);
  }
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
  updatePagePasswordAndSalt(pageId, passwordHash, salt) {
    return updatePagePasswordAndSaltStmt.run(passwordHash, salt, pageId);
  },
  deletePageById(pageId) {
    return deletePageStmt.run(pageId);
  },
};
