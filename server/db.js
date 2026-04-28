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
    encryption_salt TEXT
  )
`);

// Migration: add encryption_salt column if it doesn't exist (for existing DBs)
try {
  db.exec(`ALTER TABLE pages ADD COLUMN encryption_salt TEXT`);
} catch (e) {
  // Column already exists — ignore
}

// === Users table ===
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    stripe_customer_id TEXT,
    subscription_status TEXT DEFAULT 'none',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )
`);

// Migration: add user_id and page_password columns to pages
try {
  db.exec(`ALTER TABLE pages ADD COLUMN user_id TEXT`);
} catch (e) { /* already exists */ }
try {
  db.exec(`ALTER TABLE pages ADD COLUMN page_password TEXT`);
} catch (e) { /* already exists */ }

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
    processed_at TEXT NOT NULL
  )
`);


const insertStmt = db.prepare(`
  INSERT INTO pages (id, password_hash, original_filename, file_size, created_at, expires_at, encryption_salt, user_id, page_password)
  VALUES (@id, @password_hash, @original_filename, @file_size, @created_at, @expires_at, @encryption_salt, @user_id, @page_password)
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
const insertUserStmt = db.prepare(`INSERT INTO users (id, email, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`);
const getUserByEmailStmt = db.prepare(`SELECT * FROM users WHERE email = ?`);
const getUserByIdStmt = db.prepare(`SELECT * FROM users WHERE id = ?`);
const updateUserStripeStmt = db.prepare(`UPDATE users SET stripe_customer_id = ?, subscription_status = ?, updated_at = ? WHERE id = ?`);
const updateSubscriptionStatusStmt = db.prepare(`UPDATE users SET subscription_status = ?, updated_at = ? WHERE id = ?`);
const getUserByStripeCustomerStmt = db.prepare(`SELECT * FROM users WHERE stripe_customer_id = ?`);

// Stripe webhook idempotency statements
const getStripeEventStmt = db.prepare(`SELECT id FROM stripe_events WHERE id = ?`);
const insertStripeEventStmt = db.prepare(`INSERT INTO stripe_events (id, type, processed_at) VALUES (?, ?, ?)`);

// Dashboard page statements
const getPagesByUserStmt = db.prepare(`SELECT id, original_filename, file_size, created_at, expires_at, page_password FROM pages WHERE user_id = ? ORDER BY created_at DESC`);
const deletePageByUserStmt = db.prepare(`DELETE FROM pages WHERE id = ? AND user_id = ?`);
const expireUserPagesStmt = db.prepare(`UPDATE pages SET expires_at = ?, page_password = NULL WHERE user_id = ?`);


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
  insertUser(id, email, passwordHash) {
    const now = new Date().toISOString();
    return insertUserStmt.run(id, email, passwordHash, now, now);
  },
  getUserByEmail(email) {
    return getUserByEmailStmt.get(email);
  },
  getUserById(id) {
    return getUserByIdStmt.get(id);
  },
  updateUserStripe(id, stripeCustomerId, subscriptionStatus) {
    return updateUserStripeStmt.run(stripeCustomerId, subscriptionStatus, new Date().toISOString(), id);
  },
  updateSubscriptionStatus(id, status) {
    return updateSubscriptionStatusStmt.run(status, new Date().toISOString(), id);
  },
  getUserByStripeCustomer(stripeCustomerId) {
    return getUserByStripeCustomerStmt.get(stripeCustomerId);
  },
  hasProcessedStripeEvent(eventId) {
    return !!getStripeEventStmt.get(eventId);
  },
  markStripeEventProcessed(eventId, type) {
    return insertStripeEventStmt.run(eventId, type, new Date().toISOString());
  },
  getPagesByUser(userId) {
    return getPagesByUserStmt.all(userId);
  },
  deletePageByUser(pageId, userId) {
    return deletePageByUserStmt.run(pageId, userId);
  },
  expireUserPages(userId) {
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    return expireUserPagesStmt.run(expiresAt, userId);
  },
};
