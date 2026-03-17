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


const insertStmt = db.prepare(`
  INSERT INTO pages (id, password_hash, original_filename, file_size, created_at, expires_at, encryption_salt)
  VALUES (@id, @password_hash, @original_filename, @file_size, @created_at, @expires_at, @encryption_salt)
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
};
