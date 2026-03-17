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
    expires_at TEXT NOT NULL
  )
`);

const insertStmt = db.prepare(`
  INSERT INTO pages (id, password_hash, original_filename, file_size, created_at, expires_at)
  VALUES (@id, @password_hash, @original_filename, @file_size, @created_at, @expires_at)
`);

const getStmt = db.prepare(`
  SELECT * FROM pages WHERE id = ? AND expires_at > ?
`);

const deleteExpiredStmt = db.prepare(`
  DELETE FROM pages WHERE expires_at < ?
`);

module.exports = {
  insertPage(page) {
    return insertStmt.run(page);
  },
  getPage(id) {
    return getStmt.get(id, new Date().toISOString());
  },
  deleteExpired() {
    return deleteExpiredStmt.run(new Date().toISOString());
  },
};
