const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');

const defaultDataDir = path.join(__dirname, '..', 'data');
const dbPath = process.env.DB_PATH || path.join(defaultDataDir, 'reader-library.db');
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new DatabaseSync(dbPath, { timeout: 5000 });
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

// Small transaction helper matching the rest of the app API.
db.transaction = (fn) => (...args) => {
  db.exec('BEGIN IMMEDIATE;');
  try {
    const result = fn(...args);
    db.exec('COMMIT;');
    return result;
  } catch (err) {
    try { db.exec('ROLLBACK;'); } catch (_) {}
    throw err;
  }
};

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('participant','supervisor','manager')),
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS participants (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  lifetime_minutes INTEGER NOT NULL DEFAULT 0 CHECK(lifetime_minutes >= 0),
  wallet_minutes INTEGER NOT NULL DEFAULT 0 CHECK(wallet_minutes >= 0),
  reading_minutes INTEGER NOT NULL DEFAULT 0 CHECK(reading_minutes >= 0),
  listening_minutes INTEGER NOT NULL DEFAULT 0 CHECK(listening_minutes >= 0)
);

CREATE TABLE IF NOT EXISTS ranks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  icon TEXT NOT NULL DEFAULT '📖',
  description TEXT,
  min_minutes INTEGER NOT NULL UNIQUE,
  sort_order INTEGER NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS weekly_goals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  week_number INTEGER NOT NULL UNIQUE,
  title TEXT NOT NULL,
  reading_target INTEGER NOT NULL DEFAULT 0,
  listening_target INTEGER NOT NULL DEFAULT 0,
  description TEXT,
  starts_at TEXT NOT NULL,
  ends_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed'))
);

CREATE TABLE IF NOT EXISTS activity_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  participant_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  weekly_goal_id INTEGER NOT NULL REFERENCES weekly_goals(id) ON DELETE CASCADE,
  activity_type TEXT NOT NULL CHECK(activity_type IN ('reading','listening')),
  minutes INTEGER NOT NULL CHECK(minutes > 0),
  notes TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
  submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  reviewed_at TEXT,
  reviewed_by INTEGER REFERENCES users(id),
  review_note TEXT,
  UNIQUE(participant_id, weekly_goal_id, activity_type, minutes, submitted_at)
);

CREATE TABLE IF NOT EXISTS rewards (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  icon TEXT NOT NULL DEFAULT '🎁',
  image_url TEXT,
  description TEXT,
  price_minutes INTEGER NOT NULL CHECK(price_minutes > 0),
  quantity INTEGER NOT NULL DEFAULT 0 CHECK(quantity >= 0),
  available_from TEXT,
  available_until TEXT,
  min_rank_id INTEGER REFERENCES ranks(id),
  purchase_limit INTEGER,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS purchases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  participant_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reward_id INTEGER NOT NULL REFERENCES rewards(id),
  price_minutes INTEGER NOT NULL,
  purchased_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vouchers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  purchase_id INTEGER NOT NULL UNIQUE REFERENCES purchases(id) ON DELETE CASCADE,
  code TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'unused' CHECK(status IN ('unused','used','expired','cancelled')),
  expires_at TEXT,
  used_at TEXT,
  used_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  participant_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK(kind IN ('earn','spend','adjustment','reversal')),
  activity_type TEXT,
  amount INTEGER NOT NULL,
  wallet_before INTEGER NOT NULL,
  wallet_after INTEGER NOT NULL,
  lifetime_before INTEGER NOT NULL,
  lifetime_after INTEGER NOT NULL,
  reference_type TEXT,
  reference_id INTEGER,
  reason TEXT,
  created_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  read_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_activity_status ON activity_logs(status);
CREATE INDEX IF NOT EXISTS idx_activity_participant ON activity_logs(participant_id);
CREATE INDEX IF NOT EXISTS idx_tx_participant ON transactions(participant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_voucher_code ON vouchers(code);
`);

module.exports = db;
