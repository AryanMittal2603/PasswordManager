'use strict';
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const db = new Database(path.join(__dirname, '..', 'data', 'vault.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT UNIQUE NOT NULL,
    email        TEXT,
    password_hash TEXT NOT NULL,
    role         TEXT NOT NULL DEFAULT 'member',   -- 'admin' | 'member'
    can_view     INTEGER NOT NULL DEFAULT 1,
    can_create   INTEGER NOT NULL DEFAULT 0,
    can_edit     INTEGER NOT NULL DEFAULT 0,
    can_delete   INTEGER NOT NULL DEFAULT 0,
    is_active    INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS credentials (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    title        TEXT NOT NULL,
    folder       TEXT NOT NULL DEFAULT 'General',
    username     TEXT,
    url          TEXT,
    notes        TEXT,
    pw_ciphertext TEXT NOT NULL,
    pw_iv        TEXT NOT NULL,
    pw_tag       TEXT NOT NULL,
    created_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    updated_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER,
    username    TEXT,
    action      TEXT NOT NULL,
    target      TEXT,
    detail      TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// Seed the initial admin account from env on first run.
function seedAdmin() {
  const count = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
  if (count > 0) return;

  const username = process.env.ADMIN_USERNAME || 'admin';
  const email = process.env.ADMIN_EMAIL || '';
  const password = process.env.ADMIN_PASSWORD;
  if (!password) {
    throw new Error('No users exist and ADMIN_PASSWORD is not set. Set it in .env to seed the admin.');
  }
  const hash = bcrypt.hashSync(password, 12);
  db.prepare(`
    INSERT INTO users (username, email, password_hash, role, can_view, can_create, can_edit, can_delete)
    VALUES (?, ?, ?, 'admin', 1, 1, 1, 1)
  `).run(username, email, hash);
  console.log(`\n  Seeded admin account "${username}". Log in with the ADMIN_PASSWORD from your .env, then change it.\n`);
}

function logAction(user, action, target, detail) {
  db.prepare(`
    INSERT INTO audit_log (user_id, username, action, target, detail)
    VALUES (?, ?, ?, ?, ?)
  `).run(user ? user.id : null, user ? user.username : null, action, target || null, detail || null);
}

module.exports = { db, seedAdmin, logAction };
