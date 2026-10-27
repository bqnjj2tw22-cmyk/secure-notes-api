'use strict';

/**
 * Data-access layer.
 *
 * Uses the built-in `node:sqlite` driver (Node.js >= 22.5) so the project has no
 * native build step.  Every statement that touches user input is a *prepared
 * statement with bound parameters* - string concatenation is never used to build
 * SQL, which is the primary defence against SQL injection.
 *
 * The module never touches the file system directly: `data/` is part of the
 * repository (kept by `data/.gitkeep`) and a deployment that points `DB_PATH`
 * somewhere else is responsible for that directory, exactly like it is for a
 * PostgreSQL data directory.  No dynamic path ever reaches an `fs` call.
 */
const { DatabaseSync } = require('node:sqlite');

let db;

/**
 * @param {string} dbPath  File path, or ':memory:' for tests.
 */
function init(dbPath) {
  try {
    db = new DatabaseSync(dbPath);
  } catch (err) {
    // Turn SQLite's terse "unable to open database file" into an actionable error.
    if (dbPath !== ':memory:' && /unable to open/i.test(String(err && err.message))) {
      throw new Error(
        `Cannot open the database at "${dbPath}". Create its directory first ` +
          '(the default ./data is part of the repository) or point DB_PATH at an existing directory.'
      );
    }
    throw err;
  }

  // Defence in depth: even if an injection attempt ever got through, SQLite's
  // foreign keys and strict typing limit the damage.
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec('PRAGMA journal_mode = WAL;');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      username      TEXT    NOT NULL UNIQUE,
      password_hash TEXT    NOT NULL,
      role          TEXT    NOT NULL DEFAULT 'user',
      created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS posts (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title      TEXT    NOT NULL,
      content    TEXT    NOT NULL,
      created_at TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS login_attempts (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      username   TEXT    NOT NULL,
      ip         TEXT    NOT NULL,
      success    INTEGER NOT NULL,
      created_at TEXT    NOT NULL DEFAULT (datetime('now'))
    );
  `);

  return db;
}

function getDb() {
  if (!db) {
    throw new Error('Database not initialised - call init() first');
  }
  return db;
}

/** Parameterised lookups.  Note the `?` placeholders - never string interpolation. */
const queries = {
  findUserByUsername: (username) =>
    getDb().prepare('SELECT id, username, password_hash, role FROM users WHERE username = ?').get(username),

  findUserById: (id) => getDb().prepare('SELECT id, username, role FROM users WHERE id = ?').get(id),

  insertUser: (username, passwordHash, role = 'user') =>
    getDb()
      .prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)')
      .run(username, passwordHash, role),

  listUsers: () =>
    getDb().prepare('SELECT id, username, role, created_at FROM users ORDER BY id').all(),

  listPosts: () =>
    getDb()
      .prepare(
        `SELECT p.id, p.title, p.content, p.created_at, u.username AS author
           FROM posts p JOIN users u ON u.id = p.owner_id
          ORDER BY p.id DESC`
      )
      .all(),

  listPostsByOwner: (ownerId) =>
    getDb()
      .prepare('SELECT id, title, content, created_at FROM posts WHERE owner_id = ? ORDER BY id DESC')
      .all(ownerId),

  insertPost: (ownerId, title, content) =>
    getDb()
      .prepare('INSERT INTO posts (owner_id, title, content) VALUES (?, ?, ?)')
      .run(ownerId, title, content),

  // Ownership is part of the WHERE clause: a user cannot delete another user's
  // row even if they guess its numeric id (prevents IDOR / broken access control).
  deletePostOwnedBy: (id, ownerId) =>
    getDb().prepare('DELETE FROM posts WHERE id = ? AND owner_id = ?').run(id, ownerId),

  logLoginAttempt: (username, ip, success) =>
    getDb()
      .prepare('INSERT INTO login_attempts (username, ip, success) VALUES (?, ?, ?)')
      .run(username, ip, success ? 1 : 0),

  recentFailures: (username, ip, minutes = 15) =>
    getDb()
      .prepare(
        `SELECT COUNT(*) AS n FROM login_attempts
          WHERE success = 0 AND (username = ? OR ip = ?)
            AND created_at >= datetime('now', ?)`
      )
      .get(username, ip, `-${minutes} minutes`)
};

module.exports = { init, getDb, queries };
