'use strict';

const { queries } = require('./db');

const DEMO_USERS = [
  { username: 'alice', password: 'Alice-Str0ng!Pass', role: 'user' },
  { username: 'bob', password: 'Bob-Str0ng!Pass42', role: 'user' },
  { username: 'admin', password: 'Admin-Str0ng!Pass', role: 'admin' }
];

const DEMO_POSTS = [
  { owner: 'alice', title: 'Welcome to Secure Notes', content: 'This note is readable by any authenticated user.' },
  { owner: 'alice', title: 'Private reminder', content: 'Only alice may delete this note.' },
  { owner: 'bob', title: 'Hello from Bob', content: 'Parameterised queries keep this text safe, quotes: \' " ; --' }
];

/** Idempotent: safe to call from `npm run seed` or from the test bootstrap. */
async function seedIfEmpty({ hashPassword }) {
  if (queries.listUsers().length > 0) return false;

  const ids = {};
  for (const user of DEMO_USERS) {
    const hash = await hashPassword(user.password);
    const info = queries.insertUser(user.username, hash, user.role);
    ids[user.username] = Number(info.lastInsertRowid);
  }

  for (const post of DEMO_POSTS) {
    queries.insertPost(ids[post.owner], post.title, post.content);
  }

  return true;
}

module.exports = { seedIfEmpty, DEMO_USERS };
