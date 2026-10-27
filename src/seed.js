'use strict';

/**
 * Seed the database with demo users and notes.
 *
 * Usage: npm run seed
 * Passwords are hashed with bcrypt here - the plaintext values below are
 * throw-away demo credentials and are never reused anywhere else.
 */
require('dotenv').config();

const config = require('./config');
const { init } = require('./db');
const { hashPassword } = require('./security/passwords');
const { seedIfEmpty } = require('./seed-data');

async function main() {
  init(config.dbPath);
  const created = await seedIfEmpty({ hashPassword });
  console.log(created ? 'Database seeded.' : 'Database already contains users - nothing to do.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
