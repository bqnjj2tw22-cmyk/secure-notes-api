'use strict';

/**
 * Password hashing.
 *
 * bcrypt is used instead of a plain hash (SHA-256) because it is deliberately
 * slow and salted:
 *   - a per-password random salt defeats rainbow tables and "same password ->
 *     same hash" correlation;
 *   - the cost factor (12) makes an offline brute-force ~4000x more expensive
 *     than a single SHA-256 round.
 */
const bcrypt = require('bcryptjs');
const config = require('../config');

const BCRYPT_ROUNDS = config.bcryptRounds;

// A fixed hash used when the username does not exist.  Comparing against it
// keeps the response time of "unknown user" close to "wrong password", which
// removes the timing side channel used for user enumeration.
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing-equalisation', BCRYPT_ROUNDS);

/** Reject absurdly long passwords: bcrypt silently truncates at 72 bytes. */
const MAX_PASSWORD_BYTES = 72;

async function hashPassword(plain) {
  if (Buffer.byteLength(plain, 'utf8') > MAX_PASSWORD_BYTES) {
    throw new Error('Password is too long (bcrypt limit is 72 bytes)');
  }
  return bcrypt.hash(plain, BCRYPT_ROUNDS);
}

async function verifyPassword(plain, hash) {
  if (typeof hash !== 'string' || hash.length === 0) {
    await bcrypt.compare(plain, DUMMY_HASH);
    return false;
  }
  return bcrypt.compare(plain, hash);
}

/** Constant-work comparison for unknown users. */
async function burnTimingBudget(plain) {
  await bcrypt.compare(plain, DUMMY_HASH);
  return false;
}

module.exports = { hashPassword, verifyPassword, burnTimingBudget, BCRYPT_ROUNDS };
