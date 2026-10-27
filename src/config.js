'use strict';

/**
 * Centralised configuration.
 *
 * Every security-relevant value is read from the environment (12-factor style)
 * so that no secret is ever committed to the repository.  The module fails fast
 * when a production deployment is misconfigured, instead of silently falling
 * back to a weak default.
 */
const crypto = require('node:crypto');
const path = require('node:path');

const env = process.env.NODE_ENV || 'development';
const isProduction = env === 'production';

function readSecret() {
  const secret = process.env.JWT_SECRET;

  if (isProduction) {
    if (!secret || secret.length < 32) {
      throw new Error(
        'JWT_SECRET must be set to at least 32 characters in production. ' +
          'Generate one with: node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'base64url\'))"'
      );
    }
    return secret;
  }

  // Development/test only: an ephemeral secret keeps the repository clean but
  // means tokens die with the process, which is exactly what we want locally.
  return secret || crypto.randomBytes(48).toString('base64url');
}

const config = {
  env,
  isProduction,
  port: Number.parseInt(process.env.PORT || '3000', 10),
  dbPath: process.env.DB_PATH || path.join(__dirname, '..', 'data', 'app.db'),
  jwt: {
    secret: readSecret(),
    algorithm: 'HS256',
    issuer: 'secure-notes-api',
    audience: 'secure-notes-client',
    expiresIn: process.env.JWT_EXPIRES_IN || '15m'
  },
  bcryptRounds: Number.parseInt(process.env.BCRYPT_ROUNDS || '12', 10),
  corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  trustProxy: process.env.TRUST_PROXY === 'true'
};

module.exports = config;
