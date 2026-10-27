'use strict';

/**
 * Rate limiting.
 *
 * Two limiter instances with different budgets:
 *   - `loginLimiter` protects the credential endpoint (brute force, credential
 *     stuffing). It is deliberately tight.
 *   - `apiLimiter` is a baseline for every other API route so that a single
 *     client cannot exhaust the service (accidental loop or deliberate flood).
 *
 * Keeping them in one module makes the budgets reviewable in one place; the
 * per-account lockout in `routes/auth.js` is a second, independent brake.
 */
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'too_many_requests' }
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'too_many_requests' }
});

module.exports = { loginLimiter, apiLimiter };
