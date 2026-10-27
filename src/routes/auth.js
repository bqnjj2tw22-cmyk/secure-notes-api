'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const config = require('../config');
const { queries } = require('../db');
const { validate, loginSchema } = require('../middleware/validate');
const { verifyPassword, burnTimingBudget } = require('../security/passwords');
const { issueToken } = require('../security/tokens');
const { normaliseText } = require('../security/sanitize');

const router = express.Router();

/** Brute-force brake #1: per-IP rate limit on the login endpoint. */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'too_many_requests' }
});

/** Brute-force brake #2: per-account lock after N consecutive failures. */
const MAX_FAILURES = 5;
const LOCK_WINDOW_MINUTES = 15;

router.post('/login', loginLimiter, validate(loginSchema), async (req, res, next) => {
  const username = normaliseText(req.validated.username);
  const password = req.validated.password;
  const ip = req.ip;

  try {
    const failures = queries.recentFailures(username, ip, LOCK_WINDOW_MINUTES).n;
    if (failures >= MAX_FAILURES) {
      return res.status(429).json({ error: 'account_temporarily_locked', retry_after_minutes: LOCK_WINDOW_MINUTES });
    }

    const user = queries.findUserByUsername(username);

    // Same amount of work whether or not the account exists: no user enumeration
    // through response body OR through response time.
    const ok = user ? await verifyPassword(password, user.password_hash) : await burnTimingBudget(password);

    queries.logLoginAttempt(username, ip, ok);

    if (!ok) {
      // Deliberately generic: never reveal whether the username or the password
      // was the wrong part.
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    const token = issueToken(user);

    return res.status(200).json({
      token,
      token_type: 'Bearer',
      expires_in: config.jwt.expiresIn,
      user: { id: user.id, username: user.username, role: user.role }
    });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
