'use strict';

const jwt = require('jsonwebtoken');
const { verifyToken } = require('../security/tokens');

/**
 * Authentication middleware.
 *
 * Contract: every protected route is mounted behind `requireAuth`, so there is
 * exactly one implementation of token checking to reason about (and to test).
 * It never trusts a client-supplied identity (no `X-User-Id` header, no
 * `userId` parameter) - the caller identity comes only from a verified token.
 */
function requireAuth(req, res, next) {
  const header = req.get('authorization') || '';
  const [scheme, token] = header.split(' ');

  if (!token || !/^Bearer$/i.test(scheme)) {
    return res.status(401).json({ error: 'authentication_required' });
  }

  try {
    const payload = verifyToken(token);
    req.user = {
      id: Number(payload.sub),
      username: payload.username,
      role: payload.role
    };
    return next();
  } catch (err) {
    const reason = err instanceof jwt.TokenExpiredError ? 'token_expired' : 'invalid_token';
    return res.status(401).json({ error: reason });
  }
}

/** Role gate, used by the administrative endpoint. */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'forbidden' });
    }
    return next();
  };
}

module.exports = { requireAuth, requireRole };
