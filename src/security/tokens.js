'use strict';

/**
 * JWT issuing and verification.
 *
 * The algorithm is pinned on both sides.  This is what stops the classic
 * "alg: none" and HS/RS confusion attacks: a token that claims another
 * algorithm is rejected before its signature is even considered.
 */
const jwt = require('jsonwebtoken');
const config = require('../config');

const { secret, algorithm, issuer, audience, expiresIn } = config.jwt;

function issueToken(user) {
  return jwt.sign(
    {
      sub: String(user.id),
      username: user.username,
      role: user.role
    },
    secret,
    {
      algorithm,
      expiresIn,
      issuer,
      audience,
      jwtid: require('node:crypto').randomUUID()
    }
  );
}

/**
 * @throws {jwt.JsonWebTokenError|jwt.TokenExpiredError}
 * @returns {{sub: string, username: string, role: string, iat: number, exp: number}}
 */
function verifyToken(token) {
  return jwt.verify(token, secret, {
    algorithms: [algorithm],
    issuer,
    audience
  });
}

module.exports = { issueToken, verifyToken };
