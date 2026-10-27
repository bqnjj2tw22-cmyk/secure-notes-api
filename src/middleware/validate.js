'use strict';

/**
 * Validation helpers.
 *
 * Whitelist-style validation: unknown fields are rejected rather than ignored,
 * every string has an explicit maximum length, and no value is ever passed to
 * the database without first being type-checked here.
 */

class ValidationError extends Error {
  constructor(errors) {
    super('validation_failed');
    this.name = 'ValidationError';
    this.status = 400;
    this.errors = errors;
  }
}

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function assertAllowedKeys(body, allowed) {
  const extra = Object.keys(body).filter((key) => !allowed.includes(key));
  if (extra.length > 0) {
    throw new ValidationError([{ field: extra.join(','), message: 'unexpected field' }]);
  }
}

/**
 * Validate one string field.
 *
 * The value is passed in directly (`body.username`) instead of being looked up by
 * a computed key, so there is no dynamic property access on request data anywhere
 * in the validator - the same reason ESLint's `security/detect-object-injection`
 * exists.
 */
function requireString(raw, field, { min = 1, max = 255, pattern = null } = {}) {
  if (typeof raw !== 'string') {
    throw new ValidationError([{ field, message: 'must be a string' }]);
  }
  if (raw.length < min || raw.length > max) {
    throw new ValidationError([{ field, message: `length must be between ${min} and ${max}` }]);
  }
  if (pattern && !pattern.test(raw)) {
    throw new ValidationError([{ field, message: 'has an invalid format' }]);
  }
  return raw;
}

/** Validator middleware factory. */
function validate(schema) {
  return (req, res, next) => {
    try {
      if (!isPlainObject(req.body)) {
        throw new ValidationError([{ field: 'body', message: 'JSON object expected' }]);
      }
      req.validated = schema(req.body);
      return next();
    } catch (err) {
      return next(err);
    }
  };
}

const USERNAME_PATTERN = /^[A-Za-z0-9._-]+$/;

const loginSchema = (body) => {
  assertAllowedKeys(body, ['username', 'password']);
  return {
    username: requireString(body.username, 'username', { min: 3, max: 32, pattern: USERNAME_PATTERN }),
    password: requireString(body.password, 'password', { min: 8, max: 72 })
  };
};

const postSchema = (body) => {
  assertAllowedKeys(body, ['title', 'content']);
  return {
    title: requireString(body.title, 'title', { min: 1, max: 120 }),
    content: requireString(body.content, 'content', { min: 1, max: 5000 })
  };
};

module.exports = {
  ValidationError,
  validate,
  loginSchema,
  postSchema,
  USERNAME_PATTERN
};
