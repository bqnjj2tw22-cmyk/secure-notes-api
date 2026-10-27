'use strict';

const express = require('express');
const { queries } = require('../db');
const { requireAuth, requireRole } = require('../middleware/auth');
const { apiLimiter } = require('../middleware/limits');
const { validate, postSchema } = require('../middleware/validate');
const { normaliseText } = require('../security/sanitize');

const router = express.Router();

// Baseline flood protection for every route in this router. The login endpoint has
// its own, much tighter budget in middleware/limits.js.
router.use(apiLimiter);

/** GET /api/me - who am I (identity taken from the verified token only). */
router.get('/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

/**
 * GET /api/data - protected data listing.
 * Only authenticated callers reach this handler; anonymous requests are stopped
 * by requireAuth with 401.
 */
router.get('/data', requireAuth, (req, res) => {
  const posts = queries.listPosts();
  res.json({
    count: posts.length,
    items: posts.map((p) => ({
      id: p.id,
      title: p.title,
      content: p.content,
      author: p.author,
      created_at: p.created_at
    }))
  });
});

/** Third method: POST /api/posts - create a note (authenticated users only). */
router.post('/posts', requireAuth, validate(postSchema), (req, res) => {
  const title = normaliseText(req.validated.title);
  const content = normaliseText(req.validated.content);

  // Prepared statement with bound parameters -> SQL injection is not possible
  // even if the body contains quotes, semicolons or UNION SELECT.
  const info = queries.insertPost(req.user.id, title, content);

  res.status(201).json({
    id: Number(info.lastInsertRowid),
    title,
    content,
    author: req.user.username
  });
});

/** DELETE /api/posts/:id - ownership enforced in the SQL predicate itself. */
router.delete('/posts/:id', requireAuth, (req, res, next) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: 'invalid_id' });
  }

  try {
    const result = queries.deletePostOwnedBy(id, req.user.id);
    if (result.changes === 0) {
      // 404 rather than 403: do not confirm that somebody else's row exists.
      return res.status(404).json({ error: 'not_found' });
    }
    return res.status(204).end();
  } catch (err) {
    return next(err);
  }
});

/** Administrative endpoint - demonstrates role-based access control. */
router.get('/admin/users', requireAuth, requireRole('admin'), (req, res) => {
  res.json({ users: queries.listUsers() });
});

module.exports = router;
