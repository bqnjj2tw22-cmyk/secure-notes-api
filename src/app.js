'use strict';

const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const config = require('./config');
const { escapeDeep } = require('./security/sanitize');
const authRoutes = require('./routes/auth');
const dataRoutes = require('./routes/data');

/**
 * Build the Express application.
 *
 * Security controls are applied in layers, outermost first:
 *   1. security headers (helmet)
 *   2. CORS allow-list
 *   3. body size limit + strict JSON parsing
 *   4. output encoding of every JSON response (last line of XSS defence)
 *   5. authentication / validation / authorisation per route
 *   6. central error handler that never leaks stack traces or SQL text
 */
function createApp() {
  const app = express();

  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy ? 1 : false);

  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          defaultSrc: ["'none'"],
          frameAncestors: ["'none'"],
          baseUri: ["'none'"],
          formAction: ["'none'"]
        }
      },
      crossOriginResourcePolicy: { policy: 'same-site' },
      referrerPolicy: { policy: 'no-referrer' },
      hsts: config.isProduction ? { maxAge: 15552000, includeSubDomains: true } : false
    })
  );

  // CORS: explicit allow-list, credentials disabled (the API is token-based).
  app.use((req, res, next) => {
    const origin = req.get('origin');
    if (origin && origin === config.corsOrigin) {
      res.set('Access-Control-Allow-Origin', origin);
      res.set('Vary', 'Origin');
      res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type');
      res.set('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
      res.set('Access-Control-Max-Age', '600');
    }
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    return next();
  });

  app.use(express.json({ limit: '16kb', strict: true }));

  // Correlation id for logs; never derived from user input.
  app.use((req, res, next) => {
    req.id = crypto.randomUUID();
    res.set('X-Request-Id', req.id);
    res.set('Cache-Control', 'no-store');
    next();
  });

  // Encode every string that leaves the API. Defence in depth: even a client
  // that renders this JSON into HTML (e.g. an admin dashboard using innerHTML)
  // cannot execute an injected <script>.
  app.use((req, res, next) => {
    const originalJson = res.json.bind(res);
    res.json = (body) => originalJson(escapeDeep(body));
    next();
  });

  app.get('/health', (req, res) => res.json({ status: 'ok', uptime: Math.round(process.uptime()) }));

  app.get('/', (req, res) => {
    res.json({
      name: 'secure-notes-api',
      version: '1.0.0',
      endpoints: [
        { method: 'POST', path: '/auth/login', auth: false, description: 'Exchange username + password for a JWT' },
        { method: 'GET', path: '/api/data', auth: true, description: 'List notes (authenticated users only)' },
        { method: 'POST', path: '/api/posts', auth: true, description: 'Create a note' },
        { method: 'DELETE', path: '/api/posts/:id', auth: true, description: 'Delete own note' },
        { method: 'GET', path: '/api/me', auth: true, description: 'Current identity from the token' },
        { method: 'GET', path: '/api/admin/users', auth: true, role: 'admin', description: 'List users' }
      ]
    });
  });

  app.use('/auth', authRoutes);
  app.use('/api', dataRoutes);

  app.use((req, res) => res.status(404).json({ error: 'not_found' }));

  // Central error handler: internal details stay in the server log.
  // Four parameters are required for Express to treat this as an error handler.
  app.use((err, req, res, _next) => {
    if (err && err.name === 'ValidationError') {
      return res.status(400).json({ error: 'validation_failed', details: err.errors });
    }
    if (err && (err.type === 'entity.parse.failed' || err.type === 'entity.too.large')) {
      return res.status(400).json({ error: 'invalid_request_body' });
    }
    const status = Number.isInteger(err && err.status) ? err.status : 500;
    if (status >= 500) {
      // Log message only - never the request body, which may contain a password.
      console.error(JSON.stringify({ level: 'error', request_id: req.id, message: err && err.message }));
    }
    return res.status(status).json({ error: status >= 500 ? 'internal_error' : 'request_failed' });
  });

  return app;
}

module.exports = { createApp };
