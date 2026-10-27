'use strict';

require('dotenv').config();

const config = require('./config');
const { init } = require('./db');
const { createApp } = require('./app');

init(config.dbPath);
const app = createApp();

const server = app.listen(config.port, () => {
  console.log(`secure-notes-api listening on http://127.0.0.1:${config.port} (env=${config.env})`);
});

/** Graceful shutdown so Docker/CI do not leave half-open sockets. */
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    console.log(`${signal} received, closing server`);
    server.close(() => process.exit(0));
  });
}
