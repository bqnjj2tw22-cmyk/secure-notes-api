'use strict';

/**
 * API test-suite (node:test, no external test framework).
 *
 * The suite boots the real Express application on an ephemeral port against an
 * in-memory SQLite database, so it exercises the same middleware stack that runs
 * in production.  Every security claim in README.md has a test here.
 */
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-'.padEnd(48, 'k');
process.env.BCRYPT_ROUNDS = '4'; // fast hashing only for the test run

const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');

const config = require('../src/config');
const { init, queries } = require('../src/db');
const { createApp } = require('../src/app');
const { hashPassword } = require('../src/security/passwords');
const { seedIfEmpty, DEMO_USERS } = require('../src/seed-data');

let server;
let baseUrl;

test.before(async () => {
  init(':memory:');
  await seedIfEmpty({ hashPassword });
  const app = createApp();
  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', resolve);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

test.after(() => new Promise((resolve) => server.close(resolve)));

async function login(username, password) {
  const res = await fetch(`${baseUrl}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  return { status: res.status, body: await res.json() };
}

test('health endpoint reports ok', async () => {
  const res = await fetch(`${baseUrl}/health`);
  assert.equal(res.status, 200);
  assert.equal((await res.json()).status, 'ok');
});

test('protected endpoint rejects anonymous access with 401', async () => {
  const res = await fetch(`${baseUrl}/api/data`);
  assert.equal(res.status, 401);
  assert.deepEqual(await res.json(), { error: 'authentication_required' });
});

test('login with valid credentials returns a JWT and never the password', async () => {
  const { status, body } = await login('alice', 'Alice-Str0ng!Pass');
  assert.equal(status, 200);
  assert.equal(body.token_type, 'Bearer');
  assert.ok(body.token.split('.').length === 3);

  const decoded = jwt.decode(body.token);
  assert.equal(decoded.iss, config.jwt.issuer);
  assert.equal(decoded.aud, config.jwt.audience);
  assert.ok(decoded.exp > decoded.iat);

  assert.equal(JSON.stringify(body).includes('Alice-Str0ng!Pass'), false);
  assert.equal(JSON.stringify(body).includes('password_hash'), false);
});

test('login with a wrong password returns a generic 401', async () => {
  const { status, body } = await login('alice', 'Wrong-Password-123');
  assert.equal(status, 401);
  assert.deepEqual(body, { error: 'invalid_credentials' });
});

test('login with an unknown user is indistinguishable from a wrong password', async () => {
  const { status, body } = await login('no-such-user', 'Wrong-Password-123');
  assert.equal(status, 401);
  assert.deepEqual(body, { error: 'invalid_credentials' });
});

test('SQL injection in the login payload cannot bypass authentication', async () => {
  // 1) The strict username whitelist rejects the payload before it reaches SQL.
  const rejected = await login("' OR 1=1--", 'anything-at-all');
  assert.equal(rejected.status, 400);

  // 2) Even if such a string reached the data layer, the bound parameter makes
  //    it a literal value that matches no row.
  const rows = queries.findUserByUsername("' OR 1=1--");
  assert.equal(rows, undefined);

  // 3) A valid username with an injection-style password is still a plain 401.
  const inline = await login('alice', "' OR '1'='1' --");
  assert.equal(inline.status, 401);
});

test('authenticated request returns data', async () => {
  const { body } = await login('alice', 'Alice-Str0ng!Pass');
  const res = await fetch(`${baseUrl}/api/data`, {
    headers: { Authorization: `Bearer ${body.token}` }
  });
  assert.equal(res.status, 200);
  const json = await res.json();
  assert.ok(json.count >= 3);
  assert.ok(Array.isArray(json.items));
});

test('tampered token is rejected', async () => {
  const { body } = await login('alice', 'Alice-Str0ng!Pass');
  const parts = body.token.split('.');
  const forged = jwt.sign({ sub: '1', username: 'alice', role: 'admin' }, 'attacker-secret-attacker-secret-1234', {
    algorithm: 'HS256',
    issuer: config.jwt.issuer,
    audience: config.jwt.audience
  });
  const res = await fetch(`${baseUrl}/api/data`, { headers: { Authorization: `Bearer ${forged}` } });
  assert.equal(res.status, 401);

  const broken = [parts[0], parts[1], 'AAAA'].join('.');
  const res2 = await fetch(`${baseUrl}/api/data`, { headers: { Authorization: `Bearer ${broken}` } });
  assert.equal(res2.status, 401);
});

test('alg=none token is rejected (algorithm pinning)', async () => {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ sub: '1', username: 'alice', role: 'admin' })).toString('base64url');
  const res = await fetch(`${baseUrl}/api/data`, { headers: { Authorization: `Bearer ${header}.${payload}.` } });
  assert.equal(res.status, 401);
});

test('XSS payload is stored but escaped on output', async () => {
  const { body } = await login('alice', 'Alice-Str0ng!Pass');
  const payload = '<script>alert(document.cookie)</script>';

  const created = await fetch(`${baseUrl}/api/posts`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${body.token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ title: 'xss test', content: payload })
  });
  assert.equal(created.status, 201);
  const createdJson = await created.json();
  assert.equal(createdJson.content.includes('<script>'), false);
  assert.ok(createdJson.content.includes('&lt;script&gt;'));

  const list = await fetch(`${baseUrl}/api/data`, { headers: { Authorization: `Bearer ${body.token}` } });
  const text = await list.text();
  assert.equal(text.includes('<script>alert'), false);
  assert.ok(text.includes('&lt;script&gt;alert'));
});

test('unexpected fields are rejected by the validator', async () => {
  const { body } = await login('alice', 'Alice-Str0ng!Pass');
  const res = await fetch(`${baseUrl}/api/posts`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${body.token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ title: 't', content: 'c', role: 'admin' })
  });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error, 'validation_failed');
});

test('a user cannot delete another user\'s note (IDOR)', async () => {
  const alice = await login('alice', 'Alice-Str0ng!Pass');
  const bob = await login('bob', 'Bob-Str0ng!Pass42');

  const created = await fetch(`${baseUrl}/api/posts`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${alice.body.token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ title: 'alice only', content: 'secret' })
  });
  const { id } = await created.json();

  const forbidden = await fetch(`${baseUrl}/api/posts/${id}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${bob.body.token}` }
  });
  assert.equal(forbidden.status, 404);

  const allowed = await fetch(`${baseUrl}/api/posts/${id}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${alice.body.token}` }
  });
  assert.equal(allowed.status, 204);
});

test('non-admin cannot reach the admin endpoint', async () => {
  const alice = await login('alice', 'Alice-Str0ng!Pass');
  const res = await fetch(`${baseUrl}/api/admin/users`, {
    headers: { Authorization: `Bearer ${alice.body.token}` }
  });
  assert.equal(res.status, 403);

  const admin = await login('admin', 'Admin-Str0ng!Pass');
  const ok = await fetch(`${baseUrl}/api/admin/users`, {
    headers: { Authorization: `Bearer ${admin.body.token}` }
  });
  assert.equal(ok.status, 200);
});

test('security headers are present', async () => {
  const res = await fetch(`${baseUrl}/api/data`);
  assert.equal(res.headers.get('x-powered-by'), null);
  assert.ok(res.headers.get('content-security-policy').includes("default-src 'none'"));
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('cache-control'), 'no-store');
});

test('unknown routes return a JSON 404', async () => {
  const res = await fetch(`${baseUrl}/nope`);
  assert.equal(res.status, 404);
  assert.deepEqual(await res.json(), { error: 'not_found' });
});

test('malformed JSON is rejected without a stack trace', async () => {
  const res = await fetch(`${baseUrl}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{"username": "alice", '
  });
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.deepEqual(body, { error: 'invalid_request_body' });
});

test('demo passwords are stored as bcrypt hashes, not plaintext', async () => {
  const { getDb } = require('../src/db');
  const row = getDb().prepare('SELECT password_hash FROM users WHERE username = ?').get('alice');
  assert.match(row.password_hash, /^\$2[aby]\$\d{2}\$/);
  assert.equal(row.password_hash.includes(DEMO_USERS[0].password), false);
});
