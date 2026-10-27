# Secure Notes API — Laboratory Work 1

**Secure REST API with CI/CD security scanning and real-CVE analysis (CVE-2018-7490)**

[![CI](https://github.com/bqnjj2tw22-cmyk/secure-notes-api/actions/workflows/ci.yml/badge.svg)](https://github.com/bqnjj2tw22-cmyk/secure-notes-api/actions/workflows/ci.yml)

**Repository:** <https://github.com/bqnjj2tw22-cmyk/secure-notes-api>

| Item | Value |
| --- | --- |
| Course | Information Security, Hangzhou Dianzi University |
| Student | Li Xiao (IDU 23320323, group 23320113) |
| Variant | **CVE-2018-7490** — uWSGI PHP plugin directory traversal |
| Stack | Node.js 22 · Express 4 · SQLite (`node:sqlite`) · JWT · bcrypt |
| Tests | 17 automated tests, all passing |

---

## 1. What the project is

A small but complete REST API for a note-sharing service. Two kinds of users exist
(`user`, `admin`). Authenticated users can read all notes, create their own notes and
delete their own notes; only administrators can list accounts.

The application is deliberately *boring*: no ORM magic, no dynamic SQL, no custom
crypto. Every security control is visible in a few lines of code, which makes it
possible to point at the exact line that stops an attack and to write a test that
proves it.

### 1.1 Endpoints

| # | Method | Path | Auth | Purpose | Success | Main failures |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `POST` | `/auth/login` | no | Exchange `username` + `password` for a JWT | `200` + token | `400` validation, `401` invalid credentials, `429` locked |
| 2 | `GET` | `/api/data` | JWT | List all notes | `200` | `401` missing/invalid token |
| 3 | `POST` | `/api/posts` | JWT | Create a note | `201` | `400` validation, `401` |
| 4 | `DELETE` | `/api/posts/:id` | JWT | Delete **own** note | `204` | `401`, `404` (not found / not owner) |
| 5 | `GET` | `/api/me` | JWT | Identity from the token | `200` | `401` |
| 6 | `GET` | `/api/admin/users` | JWT + `admin` | List accounts | `200` | `401`, `403` |
| 7 | `GET` | `/health` | no | Liveness probe | `200` | — |

`GET /` returns a machine-readable description of the same table.

### 1.2 Calling the API

```bash
# 1. obtain a token
curl -s -X POST http://127.0.0.1:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"Alice-Str0ng!Pass"}'

# 2. call a protected endpoint
TOKEN=...   # token from step 1
curl -s http://127.0.0.1:3000/api/data -H "Authorization: Bearer $TOKEN"

# 3. create a note
curl -s -X POST http://127.0.0.1:3000/api/posts \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"title":"hello","content":"first note"}'

# 4. delete own note
curl -s -X DELETE http://127.0.0.1:3000/api/posts/4 -H "Authorization: Bearer $TOKEN"
```

### 1.3 Project layout

```
.
├── .github/workflows/ci.yml   # tests + SAST + SCA + CodeQL
├── Dockerfile                 # multi-stage, non-root runtime
├── eslint.config.js           # flat config incl. eslint-plugin-security
├── scripts/capture-evidence.ps1
├── src
│   ├── app.js                 # middleware pipeline, error handler
│   ├── config.js              # env config, fail-fast secret checks
│   ├── db.js                  # schema + parameterised statements
│   ├── seed.js / seed-data.js # demo data (bcrypt-hashed at seed time)
│   ├── middleware/auth.js     # JWT verification, RBAC
│   ├── middleware/validate.js # whitelist input validation
│   ├── routes/auth.js         # POST /auth/login
│   ├── routes/data.js         # /api/* endpoints
│   ├── security/passwords.js  # bcrypt hashing, timing equalisation
│   ├── security/sanitize.js   # HTML escaping / input normalisation
│   ├── security/tokens.js     # JWT sign/verify with pinned algorithm
│   └── server.js              # bootstrap + graceful shutdown
├── test/api.test.js           # 17 tests (node:test)
└── docs
    ├── evidence/              # raw request/response logs used in the report
    ├── screenshots/           # CI + CVE screenshots (see checklist)
    └── cve-2018-7490/         # vulnerable + fixed compose files
```

### 1.4 Running it

```bash
node --version          # must be >= 22.5 (built-in node:sqlite)
npm ci
cp .env.example .env    # then set JWT_SECRET
npm run seed
npm start               # http://127.0.0.1:3000
npm test                # 17/17 passing
npm run lint            # 0 problems
npm audit --audit-level=high
```

---

## 2. Implemented security measures

The design follows OWASP ASVS level 1 and the OWASP Top 10 (2021) items that matter
for this API: **A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection,
A07 Identification and Authentication Failures, A09 Security Logging/Monitoring**.

### 2.1 SQL injection (A03)

*Every* statement that contains user data is a prepared statement with bound
parameters (`src/db.js`). There is no string concatenation anywhere in the data
layer, and there is no code path that builds SQL from request values.

```js
// src/db.js
findUserByUsername: (username) =>
  getDb().prepare('SELECT id, username, password_hash, role FROM users WHERE username = ?')
         .get(username),

deletePostOwnedBy: (id, ownerId) =>
  getDb().prepare('DELETE FROM posts WHERE id = ? AND owner_id = ?').run(id, ownerId),
```

Three independent layers stop the classic `' OR 1=1 --` login bypass:

1. **Whitelist validation** — the username must match `^[A-Za-z0-9._-]+$`
   (`src/middleware/validate.js`), so quotes and comment markers never reach the DB
   layer. The request is rejected with `400`.
2. **Bound parameters** — even if such a string were accepted, SQLite treats it as a
   literal value that matches no row (`WHERE username = ?`), never as SQL syntax.
3. **Least privilege** — the API's database user owns only its two tables; even a
   hypothetical injection could not read `sqlite_master`-level secrets or drop schemas.

Evidence (`docs/evidence/06-sqli-login.txt`):

```
POST /auth/login  {"username":"' OR 1=1--","password":"whatever123"}
HTTP/1.1 400 Bad Request
{"error":"validation_failed","details":[{"field":"username","message":"has an invalid format"}]}
```

### 2.2 XSS (A03)

XSS is handled as an *output encoding* problem, not by "sanitising" input into
something meaningless:

| Context | Control | Where |
| --- | --- | --- |
| JSON responses | every string is HTML-escaped before serialisation (`escapeDeep`) | `src/app.js` response middleware |
| HTML context (future front-end) | context-aware `escapeHtml()` for `& < > " ' \` = /` | `src/security/sanitize.js` |
| Browser enforcement | strict CSP `default-src 'none'`, `frame-ancestors 'none'`, `nosniff`, `no-referrer` | `helmet` config in `src/app.js` |
| Input hygiene | control characters and NUL stripped, length capped per field | `normaliseText`, validators |

Evidence (`docs/evidence/07-xss-escaping.txt`) — the payload is stored as data, but it
can never leave the API as executable markup:

```
POST /api/posts {"title":"xss-demo","content":"<script>alert(document.cookie)</script>"}
HTTP/1.1 201 Created
{"id":4,"title":"xss-demo",
 "content":"&lt;script&gt;alert(document.cookie)&lt;&#x2F;script&gt;","author":"alice"}
```

The trade-off is documented in the code: escaping JSON means a client that *wants*
the raw string must unescape it, while a careless client that injects the value into
`innerHTML` is still safe. For a pure JSON API the real control is
`Content-Type: application/json` + CSP, which are both present.

### 2.3 Authentication (A07)

1. **Password storage** — bcrypt, cost factor 12, per-password salt
   (`src/security/passwords.js`). Passwords are never logged, never returned, and
   never stored in plaintext; the seed script hashes demo passwords at start-up.
   bcrypt is preferred over SHA-256 because it is memory/CPU-hard and salted: one
   GPU-backed attacker cannot amortise work across users or use rainbow tables.
2. **JWT issuing** — HS256, `iss`/`aud`/`sub`/`jti`, 15-minute lifetime
   (`src/security/tokens.js`). The secret must be at least 32 random bytes in
   production (fail-fast in `src/config.js`).
3. **JWT verification** — `requireAuth` middleware verifies signature, algorithm
   (pinned to HS256, so `alg: none` and RS→HS confusion are rejected), issuer,
   audience and expiry; identity is taken only from the verified claims.
4. **Brute-force and flood resistance** — three independent brakes, all defined in
   `src/middleware/limits.js`: a tight IP rate limiter on the login route
   (20 requests / 15 min), a baseline limiter on every other `/api` route
   (300 requests / 15 min), and a per-account lock after 5 consecutive failures
   within 15 minutes, recorded in `login_attempts`.
5. **Enumeration resistance** — identical body (`invalid_credentials`) and
   near-identical timing for "unknown user" and "wrong password": an unknown user is
   compared against a fixed dummy bcrypt hash (`burnTimingBudget`) so the response
   time does not reveal account existence.

Issued token (payload, `docs/evidence/11-jwt-claims.json`):

```json
{"sub":"1","username":"alice","role":"user","iat":1792986948,"exp":1792987848,
 "aud":"secure-notes-client","iss":"secure-notes-api","jti":"fe8f9464-b3cd-4f26-8815-7a29a6378a0e"}
```

### 2.4 Broken access control (A01)

* Protected routes are mounted behind a single `requireAuth` implementation; there is
  no endpoint that "forgets" the check.
* Object-level authorisation is part of the SQL predicate
  (`DELETE ... WHERE id = ? AND owner_id = ?`), so guessing a numeric id is useless.
  A failed delete returns `404`, not `403`, to avoid confirming that somebody else's
  object exists.
* Role checks (`requireRole('admin')`) are separate from authentication.

Evidence (`docs/evidence/08-idor-delete.txt`):

```
DELETE /api/posts/1   (bob's valid token, note 1 belongs to alice)
HTTP/1.1 404 Not Found
{"error":"not_found"}
```

### 2.5 Transport and platform hardening

| Control | Implementation |
| --- | --- |
| Security headers | `helmet` (CSP, COOP, CORP, `nosniff`, `X-Frame-Options`, referrer policy) |
| HSTS | enabled only with `NODE_ENV=production` |
| CORS | single allow-listed origin from `CORS_ORIGIN`, no wildcard, no credentials |
| Body limits | `express.json({ limit: '16kb', strict: true })` → 413/400 on abuse |
| Cache | `Cache-Control: no-store` on every API response |
| Error handling | central handler; clients receive `{"error":"internal_error"}`, details stay in server logs |
| Secrets | `.env` git-ignored, `.env.example` committed, production start fails without a strong `JWT_SECRET` |
| Runtime | multi-stage Dockerfile, `USER app` (non-root), `NODE_ENV=production`, healthcheck |
| Dependencies | `npm ci` from lockfile in CI; `npm audit --audit-level=high` fails the build |

---

## 3. CI/CD pipeline with security scanners

`.github/workflows/ci.yml` runs on every push and pull request:

| Job | Tool | What it proves | Failure behaviour |
| --- | --- | --- | --- |
| `test` | `node --test` (17 tests) | functionality + every security regression test | fails build |
| `sast` | ESLint + `eslint-plugin-security` → SARIF | no `eval`, no dynamic `require`, no unsafe fs/regex, no object-injection sinks | fails build |
| `sast` | Semgrep (`p/owasp-top-ten`, `p/nodejs`) → SARIF | injection, crypto, JWT and access-control anti-patterns | fails build |
| `sca` | `npm audit --audit-level=high` | no high/critical vulnerable dependency | fails build |
| `sca` | `actions/dependency-review-action` | a PR cannot introduce a vulnerable package | fails PR |
| `codeql` | CodeQL `security-extended` | data-flow analysis of the whole repository | uploads alerts |

SARIF reports are uploaded to **Security → Code scanning**, and both raw reports are
attached to the run as artefacts (`sast-reports`, `sca-reports`).

One path is deliberately excluded from Semgrep: `docs/cve-2018-7490/` contains the
*vulnerable* uWSGI environment used for the CVE study (including a `phpinfo()` page
that proves the PHP plugin works). Scanning it as production code would report the
vulnerability under study as a defect of this repository. The exclusion and its
reason are recorded in `.semgrepignore`; the application under test (`src/`, `test/`,
CI configuration) is scanned in full.

### 3.1 Local results (same commands, same config)

```
$ npm test
# tests 17
# pass 17
# fail 0

$ npx eslint .
(no output — 0 errors, 0 warnings)

$ npm audit --audit-level=high
found 0 vulnerabilities
```

`docs/evidence/12-npm-audit.json` records 179 dependencies (92 production) and
**0** vulnerabilities of any severity; `docs/evidence/13-eslint-sast.json` records
`errorCount: 0`, `warningCount: 0` for every file.

In the published repository the same three jobs finish green and
**Security → Code scanning reports 0 open alerts**: the SARIF upload is empty
because the ESLint security ruleset no longer produces findings (the last one,
`security/detect-non-literal-fs-filename`, disappeared when the data-access layer
stopped calling `fs` with a configured path), and the Semgrep run scans only the
application, not the intentionally vulnerable CVE lab material.

### 3.2 Screenshots to attach

GitHub Actions must be shown, not described. Capture (see
`docs/screenshots/README.md` for the exact list):

1. the green CI run with all four jobs (`Tests`, `SAST`, `SCA`, `CodeQL`);
2. the Semgrep job log (`0 findings`) and the `npm audit` step
   (`found 0 vulnerabilities`);
3. the **Security → Code scanning** page with no open alerts.

---

## 4. CVE-2018-7490 — analysis and remediation

### 4.1 The vulnerability

| Field | Value |
| --- | --- |
| CVE | **CVE-2018-7490** |
| Product | uWSGI — PHP plugin (`--php-docroot`) |
| Type | Path traversal / improper limitation of a pathname to a restricted directory (**CWE-22**) |
| Affected | all versions **before 2.0.17** |
| Fixed in | **2.0.17** (2018) |
| CVSS 3.0 | **7.5 High** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| Impact | unauthenticated remote file read outside the document root; disclosure of source code, configuration and credentials; in deployments where PHP files exist outside the root, execution of unintended scripts |

NVD description: *"uWSGI before 2.0.17 mishandles a DOCUMENT_ROOT check during use of
the `--php-docroot` option, allowing directory traversal."*

The vulnerable configuration is exactly the one provided by Vulhub:

```yaml
# docker-compose.yml  (vulhub/uwsgi/CVE-2018-7490)
services:
  web:
    image: vulhub/uwsgi-php:2.0.16
    ports:
      - "8080:8080"
```

### 4.2 Reproduction

> Environment: Docker + Docker Compose, Vulhub image `vulhub/uwsgi-php:2.0.16`.
> Full command log with timestamps: `docs/cve-2018-7490/reproduction-log.md`.

```bash
git clone https://github.com/vulhub/vulhub.git
cd vulhub/uwsgi/CVE-2018-7490
docker compose up -d

# baseline: normal page inside the document root
curl -s http://127.0.0.1:8080/ | head -5          # phpinfo() page

# exploit: five levels up, then /etc/passwd
curl -s --path-as-is "http://127.0.0.1:8080/..%2f..%2f..%2f..%2f..%2fetc/passwd"
```

Expected (vulnerable) output — the container's `/etc/passwd`:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```

`--path-as-is` is essential: without it curl collapses `..%2f` before sending, and the
attack disappears. The same request works in a browser because the browser sends the
path untouched; `%2f` is only decoded by uWSGI.

Why this is a real attack and not a curiosity:

* `/etc/passwd` is only the proof. The same primitive reads `uwsgi.ini`,
  `docker-entrypoint.sh`, application source (`/var/www/../app/config.php`) and any
  file readable by the uWSGI worker user.
* Readable PHP sources leak database credentials and JWT/HMAC secrets, which turns a
  file-read bug into full application compromise.
* If an attacker can *write* a file anywhere (upload, log, session file), the same
  traversal can include and execute it, i.e. remote code execution.

### 4.3 Root cause

The PHP plugin builds the script path from the document root and the request path,
and it validates the request path **before** URL-decoding it:

1. `PATH_INFO` arrives as `/..%2f..%2f..%2f..%2f..%2fetc/passwd`. A prefix check
   against `DOCUMENT_ROOT` sees no `..` separator, because the separator is still
   percent-encoded, and accepts the path.
2. The plugin then decodes `%2f` to `/` to build `SCRIPT_FILENAME`.
3. The decoded string contains `../` segments, so the resulting filesystem path
   (`/var/www/../../../../../etc/passwd`) escapes the document root.
4. The file is opened and returned. There is no `realpath()` canonicalisation and no
   post-decode "is the resolved path still inside the root?" check — the check and
   the use operate on two different representations of the same string.

This is a *canonicalisation* bug: security decisions were made on the encoded form,
while the resource was resolved from the decoded form. It is the same class of mistake
as `%00` truncation and Unicode normalisation bugs. uWSGI 2.0.17 changed the plugin to
canonicalise the path and to verify that the resolved file is inside `DOCUMENT_ROOT`
after decoding.

### 4.4 Fix

Primary fix — **upgrade uWSGI to 2.0.17 or later**. Because Vulhub ships only the
vulnerable 2.0.16 image, the fixed environment builds uWSGI 2.0.17 from the official
release and runs the same PHP plugin configuration
(`docs/cve-2018-7490/Dockerfile.fixed`, `docker-compose.fixed.yml`):

```bash
cd docs/cve-2018-7490
docker compose -f docker-compose.fixed.yml up --build -d
curl -s --path-as-is "http://127.0.0.1:8081/..%2f..%2f..%2f..%2f..%2fetc/passwd" -i
```

Defence in depth (applied in the same compose file):

1. **Reject traversal at the edge** — a request filter refuses any URI containing
   `..` or `%2e%2e` before it reaches uWSGI, so a future regression in the plugin is
   still not exploitable.
2. **Least privilege** — the worker runs as an unprivileged user whose home is empty,
   and the document root contains only the application, so a successful traversal
   would expose far less.
3. **Disable unused plugins** — the PHP plugin is only enabled where PHP is actually
   served; a Python-only deployment is not affected at all.

### 4.5 Verification of the fix

| Check | Vulnerable (2.0.16) | Fixed (2.0.17 + filter) |
| --- | --- | --- |
| `GET /..%2f..%2f..%2f..%2f..%2fetc/passwd` | `200`, file contents | `400 Bad Request`, no body |
| `GET /` (phpinfo) | `200` | `200` — functionality preserved |
| `GET /index.php` | `200` | `200` — regression check |

```
$ curl -s --path-as-is -i "http://127.0.0.1:8081/..%2f..%2f..%2f..%2f..%2fetc/passwd"
HTTP/1.1 400 Bad Request
Content-Type: text/plain
traversal attempt blocked
```

Regression testing after the patch: the phpinfo page and `index.php` still return
`200`, the container stays healthy, and a normal file inside the document root is
still served — the fix removes the traversal without breaking legitimate requests.

---

## 5. Limitations and further work

* Tokens are stateless: logout is client-side only. A production system would keep a
  `jti` deny-list in Redis and support refresh-token rotation.
* The per-account lock is stored in SQLite; with several API replicas it must move to
  a shared store.
* `node:sqlite` is still marked experimental in Node 22; a production deployment would
  use PostgreSQL (the query layer is already isolated in `src/db.js`).
* The HTML escaping of JSON is a belt-and-braces control; a real front-end should rely
  on framework auto-escaping plus the CSP.

## 6. References

1. OWASP Top 10 2021 — <https://owasp.org/www-project-top-ten/>
2. OWASP ASVS 4.0 — <https://owasp.org/www-project-application-security-verification-standard/>
3. OWASP SQL Injection Prevention Cheat Sheet — <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html>
4. OWASP XSS Prevention Cheat Sheet — <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
5. NVD — CVE-2018-7490 — <https://nvd.nist.gov/vuln/detail/CVE-2018-7490>
6. uWSGI 2.0.17 changelog — <https://uwsgi-docs.readthedocs.io/en/latest/Changelog-2.0.17.html>
7. Vulhub — uWSGI CVE-2018-7490 — <https://github.com/vulhub/vulhub/tree/master/uwsgi/CVE-2018-7490>
8. Exploit-DB 44223 — <https://www.exploit-db.com/exploits/44223>
9. GitHub Actions security hardening — <https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions>
