/**
 * Lab 1 live demo client.
 *
 * Usage:
 *   terminal A:  npm start          (or: node src/server.js)
 *   terminal B:  node scripts/demo.js
 *
 * It prints six demonstrations with the HTTP status each one must produce.
 */
const BASE = process.env.DEMO_BASE || "http://127.0.0.1:3000";

const line = (c = "-") => console.log(c.repeat(72));
const step = (n, title) => {
  console.log("");
  line("=");
  console.log(`DEMO ${n}: ${title}`);
  line("=");
};

async function call(method, path, { body, token } = {}) {
  const headers = {};
  if (body) headers["content-type"] = "application/json";
  if (token) headers.authorization = "Bearer " + token;
  const res = await fetch(BASE + path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(10000),
  });
  const text = await res.text();
  return { status: res.status, text };
}

function show(res, max = 320) {
  const body = res.text.length > max ? res.text.slice(0, max) + " ...[cut]" : res.text;
  console.log(`HTTP ${res.status}`);
  console.log(body);
}

(async () => {
  // 0. is the server up?
  try {
    const h = await call("GET", "/health");
    console.log("server:", h.text);
  } catch {
    console.error("Cannot reach " + BASE + " - start the API first: npm start");
    process.exit(1);
  }

  // 1. anonymous access
  step(1, "GET /api/data without a token  ->  must be 401");
  show(await call("GET", "/api/data"));

  // 2. valid login
  step(2, "POST /auth/login with the correct password  ->  200 + JWT");
  const login = await call("POST", "/auth/login", {
    body: { username: "alice", password: "Alice-Str0ng!Pass" },
  });
  show(login, 260);
  let token = null;
  try {
    token = JSON.parse(login.text).token;
  } catch {
    console.error("\nlogin failed - run `npm run seed` first");
    process.exit(1);
  }
  console.log("\ntoken acquired:", token.slice(0, 32) + "...");

  // 3. authenticated data
  step(3, "GET /api/data with the token  ->  200 + data");
  show(await call("GET", "/api/data", { token }), 400);

  // 4. SQL injection attempt
  step(4, "SQL injection in the login body:  ' OR 1=1--   ->  400, never 200");
  show(
    await call("POST", "/auth/login", { body: { username: "' OR 1=1--", password: "whatever123" } })
  );

  // 5. XSS payload
  step(5, "XSS payload is stored, but leaves the API escaped  ->  201");
  show(
    await call("POST", "/api/posts", {
      token,
      body: { title: "xss-demo", content: "<script>alert(document.cookie)</script>" },
    })
  );
  console.log("\nNote: <script> became &lt;script&gt; - the data is intact, the markup is neutralised.");

  // 6. IDOR
  step(6, "bob's valid token tries to delete alice's note (id 1)  ->  404");
  const bob = await call("POST", "/auth/login", { body: { username: "bob", password: "Bob-Str0ng!Pass42" } });
  const bobToken = JSON.parse(bob.text).token;
  show(await call("DELETE", "/api/posts/1", { token: bobToken }), 200);

  line("=");
  console.log("Demo finished. Expected: 401, 200, 200, 400, 201, 404.");
  line("=");
})();
