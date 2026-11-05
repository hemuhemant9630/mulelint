// MuleLint accounts: one Vercel function serving
//   POST /api/auth/signup   {name, email, password, organization, role}
//   POST /api/auth/login    {email, password}
//   POST /api/auth/logout
//   GET  /api/auth/me
// Users and sessions live in Postgres (DATABASE_URL, e.g. Neon). Passwords are hashed with scrypt.
// The session is a random token in an HttpOnly cookie; only its SHA-256 is stored.

const crypto = require("node:crypto");
const { Pool } = require("pg");

const COOKIE = "ml_session";
const SESSION_DAYS = 30;
const MAX_FAILED_LOGINS = 10; // per email per 15 minutes
const ROLES = [
  "MuleSoft Developer",
  "Integration Architect",
  "Technical Lead",
  "QA / Test Engineer",
  "Project Manager",
  "Consultant",
  "Student",
  "Other",
];

let pool;
let schemaReady;

function db() {
  const url = process.env.DATABASE_URL || process.env.POSTGRES_URL;
  if (!url) throw httpError(503, "Accounts are not set up yet: the site has no database configured.");
  if (!pool) {
    const local = /localhost|127\.0\.0\.1/.test(url);
    pool = new Pool({ connectionString: url, max: 3, ssl: local ? false : { rejectUnauthorized: false } });
  }
  return pool;
}

function ensureSchema() {
  if (!schemaReady) {
    schemaReady = db()
      .query(`
        CREATE TABLE IF NOT EXISTS ml_users (
          id            UUID PRIMARY KEY,
          name          VARCHAR(100)  NOT NULL,
          email         VARCHAR(254)  NOT NULL UNIQUE,
          password_hash VARCHAR(200)  NOT NULL,
          organization  VARCHAR(120)  NOT NULL,
          role          VARCHAR(60)   NOT NULL,
          created_at    TIMESTAMPTZ   NOT NULL DEFAULT now(),
          last_login_at TIMESTAMPTZ
        );
        CREATE TABLE IF NOT EXISTS ml_sessions (
          token_hash CHAR(64)    PRIMARY KEY,
          user_id    UUID        NOT NULL REFERENCES ml_users(id) ON DELETE CASCADE,
          expires_at TIMESTAMPTZ NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS ml_sessions_user ON ml_sessions(user_id);
        CREATE TABLE IF NOT EXISTS ml_login_failures (
          email   VARCHAR(254) NOT NULL,
          at      TIMESTAMPTZ  NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS ml_login_failures_email ON ml_login_failures(email, at);
      `)
      .catch((e) => {
        schemaReady = null;
        throw e;
      });
  }
  return schemaReady;
}

// ------------------------------------------------------------------ helpers

function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

function send(res, status, body, headers = {}) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
  res.end(JSON.stringify(body));
}

async function readJson(req) {
  if (req.body && typeof req.body === "object") return req.body;
  if (typeof req.body === "string") return safeParse(req.body);
  let raw = "";
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 20000) throw httpError(413, "Request is too large.");
  }
  return safeParse(raw);
}

function safeParse(s) {
  if (!s) return {};
  try {
    return JSON.parse(s);
  } catch {
    throw httpError(400, "Malformed request.");
  }
}

const str = (v) => (typeof v === "string" ? v.trim() : "");
const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$16384$8$1$${salt.toString("base64")}$${hash.toString("base64")}`;
}

function verifyPassword(password, stored) {
  const [alg, N, r, p, salt, hash] = String(stored).split("$");
  if (alg !== "scrypt") return false;
  const expected = Buffer.from(hash, "base64");
  const got = crypto.scryptSync(password, Buffer.from(salt, "base64"), expected.length, { N: +N, r: +r, p: +p });
  return crypto.timingSafeEqual(got, expected);
}
// Burns the same time as a real check so unknown emails can't be detected by timing.
const DUMMY_HASH = hashPassword(crypto.randomBytes(12).toString("hex"));

function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function isHttps(req) {
  return req.headers["x-forwarded-proto"] === "https" || !/^(localhost|127\.0\.0\.1)(:\d+)?$/.test(req.headers.host || "");
}

function sessionCookie(req, token, maxAgeSeconds) {
  return [
    `${COOKIE}=${token}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${maxAgeSeconds}`,
    isHttps(req) ? "Secure" : null,
  ].filter(Boolean).join("; ");
}

const publicUser = (u) => ({
  id: u.id,
  name: u.name,
  email: u.email,
  organization: u.organization,
  role: u.role,
  createdAt: u.created_at,
});

async function startSession(req, userId) {
  const token = crypto.randomBytes(32).toString("base64url");
  const expires = new Date(Date.now() + SESSION_DAYS * 86400e3);
  await db().query("INSERT INTO ml_sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)", [sha256(token), userId, expires]);
  // Opportunistic cleanup keeps the table small without a cron job.
  if (Math.random() < 0.05) {
    await db().query("DELETE FROM ml_sessions WHERE expires_at < now()");
    await db().query("DELETE FROM ml_login_failures WHERE at < now() - interval '1 day'");
  }
  return sessionCookie(req, token, SESSION_DAYS * 86400);
}

async function currentUser(req) {
  const token = parseCookies(req)[COOKIE];
  if (!token || token.length > 100) return null;
  const r = await db().query(
    `SELECT u.* FROM ml_sessions s JOIN ml_users u ON u.id = s.user_id
     WHERE s.token_hash = $1 AND s.expires_at > now()`,
    [sha256(token)],
  );
  return r.rows[0] || null;
}

function sameOrigin(req) {
  // Blocks cross-site form posts; browsers send Origin on POST.
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    return new URL(origin).host === req.headers.host;
  } catch {
    return false;
  }
}

// ------------------------------------------------------------------ actions

async function signup(req, res) {
  const b = await readJson(req);
  const name = str(b.name), email = str(b.email).toLowerCase(), password = typeof b.password === "string" ? b.password : "";
  const organization = str(b.organization), role = str(b.role);
  if (!name || name.length > 100) throw httpError(400, "Enter your name (up to 100 characters).");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) throw httpError(400, "Enter a valid email address.");
  if (password.length < 8 || password.length > 128) throw httpError(400, "Use a password of 8 to 128 characters.");
  if (!organization || organization.length > 120) throw httpError(400, "Enter your organization name (up to 120 characters).");
  if (!ROLES.includes(role)) throw httpError(400, "Choose your role from the list.");

  const id = crypto.randomUUID();
  try {
    const r = await db().query(
      `INSERT INTO ml_users (id, name, email, password_hash, organization, role, last_login_at)
       VALUES ($1, $2, $3, $4, $5, $6, now()) RETURNING *`,
      [id, name, email, hashPassword(password), organization, role],
    );
    const cookie = await startSession(req, id);
    send(res, 201, { user: publicUser(r.rows[0]) }, { "Set-Cookie": cookie });
  } catch (e) {
    if (e.code === "23505") throw httpError(409, "An account with this email already exists. Sign in instead.");
    throw e;
  }
}

async function login(req, res) {
  const b = await readJson(req);
  const email = str(b.email).toLowerCase(), password = typeof b.password === "string" ? b.password : "";
  if (!email || !password) throw httpError(400, "Enter your email and password.");
  const recent = await db().query(
    "SELECT count(*)::int AS n FROM ml_login_failures WHERE email = $1 AND at > now() - interval '15 minutes'",
    [email],
  );
  if (recent.rows[0].n >= MAX_FAILED_LOGINS) throw httpError(429, "Too many failed attempts. Wait 15 minutes and try again.");

  const r = await db().query("SELECT * FROM ml_users WHERE email = $1", [email]);
  const user = r.rows[0];
  const ok = user ? verifyPassword(password, user.password_hash) : (verifyPassword(password, DUMMY_HASH), false);
  if (!ok) {
    await db().query("INSERT INTO ml_login_failures (email) VALUES ($1)", [email]);
    throw httpError(401, "Wrong email or password.");
  }
  await db().query("DELETE FROM ml_login_failures WHERE email = $1", [email]);
  await db().query("UPDATE ml_users SET last_login_at = now() WHERE id = $1", [user.id]);
  const cookie = await startSession(req, user.id);
  send(res, 200, { user: publicUser(user) }, { "Set-Cookie": cookie });
}

async function logout(req, res) {
  const token = parseCookies(req)[COOKIE];
  if (token) await db().query("DELETE FROM ml_sessions WHERE token_hash = $1", [sha256(token)]);
  send(res, 200, { ok: true }, { "Set-Cookie": sessionCookie(req, "", 0) });
}

async function me(req, res) {
  const user = await currentUser(req);
  if (!user) return send(res, 401, { error: "Not signed in." });
  send(res, 200, { user: publicUser(user) });
}

const ROUTES = {
  signup: { method: "POST", fn: signup },
  login: { method: "POST", fn: login },
  logout: { method: "POST", fn: logout },
  me: { method: "GET", fn: me },
};

module.exports = async function handler(req, res) {
  const action = (req.query && req.query.action) || String(req.url || "").split("?")[0].split("/").pop();
  const route = ROUTES[action];
  try {
    if (!route) throw httpError(404, "Not found.");
    if (req.method !== route.method) {
      res.setHeader("Allow", route.method);
      throw httpError(405, "Method not allowed.");
    }
    if (route.method === "POST" && !sameOrigin(req)) throw httpError(403, "Cross-site request refused.");
    await ensureSchema();
    await route.fn(req, res);
  } catch (e) {
    if (e.status) return send(res, e.status, { error: e.message });
    console.error("auth error", e);
    send(res, 500, { error: "Something went wrong on our side. Try again in a minute." });
  }
};

module.exports.ROLES = ROLES;
