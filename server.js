const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const pg = require("pg");
const pgSession = require("connect-pg-simple")(session);

const { Pool } = pg;
const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// Configuration
// ============================================================

if (!process.env.DATABASE_URL) {
  console.warn(
    "DATABASE_URL is not set. Authentication/data sync endpoints will not work until PostgreSQL is configured."
  );
}

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl:
        process.env.DATABASE_URL.includes("railway") ||
        process.env.NODE_ENV === "production"
          ? { rejectUnauthorized: false }
          : undefined,
    })
  : null;

const SESSION_SECRET =
  process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

const APP_URL = (process.env.APP_URL || "").replace(/\/+$/, "");

// Email verification code lifetime
const CODE_TTL_MINUTES = 10;

// Password reset link lifetime
const RESET_TTL_MINUTES = 30;

// Registration verification lifetime in the database
const REGISTER_VERIFICATION_TTL_MINUTES = 15;

// ============================================================
// Mail configuration
// ============================================================



// ============================================================
// Middleware
// ============================================================

app.use(express.json({ limit: "500kb" }));

// ============================================================
// Session
// ============================================================

if (pool) {
  app.use(
    session({
      store: new pgSession({
        pool,
        tableName: "user_sessions",
        createTableIfMissing: true,
      }),
      secret: SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
        maxAge: null,
      },
    })
  );
} else {
  // Local fallback.
  // Authentication/data sync still require PostgreSQL.
  app.use(
    session({
      secret: SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: false,
      },
    })
  );
}

// ============================================================
// Database helpers
// ============================================================

async function requireDB(res) {
  if (!pool) {
    res.status(503).json({
      error:
        "Database is not configured. Add DATABASE_URL in Railway.",
    });
    return false;
  }

  return true;
}

// ============================================================
// Database initialization
// ============================================================

async function initDB() {
  if (!pool) return;

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      email_verified BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS email_codes (
      id BIGSERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      purpose TEXT NOT NULL,
      code_hash TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      consumed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS email_codes_lookup
      ON email_codes(email, purpose, expires_at);

    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id BIGSERIAL PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS password_reset_lookup
      ON password_reset_tokens(token_hash, expires_at);

    CREATE TABLE IF NOT EXISTS user_data (
      user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      cabinet JSONB NOT NULL DEFAULT '[]'::jsonb,
      global_stats JSONB NOT NULL DEFAULT '{}'::jsonb,
      current_state JSONB,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    /*
     * IMPORTANT:
     *
     * This table fixes the registration verification problem.
     *
     * We no longer rely only on req.session.registerVerifiedEmail.
     * Once an email verification code is successfully verified,
     * the server creates a database record here.
     *
     * The subsequent "Create account" request checks this table.
     */
    CREATE TABLE IF NOT EXISTS register_verifications (
      email TEXT PRIMARY KEY,
      verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL
    );

    CREATE INDEX IF NOT EXISTS register_verifications_expiry
      ON register_verifications(expires_at);
  `);
}

// ============================================================
// Utility functions
// ============================================================

function normalizeEmail(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function hashToken(value) {
  return crypto
    .createHash("sha256")
    .update(String(value))
    .digest("hex");
}

function makeCode() {
  return String(crypto.randomInt(0, 1000000)).padStart(6, "0");
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ============================================================
// Email sending
// ============================================================

async function sendMail(to, subject, text, html) {
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.RESEND_FROM;

  if (!apiKey || !from) {
    throw new Error("Email service is not configured.");
  }

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from,
      to,
      subject,
      text,
      html
    })
  });

  if (!response.ok) {
    const errorText = await response.text();

    console.error("Resend API error:", errorText);

    throw new Error("Unable to send email.");
  }

  const result = await response.json();

  console.log("Email sent successfully:", result.id);

  return result;
}
// ============================================================
// Email verification code
// ============================================================

async function issueEmailCode(email, purpose) {
  if (!pool) {
    throw new Error("Database is not configured.");
  }

  // Prevent excessive code requests.
  const recent = await pool.query(
    `SELECT created_at
     FROM email_codes
     WHERE email=$1
       AND purpose=$2
       AND created_at > NOW() - INTERVAL '60 seconds'
     ORDER BY created_at DESC
     LIMIT 1`,
    [email, purpose]
  );

  if (recent.rowCount) {
    throw new Error(
      "Please wait a minute before requesting another code."
    );
  }

  const code = makeCode();

  // Invalidate all previous unused codes for this email/purpose.
  await pool.query(
    `UPDATE email_codes
     SET consumed_at=NOW()
     WHERE email=$1
       AND purpose=$2
       AND consumed_at IS NULL`,
    [email, purpose]
  );

  await pool.query(
    `INSERT INTO email_codes(
       email,
       purpose,
       code_hash,
       expires_at
     )
     VALUES(
       $1,
       $2,
       $3,
       NOW() + INTERVAL '${CODE_TTL_MINUTES} minutes'
     )`,
    [email, purpose, hashToken(code)]
  );

  const subject =
    purpose === "register"
      ? "The Lexicon — verify your email"
      : "The Lexicon — your login code";

  const text =
    purpose === "register"
      ? `Your The Lexicon verification code is ${code}. It expires in ${CODE_TTL_MINUTES} minutes.`
      : `Your The Lexicon login code is ${code}. It expires in ${CODE_TTL_MINUTES} minutes.`;

  const html =
    purpose === "register"
      ? `
        <div style="font-family:Arial,sans-serif">
          <p>Your The Lexicon verification code is:</p>
          <p style="font-size:32px;letter-spacing:8px">
            <strong>${code}</strong>
          </p>
          <p>This code expires in ${CODE_TTL_MINUTES} minutes.</p>
        </div>
      `
      : `
        <div style="font-family:Arial,sans-serif">
          <p>Your The Lexicon login code is:</p>
          <p style="font-size:32px;letter-spacing:8px">
            <strong>${code}</strong>
          </p>
          <p>This code expires in ${CODE_TTL_MINUTES} minutes.</p>
        </div>
      `;

  await sendMail(email, subject, text, html);
}

// ============================================================
// Verify email code
// ============================================================

async function verifyEmailCode(email, purpose, code) {
  if (!pool) return false;

  const result = await pool.query(
    `SELECT id
     FROM email_codes
     WHERE email=$1
       AND purpose=$2
       AND code_hash=$3
       AND consumed_at IS NULL
       AND expires_at > NOW()
     ORDER BY created_at DESC
     LIMIT 1`,
    [email, purpose, hashToken(code)]
  );

  if (!result.rowCount) {
    return false;
  }

  await pool.query(
    `UPDATE email_codes
     SET consumed_at=NOW()
     WHERE id=$1`,
    [result.rows[0].id]
  );

  return true;
}

// ============================================================
// Registration verification state
// ============================================================

/*
 * Mark the email as verified for registration.
 *
 * This is the important fix.
 *
 * The browser Session is still updated for compatibility,
 * but the database is now the real source of truth.
 */
async function markRegistrationEmailVerified(email) {
  if (!pool) return;

  await pool.query(
    `INSERT INTO register_verifications(
       email,
       verified_at,
       expires_at
     )
     VALUES(
       $1,
       NOW(),
       NOW() + INTERVAL '${REGISTER_VERIFICATION_TTL_MINUTES} minutes'
     )
     ON CONFLICT(email)
     DO UPDATE SET
       verified_at=NOW(),
       expires_at=NOW() + INTERVAL '${REGISTER_VERIFICATION_TTL_MINUTES} minutes'`,
    [email]
  );
}

/*
 * Check whether an email has recently passed registration
 * verification.
 */
async function isRegistrationEmailVerified(email) {
  if (!pool) return false;

  const result = await pool.query(
    `SELECT email
     FROM register_verifications
     WHERE email=$1
       AND expires_at > NOW()
     LIMIT 1`,
    [email]
  );

  return result.rowCount > 0;
}

/*
 * Once the account is successfully created, the temporary
 * verification record is removed.
 */
async function clearRegistrationEmailVerification(email) {
  if (!pool) return;

  await pool.query(
    `DELETE FROM register_verifications
     WHERE email=$1`,
    [email]
  );
}

// ============================================================
// Session helpers
// ============================================================

function setRememberCookie(req, remember) {
  /*
   * The session itself is stored server-side.
   *
   * remember = true:
   *   cookie survives browser restarts for 30 days.
   *
   * remember = false:
   *   browser session cookie.
   */
  req.session.cookie.maxAge = remember
    ? 1000 * 60 * 60 * 24 * 30
    : null;
}

function publicUser(row) {
  return {
    id: row.id,
    email: row.email,
    emailVerified: !!row.email_verified,
  };
}

async function createLoggedInSession(req, user, remember) {
  req.session.userId = user.id;

  // Registration verification should never remain in the session.
  delete req.session.registerVerifiedEmail;

  setRememberCookie(req, remember);

  await new Promise((resolve, reject) => {
    req.session.save((err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

// ============================================================
// Health check
// ============================================================

app.get("/api/health", async (req, res) => {
  let database = false;

  if (pool) {
    try {
      await pool.query("SELECT 1");
      database = true;
    } catch (_) {
      database = false;
    }
  }

  res.json({
    ok: true,
    database,
    message: "English Word Lab server is running!",
  });
});

// ============================================================
// AUTH — REGISTER: REQUEST CODE
// ============================================================

app.post("/api/auth/register/request-code", async (req, res) => {
  if (!(await requireDB(res))) return;

  try {
    const email = normalizeEmail(req.body.email);

    if (!isValidEmail(email)) {
      return res.status(400).json({
        error: "Please enter a valid email address.",
      });
    }

    const existing = await pool.query(
      `SELECT id, email_verified
       FROM users
       WHERE email=$1`,
      [email]
    );

    /*
     * If a verified account already exists,
     * registration is not allowed.
     */
    if (
      existing.rowCount &&
      existing.rows[0].email_verified
    ) {
      return res.status(409).json({
        error:
          "An account with this email already exists. Please log in.",
      });
    }

    /*
     * If the user starts registration again,
     * invalidate any previous temporary verification state.
     */
    await clearRegistrationEmailVerification(email);

    /*
     * Send the verification code.
     */
    await issueEmailCode(email, "register");

    /*
     * Keep the email in the Session too.
     * This is only a convenience/backward compatibility layer.
     * The database record will be the actual verification source.
     */
    req.session.registerEmail = email;

    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    res.json({
      ok: true,
    });
  } catch (error) {
    console.error(error);

    res.status(400).json({
      error:
        error.message ||
        "Unable to send verification code.",
    });
  }
});

// ============================================================
// AUTH — REGISTER: VERIFY CODE
// ============================================================

app.post("/api/auth/register/verify", async (req, res) => {
  if (!(await requireDB(res))) return;

  try {
    const email = normalizeEmail(req.body.email);
    const code = String(req.body.code || "").trim();

    if (!isValidEmail(email)) {
      return res.status(400).json({
        error: "Please enter a valid email address.",
      });
    }

    if (!/^\d{6}$/.test(code)) {
      return res.status(400).json({
        error: "Enter the 6-digit code.",
      });
    }

    /*
     * Verify the actual one-time code.
     */
    const valid = await verifyEmailCode(
      email,
      "register",
      code
    );

    if (!valid) {
      return res.status(400).json({
        error: "That code is invalid or has expired.",
      });
    }

    /*
     * ========================================================
     * IMPORTANT FIX
     * ========================================================
     *
     * The verification result is now written to PostgreSQL.
     *
     * Therefore the next request:
     *
     * POST /api/auth/register
     *
     * does NOT depend only on the Session.
     */
    await markRegistrationEmailVerified(email);

    /*
     * Also keep the Session state for compatibility with
     * the current frontend.
     */
    req.session.registerVerifiedEmail = email;
    req.session.registerEmail = email;

    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    res.json({
      ok: true,
    });
  } catch (error) {
    console.error(error);

    res.status(400).json({
      error: "Unable to verify this email.",
    });
  }
});

// ============================================================
// AUTH — REGISTER: CREATE ACCOUNT
// ============================================================

app.post("/api/auth/register", async (req, res) => {
  if (!(await requireDB(res))) return;

  const client = await pool.connect();

  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!isValidEmail(email)) {
      return res.status(400).json({
        error: "Please enter a valid email address.",
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Password must be at least 8 characters.",
      });
    }

    /*
     * ========================================================
     * IMPORTANT FIX
     * ========================================================
     *
     * The server now checks PostgreSQL instead of relying
     * exclusively on req.session.registerVerifiedEmail.
     */
    const verified = await isRegistrationEmailVerified(email);

    if (!verified) {
      return res.status(400).json({
        error:
          "Please verify your email first. The verification may have expired; please request a new code.",
      });
    }

    /*
     * Check whether the email already belongs to a verified
     * account.
     */
    const existing = await client.query(
      `SELECT *
       FROM users
       WHERE email=$1
       LIMIT 1`,
      [email]
    );

    if (
      existing.rowCount &&
      existing.rows[0].email_verified
    ) {
      return res.status(409).json({
        error:
          "An account with this email already exists. Please log in.",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    await client.query("BEGIN");

    let user;

    /*
     * --------------------------------------------------------
     * Case 1:
     * There is an old unverified user record.
     *
     * Complete that account instead of creating a duplicate.
     * --------------------------------------------------------
     */
    if (existing.rowCount) {
      await client.query(
        `UPDATE users
         SET
           password_hash=$1,
           email_verified=TRUE,
           updated_at=NOW()
         WHERE id=$2`,
        [
          passwordHash,
          existing.rows[0].id,
        ]
      );

      const updated = await client.query(
        `SELECT *
         FROM users
         WHERE id=$1`,
        [existing.rows[0].id]
      );

      user = updated.rows[0];

      /*
       * Make sure user_data exists.
       */
      await client.query(
        `INSERT INTO user_data(
           user_id,
           cabinet,
           global_stats,
           current_state
         )
         VALUES(
           $1,
           '[]'::jsonb,
           '{}'::jsonb,
           NULL
         )
         ON CONFLICT(user_id) DO NOTHING`,
        [user.id]
      );
    }

    /*
     * --------------------------------------------------------
     * Case 2:
     * New account.
     * --------------------------------------------------------
     */
    else {
      const id = crypto.randomUUID();

      await client.query(
        `INSERT INTO users(
           id,
           email,
           password_hash,
           email_verified
         )
         VALUES(
           $1,
           $2,
           $3,
           TRUE
         )`,
        [
          id,
          email,
          passwordHash,
        ]
      );

      await client.query(
        `INSERT INTO user_data(
           user_id,
           cabinet,
           global_stats,
           current_state
         )
         VALUES(
           $1,
           '[]'::jsonb,
           '{}'::jsonb,
           NULL
         )`,
        [id]
      );

      const created = await client.query(
        `SELECT *
         FROM users
         WHERE id=$1`,
        [id]
      );

      user = created.rows[0];
    }

    await client.query("COMMIT");

    /*
     * Verification is a one-time registration state.
     * Once account creation succeeds, remove it.
     */
    await clearRegistrationEmailVerification(email);

    /*
     * Log the user in.
     *
     * The frontend will then show the "Remember this device?"
     * modal.
     */
    await createLoggedInSession(
      req,
      user,
      false
    );

    res.json({
      user: publicUser(user),
    });
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (_) {}

    console.error(error);

    res.status(400).json({
      error: "Unable to create the account.",
    });
  } finally {
    client.release();
  }
});

// ============================================================
// AUTH — PASSWORD LOGIN
// ============================================================

app.post("/api/auth/login/password", async (req, res) => {
  if (!(await requireDB(res))) return;

  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({
        error:
          "Please enter your email and password.",
      });
    }

    const result = await pool.query(
      `SELECT *
       FROM users
       WHERE email=$1`,
      [email]
    );

    if (!result.rowCount) {
      return res.status(401).json({
        error: "Incorrect email or password.",
      });
    }

    const user = result.rows[0];

    if (!user.email_verified) {
      return res.status(403).json({
        error:
          "Please verify your email before logging in.",
      });
    }

    const ok = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!ok) {
      return res.status(401).json({
        error: "Incorrect email or password.",
      });
    }

    await createLoggedInSession(
      req,
      user,
      !!req.body.remember
    );

    res.json({
      user: publicUser(user),
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to log in.",
    });
  }
});

// ============================================================
// AUTH — LOGIN CODE REQUEST
// ============================================================

app.post("/api/auth/login/request-code", async (req, res) => {
  if (!(await requireDB(res))) return;

  try {
    const email = normalizeEmail(req.body.email);

    if (!isValidEmail(email)) {
      return res.status(400).json({
        error: "Please enter a valid email address.",
      });
    }

    const result = await pool.query(
      `SELECT id, email_verified
       FROM users
       WHERE email=$1`,
      [email]
    );

    if (
      !result.rowCount ||
      !result.rows[0].email_verified
    ) {
      return res.status(400).json({
        error:
          "No verified account was found for that email.",
      });
    }

    await issueEmailCode(
      email,
      "login"
    );

    res.json({
      ok: true,
    });
  } catch (error) {
    console.error(error);

    res.status(400).json({
      error:
        error.message ||
        "Unable to send login code.",
    });
  }
});

// ============================================================
// AUTH — LOGIN WITH CODE
// ============================================================

app.post("/api/auth/login/code", async (req, res) => {
  if (!(await requireDB(res))) return;

  try {
    const email = normalizeEmail(req.body.email);
    const code = String(req.body.code || "").trim();

    if (!isValidEmail(email)) {
      return res.status(400).json({
        error: "Please enter a valid email address.",
      });
    }

    if (!/^\d{6}$/.test(code)) {
      return res.status(400).json({
        error: "Enter the 6-digit code.",
      });
    }

    const result = await pool.query(
      `SELECT *
       FROM users
       WHERE email=$1
         AND email_verified=TRUE`,
      [email]
    );

    if (!result.rowCount) {
      return res.status(401).json({
        error:
          "Unable to verify that account.",
      });
    }

    const valid = await verifyEmailCode(
      email,
      "login",
      code
    );

    if (!valid) {
      return res.status(401).json({
        error:
          "That code is invalid or has expired.",
      });
    }

    await createLoggedInSession(
      req,
      result.rows[0],
      !!req.body.remember
    );

    res.json({
      user: publicUser(result.rows[0]),
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error:
        "Unable to log in with email code.",
    });
  }
});

// ============================================================
// AUTH — REMEMBER THIS DEVICE
// ============================================================

app.post(
  "/api/auth/session-preference",
  (req, res) => {
    if (!req.session.userId) {
      return res.status(401).json({
        error: "Not logged in.",
      });
    }

    setRememberCookie(
      req,
      !!req.body.remember
    );

    req.session.save((err) => {
      if (err) {
        return res.status(500).json({
          error:
            "Unable to update session.",
        });
      }

      res.json({
        ok: true,
      });
    });
  }
);

// ============================================================
// AUTH — CURRENT USER
// ============================================================

app.get("/api/auth/me", async (req, res) => {
  if (!(await requireDB(res))) return;

  if (!req.session.userId) {
    return res.status(401).json({
      error: "Not logged in.",
    });
  }

  try {
    const result = await pool.query(
      `SELECT *
       FROM users
       WHERE id=$1`,
      [req.session.userId]
    );

    if (!result.rowCount) {
      req.session.destroy(() => {});

      return res.status(401).json({
        error: "Session expired.",
      });
    }

    res.json({
      user: publicUser(result.rows[0]),
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to check session.",
    });
  }
});

// ============================================================
// AUTH — LOGOUT
// ============================================================

app.post("/api/auth/logout", (req, res) => {
  req.session.destroy((err) => {
    res.clearCookie("connect.sid");

    if (err) {
      return res.status(500).json({
        error: "Unable to log out.",
      });
    }

    res.json({
      ok: true,
    });
  });
});

// ============================================================
// PASSWORD RESET — REQUEST
// ============================================================

app.post(
  "/api/auth/password-reset/request",
  async (req, res) => {
    if (!(await requireDB(res))) return;

    /*
     * Always use the same response so attackers cannot
     * determine whether an email is registered.
     */
    const generic =
      "If that account exists, a reset link has been sent.";

    try {
      const email = normalizeEmail(
        req.body.email
      );

      if (!isValidEmail(email)) {
        return res.json({
          ok: true,
          message: generic,
        });
      }

      const result = await pool.query(
        `SELECT *
         FROM users
         WHERE email=$1
           AND email_verified=TRUE`,
        [email]
      );

      if (!result.rowCount) {
        return res.json({
          ok: true,
          message: generic,
        });
      }

      /*
       * Invalidate older unused reset tokens.
       */
      await pool.query(
        `UPDATE password_reset_tokens
         SET used_at=NOW()
         WHERE user_id=$1
           AND used_at IS NULL`,
        [result.rows[0].id]
      );

      /*
       * Generate a secure random reset token.
       */
      const rawToken =
        crypto.randomBytes(32).toString("hex");

      await pool.query(
        `INSERT INTO password_reset_tokens(
           user_id,
           token_hash,
           expires_at
         )
         VALUES(
           $1,
           $2,
           NOW() + INTERVAL '${RESET_TTL_MINUTES} minutes'
         )`,
        [
          result.rows[0].id,
          hashToken(rawToken),
        ]
      );

      /*
       * Build reset URL.
       *
       * APP_URL should normally be your Railway/public website URL.
       */
      const base =
        APP_URL ||
        `${req.protocol}://${req.get("host")}`;

      const link =
        `${base}/reset-password?reset=` +
        encodeURIComponent(rawToken);

      await sendMail(
        email,
        "The Lexicon — reset your password",
        `Use this link to reset your The Lexicon password. It expires in ${RESET_TTL_MINUTES} minutes:\n\n${link}`,
        `
          <div style="font-family:Arial,sans-serif">
            <p>
              Use the secure link below to reset your
              The Lexicon password.
            </p>

            <p>
              <a href="${link}">
                Reset your password
              </a>
            </p>

            <p>
              This link expires in
              ${RESET_TTL_MINUTES} minutes.
            </p>
          </div>
        `
      );

      res.json({
        ok: true,
        message: generic,
      });
    } catch (error) {
      console.error(error);

      /*
       * Do not expose account existence or internal
       * email-service errors to the user.
       */
      res.json({
        ok: true,
        message: generic,
      });
    }
  }
);

// ============================================================
// PASSWORD RESET — COMPLETE
// ============================================================

app.post(
  "/api/auth/password-reset/complete",
  async (req, res) => {
    if (!(await requireDB(res))) return;

    const client = await pool.connect();

    try {
      const token = String(
        req.body.token || ""
      );

      const password = String(
        req.body.password || ""
      );

      if (!token || password.length < 8) {
        return res.status(400).json({
          error:
            "Invalid reset request or password.",
        });
      }

      const result = await client.query(
        `SELECT
           u.*,
           prt.id AS reset_id
         FROM password_reset_tokens prt
         JOIN users u
           ON u.id=prt.user_id
         WHERE prt.token_hash=$1
           AND prt.used_at IS NULL
           AND prt.expires_at>NOW()
         LIMIT 1`,
        [hashToken(token)]
      );

      if (!result.rowCount) {
        return res.status(400).json({
          error:
            "This reset link is invalid or has expired.",
        });
      }

      const user = result.rows[0];

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      await client.query("BEGIN");

      await client.query(
        `UPDATE users
         SET
           password_hash=$1,
           updated_at=NOW()
         WHERE id=$2`,
        [
          passwordHash,
          user.id,
        ]
      );

      await client.query(
        `UPDATE password_reset_tokens
         SET used_at=NOW()
         WHERE id=$1`,
        [user.reset_id]
      );

      /*
       * Invalidate every other reset token for this account.
       */
      await client.query(
        `UPDATE password_reset_tokens
         SET used_at=NOW()
         WHERE user_id=$1
           AND used_at IS NULL`,
        [user.id]
      );

      await client.query("COMMIT");

      /*
       * Automatically log the user in.
       */
      await createLoggedInSession(
        req,
        user,
        false
      );

      res.json({
        user: publicUser(user),
      });
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch (_) {}

      console.error(error);

      res.status(400).json({
        error:
          "Unable to reset the password.",
      });
    } finally {
      client.release();
    }
  }
);

// ============================================================
// USER DATA — GET
// ============================================================

app.get("/api/data", async (req, res) => {
  if (!(await requireDB(res))) return;

  if (!req.session.userId) {
    return res.status(401).json({
      error: "Not logged in.",
    });
  }

  try {
    const result = await pool.query(
      `SELECT
         cabinet,
         global_stats,
         current_state
       FROM user_data
       WHERE user_id=$1`,
      [req.session.userId]
    );

    if (!result.rowCount) {
      return res.json({
        cabinet: [],
        globalStats: {},
        currentState: null,
      });
    }

    const row = result.rows[0];

    res.json({
      cabinet: row.cabinet,
      globalStats: row.global_stats,
      currentState: row.current_state,
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error:
        "Unable to load user data.",
    });
  }
});

// ============================================================
// USER DATA — SAVE
// ============================================================

app.put("/api/data", async (req, res) => {
  if (!(await requireDB(res))) return;

  if (!req.session.userId) {
    return res.status(401).json({
      error: "Not logged in.",
    });
  }

  try {
    const cabinet = Array.isArray(
      req.body.cabinet
    )
      ? req.body.cabinet
      : [];

    const globalStats =
      req.body.globalStats &&
      typeof req.body.globalStats === "object"
        ? req.body.globalStats
        : {};

    const currentState =
      req.body.currentState ?? null;

    await pool.query(
      `INSERT INTO user_data(
         user_id,
         cabinet,
         global_stats,
         current_state,
         updated_at
       )
       VALUES(
         $1,
         $2::jsonb,
         $3::jsonb,
         $4::jsonb,
         NOW()
       )
       ON CONFLICT(user_id)
       DO UPDATE SET
         cabinet=EXCLUDED.cabinet,
         global_stats=EXCLUDED.global_stats,
         current_state=EXCLUDED.current_state,
         updated_at=NOW()`,
      [
        req.session.userId,
        JSON.stringify(cabinet),
        JSON.stringify(globalStats),
        JSON.stringify(currentState),
      ]
    );

    res.json({
      ok: true,
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error:
        "Unable to save user data.",
    });
  }
});

// ============================================================
// DEEPSEEK — GENERATE VOCABULARY
// ============================================================

app.post("/api/generate", async (req, res) => {
  try {
    const { words } = req.body;

    if (!Array.isArray(words)) {
      return res.status(400).json({
        error: "words must be an array",
      });
    }

    if (words.length === 0) {
      return res.status(400).json({
        error:
          "Please provide at least one word",
      });
    }

    if (words.length > 50) {
      return res.status(400).json({
        error:
          "Maximum 50 words per request",
      });
    }

    const cleanedWords = words
      .map((word) =>
        String(word).trim()
      )
      .filter(Boolean);

    if (cleanedWords.length === 0) {
      return res.status(400).json({
        error:
          "No valid words provided",
      });
    }

    if (!process.env.DEEPSEEK_API_KEY) {
      return res.status(500).json({
        error:
          "DeepSeek API key is not configured",
      });
    }

    const systemPrompt = `
You are an English vocabulary learning assistant.

The user will provide a list of English vocabulary words.

Generate a vocabulary library for these words.

IMPORTANT:
Each item in the user's list represents exactly ONE vocabulary word.
Treat each input item as a complete word.
NEVER split, segment, decompose, shorten, or reinterpret an input word.

For example:
- "banana" must produce exactly one entry with "word": "banana"
- "beautiful" must produce exactly one entry with "word": "beautiful"
- "reluctant" must produce exactly one entry with "word": "reluctant"

The number of vocabulary entries MUST match the number of valid input words.
Preserve the original word spelling exactly.

You MUST return valid JSON.

The JSON must have exactly this structure:

{
  "words": [
    {
      "word": "example",
      "definition": "a clear and concise English definition",
      "examples": [
        "A natural English example sentence.",
        "A second natural English example sentence.",
        "A third natural English example sentence."
      ],
      "synonyms": ["word1", "word2", "word3"],
      "antonyms": ["word1", "word2"],
      "root": "A concise explanation of the word origin or root.",
      "cognates": ["word1", "word2"]
    }
  ]
}

Rules:

1. Keep the original word spelling exactly as provided by the user.
2. Never split one input word into multiple words.
3. Create exactly one vocabulary entry for each input word.
4. The number of entries in "words" must match the number of valid input words.
5. Definitions must be clear, concise, and suitable for English learners.
6. Generate EXACTLY THREE example sentences for every word.
7. The three example sentences should be natural, grammatically correct, and useful for learning.
8. The three examples should use the target word naturally and demonstrate meaningful usage.
9. Avoid making the three example sentences repetitive.
10. Provide useful synonyms when possible.
11. Provide useful antonyms when possible.
12. Explain the word's root or etymology briefly and accurately when possible.
13. Provide useful English derivatives or cognates when possible.
14. If a field has no useful information, use an empty array or an empty string.
15. Do not add extra fields.
16. Return JSON only.
`;

    const userPrompt = `
Generate the vocabulary library for these words:

${cleanedWords.join("\n")}
`;

    const response = await fetch(
      "https://api.deepseek.com/chat/completions",
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/json",
          Authorization:
            `Bearer ${process.env.DEEPSEEK_API_KEY}`,
        },
        body: JSON.stringify({
          model: "deepseek-v4-flash",

          thinking: {
            type: "disabled",
          },

          messages: [
            {
              role: "system",
              content: systemPrompt,
            },
            {
              role: "user",
              content: userPrompt,
            },
          ],

          response_format: {
            type: "json_object",
          },

          max_tokens: 6000,

          stream: false,
        }),
      }
    );

    if (!response.ok) {
      const errorText =
        await response.text();

      console.error(
        "DeepSeek API error:",
        errorText
      );

      return res.status(502).json({
        error:
          "DeepSeek API request failed",
      });
    }

    const data =
      await response.json();

    const content =
      data?.choices?.[0]?.message
        ?.content;

    if (!content) {
      return res.status(502).json({
        error:
          "DeepSeek returned an empty response",
      });
    }

    let result;

    try {
      result = JSON.parse(content);
    } catch (error) {
      console.error(
        "Invalid JSON from DeepSeek:",
        content
      );

      return res.status(502).json({
        error:
          "DeepSeek returned invalid JSON",
      });
    }

    if (
      !result.words ||
      !Array.isArray(result.words)
    ) {
      return res.status(502).json({
        error:
          "Invalid vocabulary data returned by DeepSeek",
      });
    }

    if (
      result.words.length !==
      cleanedWords.length
    ) {
      return res.status(502).json({
        error:
          "DeepSeek returned an incorrect number of vocabulary entries",
      });
    }

    const expectedWords =
      cleanedWords.map((word) =>
        word.toLowerCase()
      );

    const returnedWords =
      result.words.map((item) =>
        String(item.word || "")
          .trim()
          .toLowerCase()
      );

    if (
      expectedWords.some(
        (word, index) =>
          returnedWords[index] !== word
      )
    ) {
      return res.status(502).json({
        error:
          "DeepSeek did not preserve the original vocabulary words",
      });
    }

    for (const item of result.words) {
      if (
        !Array.isArray(item.examples) ||
        item.examples.length !== 3
      ) {
        return res.status(502).json({
          error:
            `DeepSeek did not return exactly three examples for "${item.word}"`,
        });
      }
    }

    res.json(result);
  } catch (error) {
    console.error(
      "Server error:",
      error
    );

    res.status(500).json({
      error:
        "Internal server error",
    });
  }
});

// ============================================================
// RESET PASSWORD PAGE
// ============================================================

/*
 * Serve the same SPA entry point for password reset links.
 */
app.get("/reset-password", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );
});

// ============================================================
// STATIC WEBSITE
// ============================================================

app.use(
  express.static(
    path.join(
      __dirname,
      "public"
    )
  )
);

// ============================================================
// START SERVER
// ============================================================

initDB()
  .then(() => {
    console.log("Database initialized.");

    app.listen(PORT, () => {
      console.log(
        `Server running on port ${PORT}`
      );
    });
  })
  .catch((error) => {
    console.error(
      "Database initialization failed:",
      error
    );

    process.exit(1);
  });
