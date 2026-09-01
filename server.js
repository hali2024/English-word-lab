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

/*
|--------------------------------------------------------------------------
| Environment
|--------------------------------------------------------------------------
*/

if (!process.env.DATABASE_URL) {
  console.warn(
    "DATABASE_URL is not set. Authentication/data sync endpoints will not work until PostgreSQL is configured."
  );
}

if (!process.env.RESEND_API_KEY) {
  console.warn(
    "RESEND_API_KEY is not set. Email verification and password reset emails will not work."
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
  process.env.SESSION_SECRET ||
  crypto.randomBytes(32).toString("hex");

const APP_URL = (process.env.APP_URL || "").replace(/\/+$/, "");

const RESEND_API_KEY = process.env.RESEND_API_KEY || "";

const RESEND_FROM =
  process.env.RESEND_FROM ||
  "The Lexicon <hello@lexiconoftheworld.win>";

const CODE_TTL_MINUTES = 10;
const RESET_TTL_MINUTES = 30;

/*
|--------------------------------------------------------------------------
| Express
|--------------------------------------------------------------------------
*/

app.use(express.json({ limit: "500kb" }));

/*
|--------------------------------------------------------------------------
| Sessions
|--------------------------------------------------------------------------
*/

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
  // Local fallback so the static site and /api/generate can still run.
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

/*
|--------------------------------------------------------------------------
| Database helpers
|--------------------------------------------------------------------------
*/

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
  `);
}

/*
|--------------------------------------------------------------------------
| General helpers
|--------------------------------------------------------------------------
*/

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

/*
|--------------------------------------------------------------------------
| Resend email sender
|--------------------------------------------------------------------------
|
| IMPORTANT:
| We intentionally use the Resend HTTPS API instead of SMTP.
|
| Railway Hobby blocks outbound SMTP connections, so Nodemailer SMTP
| cannot be used here. Node.js 20+ has built-in fetch(), so no extra
| npm package is required.
|
*/

async function sendMail(to, subject, text, html) {
  if (!RESEND_API_KEY) {
    throw new Error("RESEND_API_KEY is not configured.");
  }

  const response = await fetch(
    "https://api.resend.com/emails",
    {
      method: "POST",

      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${RESEND_API_KEY}`,
      },

      body: JSON.stringify({
        from: RESEND_FROM,
        to: [to],
        subject,
        text,
        html,
      }),
    }
  );

  let data = null;

  try {
    data = await response.json();
  } catch (_) {
    data = null;
  }

  if (!response.ok) {
    const message =
      data?.message ||
      data?.error ||
      `Resend API request failed with status ${response.status}.`;

    throw new Error(`Resend API error: ${message}`);
  }

  console.log(
    `Email sent through Resend. To: ${to}, Subject: ${subject}, ID: ${
      data?.id || "unknown"
    }`
  );

  return data;
}

/*
|--------------------------------------------------------------------------
| Email verification / login code
|--------------------------------------------------------------------------
*/

async function issueEmailCode(email, purpose) {
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

  /*
   * Invalidate any previous unused code for the same purpose.
   */
  await pool.query(
    `UPDATE email_codes
     SET consumed_at=NOW()
     WHERE email=$1
       AND purpose=$2
       AND consumed_at IS NULL`,
    [email, purpose]
  );

  /*
   * Store only a SHA-256 hash of the verification code.
   */
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
       NOW()+INTERVAL '${CODE_TTL_MINUTES} minutes'
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
        <div style="font-family: Georgia, serif; line-height: 1.6;">
          <h2>The Lexicon</h2>
          <p>Use the verification code below to verify your email address.</p>

          <p style="
            font-size: 32px;
            letter-spacing: 8px;
            margin: 24px 0;
          ">
            <strong>${code}</strong>
          </p>

          <p>
            This code expires in ${CODE_TTL_MINUTES} minutes.
          </p>
        </div>
      `
      : `
        <div style="font-family: Georgia, serif; line-height: 1.6;">
          <h2>The Lexicon</h2>
          <p>Use the login code below to sign in.</p>

          <p style="
            font-size: 32px;
            letter-spacing: 8px;
            margin: 24px 0;
          ">
            <strong>${code}</strong>
          </p>

          <p>
            This code expires in ${CODE_TTL_MINUTES} minutes.
          </p>
        </div>
      `;

  await sendMail(
    email,
    subject,
    text,
    html
  );
}

async function verifyEmailCode(email, purpose, code) {
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

/*
|--------------------------------------------------------------------------
| Session helpers
|--------------------------------------------------------------------------
*/

function setRememberCookie(req, remember) {
  /*
   * The session itself is stored server-side.
   *
   * remember = true:
   * persistent cookie for 30 days
   *
   * remember = false:
   * session cookie
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

  setRememberCookie(req, remember);

  await new Promise((resolve, reject) => {
    req.session.save((err) => {
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    });
  });
}

/*
|--------------------------------------------------------------------------
| Health check
|--------------------------------------------------------------------------
*/

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

/*
|--------------------------------------------------------------------------
| Authentication — registration
|--------------------------------------------------------------------------
*/

/*
 * Step 1:
 * User enters email.
 *
 * Server:
 * 1. validates email
 * 2. checks existing account
 * 3. generates 6-digit code
 * 4. stores hashed code in PostgreSQL
 * 5. sends code using Resend HTTPS API
 */

app.post(
  "/api/auth/register/request-code",
  async (req, res) => {
    if (!(await requireDB(res))) return;

    try {
      const email = normalizeEmail(req.body.email);

      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
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

      if (
        existing.rowCount &&
        existing.rows[0].email_verified
      ) {
        return res.status(409).json({
          error:
            "An account with this email already exists. Please log in.",
        });
      }

      await issueEmailCode(
        email,
        "register"
      );

      res.json({
        ok: true,
      });
    } catch (error) {
      console.error(
        "Registration email error:",
        error
      );

      res.status(400).json({
        error:
          error.message ||
          "Unable to send verification code.",
      });
    }
  }
);

/*
 * Step 2:
 * Verify the 6-digit registration code.
 */

app.post(
  "/api/auth/register/verify",
  async (req, res) => {
    if (!(await requireDB(res))) return;

    try {
      const email = normalizeEmail(
        req.body.email
      );

      const code = String(
        req.body.code || ""
      ).trim();

      if (!/^\d{6}$/.test(code)) {
        return res.status(400).json({
          error: "Enter the 6-digit code.",
        });
      }

      const valid = await verifyEmailCode(
        email,
        "register",
        code
      );

      if (!valid) {
        return res.status(400).json({
          error:
            "That code is invalid or has expired.",
        });
      }

      req.session.registerVerifiedEmail =
        email;

      await new Promise(
        (resolve, reject) => {
          req.session.save((err) => {
            if (err) {
              reject(err);
            } else {
              resolve();
            }
          });
        }
      );

      res.json({
        ok: true,
      });
    } catch (error) {
      console.error(
        "Email verification error:",
        error
      );

      res.status(400).json({
        error:
          "Unable to verify this email.",
      });
    }
  }
);

/*
 * Step 3:
 * User has verified email and now creates password.
 */

app.post(
  "/api/auth/register",
  async (req, res) => {
    if (!(await requireDB(res))) return;

    try {
      const email = normalizeEmail(
        req.body.email
      );

      const password = String(
        req.body.password || ""
      );

      if (
        req.session.registerVerifiedEmail !==
        email
      ) {
        return res.status(400).json({
          error:
            "Please verify your email first.",
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          error:
            "Password must be at least 8 characters.",
        });
      }

      const existing = await pool.query(
        `SELECT id, email_verified
         FROM users
         WHERE email=$1`,
        [email]
      );

      if (
        existing.rowCount &&
        existing.rows[0].email_verified
      ) {
        return res.status(409).json({
          error:
            "An account with this email already exists.",
        });
      }

      const id = crypto.randomUUID();

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      /*
       * We use a dedicated PostgreSQL client
       * for the transaction.
       */

      const client =
        await pool.connect();

      try {
        await client.query(
          "BEGIN"
        );

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

          const user =
            await client.query(
              `SELECT *
               FROM users
               WHERE id=$1`,
              [
                existing.rows[0].id,
              ]
            );

          await client.query(
            "COMMIT"
          );

          delete req.session
            .registerVerifiedEmail;

          await createLoggedInSession(
            req,
            user.rows[0],
            false
          );

          return res.json({
            user: publicUser(
              user.rows[0]
            ),
          });
        }

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

        const user =
          await client.query(
            `SELECT *
             FROM users
             WHERE id=$1`,
            [id]
          );

        await client.query(
          "COMMIT"
        );

        delete req.session
          .registerVerifiedEmail;

        await createLoggedInSession(
          req,
          user.rows[0],
          false
        );

        res.json({
          user: publicUser(
            user.rows[0]
          ),
        });
      } catch (error) {
        await client.query(
          "ROLLBACK"
        );

        throw error;
      } finally {
        client.release();
      }
    } catch (error) {
      console.error(
        "Registration error:",
        error
      );

      res.status(400).json({
        error:
          "Unable to create the account.",
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| Authentication — password login
|--------------------------------------------------------------------------
*/

app.post(
  "/api/auth/login/password",
  async (req, res) => {
    if (!(await requireDB(res))) return;

    try {
      const email = normalizeEmail(
        req.body.email
      );

      const password = String(
        req.body.password || ""
      );

      const result = await pool.query(
        `SELECT *
         FROM users
         WHERE email=$1`,
        [email]
      );

      if (!result.rowCount) {
        return res.status(401).json({
          error:
            "Incorrect email or password.",
        });
      }

      const user =
        result.rows[0];

      if (!user.email_verified) {
        return res.status(403).json({
          error:
            "Please verify your email before logging in.",
        });
      }

      const ok =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!ok) {
        return res.status(401).json({
          error:
            "Incorrect email or password.",
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
      console.error(
        "Password login error:",
        error
      );

      res.status(500).json({
        error:
          "Unable to log in.",
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| Authentication — request login code
|--------------------------------------------------------------------------
*/

app.post(
  "/api/auth/login/request-code",
  async (req, res) => {
    if (!(await requireDB(res))) return;

    try {
      const email = normalizeEmail(
        req.body.email
      );

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
      console.error(
        "Login code error:",
        error
      );

      res.status(400).json({
        error:
          error.message ||
          "Unable to send login code.",
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| Authentication — login using code
|--------------------------------------------------------------------------
*/

app.post(
  "/api/auth/login/code",
  async (req, res) => {
    if (!(await requireDB(res))) return;

    try {
      const email = normalizeEmail(
        req.body.email
      );

      const code = String(
        req.body.code || ""
      ).trim();

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

      const valid =
        await verifyEmailCode(
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
        user: publicUser(
          result.rows[0]
        ),
      });
    } catch (error) {
      console.error(
        "Code login error:",
        error
      );

      res.status(500).json({
        error:
          "Unable to log in with email code.",
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| Authentication — session preference
|--------------------------------------------------------------------------
*/

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

    req.session.save(
      (err) => {
        if (err) {
          return res.status(500).json({
            error:
              "Unable to update session.",
          });
        }

        res.json({
          ok: true,
        });
      }
    );
  }
);

/*
|--------------------------------------------------------------------------
| Authentication — current user
|--------------------------------------------------------------------------
*/

app.get(
  "/api/auth/me",
  async (req, res) => {
    if (!(await requireDB(res))) return;

    if (!req.session.userId) {
      return res.status(401).json({
        error: "Not logged in.",
      });
    }

    const result = await pool.query(
      `SELECT *
       FROM users
       WHERE id=$1`,
      [req.session.userId]
    );

    if (!result.rowCount) {
      req.session.destroy(
        () => {}
      );

      return res.status(401).json({
        error:
          "Session expired.",
      });
    }

    res.json({
      user: publicUser(
        result.rows[0]
      ),
    });
  }
);

/*
|--------------------------------------------------------------------------
| Authentication — logout
|--------------------------------------------------------------------------
*/

app.post(
  "/api/auth/logout",
  (req, res) => {
    req.session.destroy(
      (err) => {
        res.clearCookie(
          "connect.sid"
        );

        if (err) {
          return res.status(500).json({
            error:
              "Unable to log out.",
          });
        }

        res.json({
          ok: true,
        });
      }
    );
  }
);

/*
|--------------------------------------------------------------------------
| Password reset — request secure link
|--------------------------------------------------------------------------
*/

app.post(
  "/api/auth/password-reset/request",
  async (req, res) => {
    if (!(await requireDB(res))) return;

    /*
     * Always use the same response so that
     * attackers cannot discover whether an
     * email address has an account.
     */

    const generic =
      "If that account exists, a reset link has been sent.";

    try {
      const email = normalizeEmail(
        req.body.email
      );

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

      const rawToken =
        crypto.randomBytes(32)
          .toString("hex");

      /*
       * Store only the hash of the reset token.
       */

      await pool.query(
        `INSERT INTO password_reset_tokens(
           user_id,
           token_hash,
           expires_at
         )
         VALUES(
           $1,
           $2,
           NOW()+INTERVAL '${RESET_TTL_MINUTES} minutes'
         )`,
        [
          result.rows[0].id,
          hashToken(rawToken),
        ]
      );

      /*
       * Prefer APP_URL if configured.
       * Otherwise fall back to the current request host.
       */

      const base =
        APP_URL ||
        `${req.protocol}://${req.get(
          "host"
        )}`;

      const link =
        `${base}/reset-password?reset=` +
        encodeURIComponent(
          rawToken
        );

      await sendMail(
        email,

        "The Lexicon — reset your password",

        `Use this link to reset your The Lexicon password. It expires in ${RESET_TTL_MINUTES} minutes:

${link}`,

        `
        <div style="font-family: Georgia, serif; line-height: 1.6;">
          <h2>The Lexicon</h2>

          <p>
            We received a request to reset your password.
          </p>

          <p>
            <a
              href="${link}"
              style="
                display:inline-block;
                padding:12px 20px;
                background:#71333a;
                color:#ffffff;
                text-decoration:none;
                border-radius:4px;
              "
            >
              Reset your password
            </a>
          </p>

          <p>
            This link expires in ${RESET_TTL_MINUTES} minutes.
          </p>

          <p>
            If you did not request a password reset,
            you can safely ignore this email.
          </p>
        </div>
        `
      );

      res.json({
        ok: true,
        message: generic,
      });
    } catch (error) {
      console.error(
        "Password reset email error:",
        error
      );

      /*
       * Do not reveal internal email errors
       * to the user.
       */

      res.json({
        ok: true,
        message: generic,
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| Password reset — complete
|--------------------------------------------------------------------------
*/

app.post(
  "/api/auth/password-reset/complete",
  async (req, res) => {
    if (!(await requireDB(res))) return;

    try {
      const token = String(
        req.body.token || ""
      );

      const password = String(
        req.body.password || ""
      );

      if (
        !token ||
        password.length < 8
      ) {
        return res.status(400).json({
          error:
            "Invalid reset request or password.",
        });
      }

      const result = await pool.query(
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

      const user =
        result.rows[0];

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const client =
        await pool.connect();

      try {
        await client.query(
          "BEGIN"
        );

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

        await client.query(
          "COMMIT"
        );
      } catch (error) {
        await client.query(
          "ROLLBACK"
        );

        throw error;
      } finally {
        client.release();
      }

      await createLoggedInSession(
        req,
        user,
        false
      );

      res.json({
        user: publicUser(user),
      });
    } catch (error) {
      console.error(
        "Password reset completion error:",
        error
      );

      res.status(400).json({
        error:
          "Unable to reset the password.",
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| User data
|--------------------------------------------------------------------------
*/

app.get(
  "/api/data",
  async (req, res) => {
    if (!(await requireDB(res))) return;

    if (!req.session.userId) {
      return res.status(401).json({
        error: "Not logged in.",
      });
    }

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

    const row =
      result.rows[0];

    res.json({
      cabinet: row.cabinet,
      globalStats:
        row.global_stats,
      currentState:
        row.current_state,
    });
  }
);

app.put(
  "/api/data",
  async (req, res) => {
    if (!(await requireDB(res))) return;

    if (!req.session.userId) {
      return res.status(401).json({
        error: "Not logged in.",
      });
    }

    const cabinet =
      Array.isArray(
        req.body.cabinet
      )
        ? req.body.cabinet
        : [];

    const globalStats =
      req.body.globalStats &&
      typeof req.body.globalStats ===
        "object"
        ? req.body.globalStats
        : {};

    const currentState =
      req.body.currentState ??
      null;

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
  }
);

/*
|--------------------------------------------------------------------------
| Generate vocabulary with DeepSeek
|--------------------------------------------------------------------------
*/

app.post(
  "/api/generate",
  async (req, res) => {
    try {
      const { words } =
        req.body;

      if (!Array.isArray(words)) {
        return res.status(400).json({
          error:
            "words must be an array",
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

      const cleanedWords =
        words
          .map((word) =>
            String(word).trim()
          )
          .filter(Boolean);

      if (
        cleanedWords.length === 0
      ) {
        return res.status(400).json({
          error:
            "No valid words provided",
        });
      }

      if (
        !process.env.DEEPSEEK_API_KEY
      ) {
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

      const response =
        await fetch(
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
              model:
                "deepseek-v4-flash",

              thinking: {
                type: "disabled",
              },

              messages: [
                {
                  role: "system",
                  content:
                    systemPrompt,
                },

                {
                  role: "user",
                  content:
                    userPrompt,
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
        data?.choices?.[0]
          ?.message?.content;

      if (!content) {
        return res.status(502).json({
          error:
            "DeepSeek returned an empty response",
        });
      }

      let result;

      try {
        result =
          JSON.parse(content);
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
        !Array.isArray(
          result.words
        )
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
        cleanedWords.map(
          (word) =>
            word.toLowerCase()
        );

      const returnedWords =
        result.words.map(
          (item) =>
            String(
              item.word || ""
            )
              .trim()
              .toLowerCase()
        );

      if (
        expectedWords.some(
          (word, index) =>
            returnedWords[index] !==
            word
        )
      ) {
        return res.status(502).json({
          error:
            "DeepSeek did not preserve the original vocabulary words",
        });
      }

      for (
        const item of result.words
      ) {
        if (
          !Array.isArray(
            item.examples
          ) ||
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
  }
);

/*
|--------------------------------------------------------------------------
| Reset password page
|--------------------------------------------------------------------------
|
| The frontend handles the actual reset-password UI.
| This route simply serves the SPA entry point.
|
*/

app.get(
  "/reset-password",
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );
  }
);

/*
|--------------------------------------------------------------------------
| Static website
|--------------------------------------------------------------------------
*/

app.use(
  express.static(
    path.join(
      __dirname,
      "public"
    )
  )
);

/*
|--------------------------------------------------------------------------
| Start server
|--------------------------------------------------------------------------
*/

initDB()
  .then(() => {
    app.listen(
      PORT,
      () => {
        console.log(
          `Server running on port ${PORT}`
        );
      }
    );
  })
  .catch((error) => {
    console.error(
      "Database initialization failed:",
      error
    );

    process.exit(1);
  });
