const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const session = require("express-session");
const pg = require("pg");
const connectPgSimple = require("connect-pg-simple");

const { Pool } = pg;
const PgSession = connectPgSimple(session);

const app = express();
const PORT = process.env.PORT || 3000;

/* =========================================================
   Configuration
========================================================= */

const DATABASE_URL = process.env.DATABASE_URL || "";
const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  crypto.randomBytes(32).toString("hex");

const APP_URL = (process.env.APP_URL || "").replace(/\/+$/, "");

const CODE_TTL_MINUTES = 10;
const RESET_TTL_MINUTES = 30;

const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl:
        process.env.NODE_ENV === "production"
          ? { rejectUnauthorized: false }
          : undefined,
    })
  : null;

/* =========================================================
   Express
========================================================= */

app.use(express.json({ limit: "500kb" }));

/* =========================================================
   Session
========================================================= */

if (pool) {
  app.use(
    session({
      store: new PgSession({
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
  /*
    Local development fallback.

    Authentication/data sync requires PostgreSQL,
    but this allows the website itself to run locally.
  */

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

/* =========================================================
   Database helpers
========================================================= */

function databaseRequired(res) {
  if (!pool) {
    res.status(503).json({
      error:
        "Database is not configured. Please add DATABASE_URL in Railway.",
    });

    return false;
  }

  return true;
}

async function initializeDatabase() {
  if (!pool) {
    console.warn(
      "DATABASE_URL is not configured. Database features are disabled."
    );

    return;
  }

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
      user_id UUID NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      token_hash TEXT NOT NULL UNIQUE,

      expires_at TIMESTAMPTZ NOT NULL,

      used_at TIMESTAMPTZ,

      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS password_reset_lookup
      ON password_reset_tokens(token_hash, expires_at);

    CREATE TABLE IF NOT EXISTS user_data (
      user_id UUID PRIMARY KEY
        REFERENCES users(id)
        ON DELETE CASCADE,

      cabinet JSONB NOT NULL DEFAULT '[]'::jsonb,

      global_stats JSONB NOT NULL DEFAULT '{}'::jsonb,

      current_state JSONB,

      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  console.log("Database initialized.");
}

/* =========================================================
   Email
========================================================= */

const mailer =
  process.env.SMTP_HOST &&
  process.env.SMTP_USER &&
  process.env.SMTP_PASS
    ? nodemailer.createTransport({
        host: process.env.SMTP_HOST,

        port: Number(process.env.SMTP_PORT || 587),

        secure:
          String(process.env.SMTP_SECURE || "false") === "true",

        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS,
        },
      })
    : null;

async function sendMail(to, subject, text, html) {
  /*
    Development mode:
    print the email contents to Railway/local console.
  */

  if (!mailer) {
    if (process.env.NODE_ENV !== "production") {
      console.log("");
      console.log("========== DEV EMAIL ==========");
      console.log("TO:", to);
      console.log("SUBJECT:", subject);
      console.log(text);
      console.log("================================");
      console.log("");

      return;
    }

    throw new Error("SMTP email service is not configured.");
  }

  await mailer.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,

    to,

    subject,

    text,

    html,
  });
}

/* =========================================================
   Security helpers
========================================================= */

function normalizeEmail(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function hashValue(value) {
  return crypto
    .createHash("sha256")
    .update(String(value))
    .digest("hex");
}

function generateCode() {
  return String(
    crypto.randomInt(0, 1000000)
  ).padStart(6, "0");
}

function generateResetToken() {
  return crypto
    .randomBytes(32)
    .toString("hex");
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/* =========================================================
   Email verification codes
========================================================= */

async function issueEmailCode(email, purpose) {
  /*
    Prevent repeated requests within 60 seconds.
  */

  const recent = await pool.query(
    `
      SELECT created_at
      FROM email_codes
      WHERE email = $1
        AND purpose = $2
        AND created_at >
            NOW() - INTERVAL '60 seconds'
      ORDER BY created_at DESC
      LIMIT 1
    `,
    [email, purpose]
  );

  if (recent.rowCount) {
    throw new Error(
      "Please wait a minute before requesting another code."
    );
  }

  const code = generateCode();

  /*
    Invalidate older unused codes.
  */

  await pool.query(
    `
      UPDATE email_codes
      SET consumed_at = NOW()
      WHERE email = $1
        AND purpose = $2
        AND consumed_at IS NULL
    `,
    [email, purpose]
  );

  await pool.query(
    `
      INSERT INTO email_codes
        (email, purpose, code_hash, expires_at)
      VALUES
        (
          $1,
          $2,
          $3,
          NOW() + INTERVAL '10 minutes'
        )
    `,
    [email, purpose, hashValue(code)]
  );

  let subject;
  let text;

  if (purpose === "register") {
    subject = "The Lexicon — verify your email";

    text =
      `Your The Lexicon verification code is ${code}.\n\n` +
      `This code expires in ${CODE_TTL_MINUTES} minutes.`;
  } else {
    subject = "The Lexicon — your login code";

    text =
      `Your The Lexicon login code is ${code}.\n\n` +
      `This code expires in ${CODE_TTL_MINUTES} minutes.`;
  }

  const html = `
    <div style="font-family:Arial,sans-serif">
      <p>Your The Lexicon code is:</p>

      <p
        style="
          font-size:32px;
          letter-spacing:8px;
          font-weight:bold;
        "
      >
        ${code}
      </p>

      <p>
        This code expires in
        ${CODE_TTL_MINUTES} minutes.
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

async function verifyEmailCode(
  email,
  purpose,
  code
) {
  const result = await pool.query(
    `
      SELECT id
      FROM email_codes
      WHERE email = $1
        AND purpose = $2
        AND code_hash = $3
        AND consumed_at IS NULL
        AND expires_at > NOW()
      ORDER BY created_at DESC
      LIMIT 1
    `,
    [
      email,
      purpose,
      hashValue(code),
    ]
  );

  if (!result.rowCount) {
    return false;
  }

  await pool.query(
    `
      UPDATE email_codes
      SET consumed_at = NOW()
      WHERE id = $1
    `,
    [result.rows[0].id]
  );

  return true;
}

/* =========================================================
   Session helpers
========================================================= */

function setRememberDevice(req, remember) {
  /*
    "Yes":
    persistent login for 30 days.

    "No":
    session cookie disappears when browser session ends.
  */

  req.session.cookie.maxAge = remember
    ? 1000 * 60 * 60 * 24 * 30
    : null;
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save((error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}

function destroySession(req) {
  return new Promise((resolve, reject) => {
    req.session.destroy((error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}

function publicUser(user) {
  return {
    id: user.id,

    email: user.email,

    emailVerified: Boolean(
      user.email_verified
    ),
  };
}

async function loginUser(
  req,
  user,
  remember
) {
  req.session.userId = user.id;

  delete req.session.registerVerifiedEmail;

  setRememberDevice(
    req,
    Boolean(remember)
  );

  await saveSession(req);
}

/* =========================================================
   Health
========================================================= */

app.get("/api/health", async (req, res) => {
  let database = false;

  if (pool) {
    try {
      await pool.query("SELECT 1");
      database = true;
    } catch (error) {
      console.error(
        "Database health check failed:",
        error.message
      );
    }
  }

  res.json({
    ok: true,

    database,

    message:
      "English Word Lab server is running!",
  });
});

/* =========================================================
   Current user
========================================================= */

app.get("/api/auth/me", async (req, res) => {
  if (!pool) {
    return res.json({
      user: null,
    });
  }

  if (!req.session.userId) {
    return res.json({
      user: null,
    });
  }

  try {
    const result = await pool.query(
      `
        SELECT id, email, email_verified
        FROM users
        WHERE id = $1
        LIMIT 1
      `,
      [req.session.userId]
    );

    if (!result.rowCount) {
      delete req.session.userId;

      await saveSession(req);

      return res.json({
        user: null,
      });
    }

    return res.json({
      user: publicUser(
        result.rows[0]
      ),
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      error: "Unable to load account.",
    });
  }
});

/* =========================================================
   Register — request verification code
========================================================= */

app.post(
  "/api/auth/register/request-code",
  async (req, res) => {
    if (!databaseRequired(res)) {
      return;
    }

    try {
      const email = normalizeEmail(
        req.body.email
      );

      if (!validEmail(email)) {
        return res.status(400).json({
          error:
            "Please enter a valid email address.",
        });
      }

      const existing = await pool.query(
        `
          SELECT id, email_verified
          FROM users
          WHERE email = $1
        `,
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
      console.error(error);

      res.status(400).json({
        error:
          error.message ||
          "Unable to send verification code.",
      });
    }
  }
);

/* =========================================================
   Register — verify email
========================================================= */

app.post(
  "/api/auth/register/verify",
  async (req, res) => {
    if (!databaseRequired(res)) {
      return;
    }

    try {
      const email = normalizeEmail(
        req.body.email
      );

      const code = String(
        req.body.code || ""
      ).trim();

      if (!validEmail(email)) {
        return res.status(400).json({
          error:
            "Please enter a valid email address.",
        });
      }

      if (!/^\d{6}$/.test(code)) {
        return res.status(400).json({
          error:
            "Please enter the 6-digit verification code.",
        });
      }

      const valid =
        await verifyEmailCode(
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

      await saveSession(req);

      res.json({
        ok: true,
      });
    } catch (error) {
      console.error(error);

      res.status(400).json({
        error:
          "Unable to verify this email.",
      });
    }
  }
);

/* =========================================================
   Register — create account
========================================================= */

app.post(
  "/api/auth/register",
  async (req, res) => {
    if (!databaseRequired(res)) {
      return;
    }

    try {
      const email = normalizeEmail(
        req.body.email
      );

      const password = String(
        req.body.password || ""
      );

      const remember =
        Boolean(req.body.remember);

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
        `
          SELECT id, email_verified
          FROM users
          WHERE email = $1
        `,
        [email]
      );

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      let user;

      await pool.query("BEGIN");

      try {
        if (existing.rowCount) {
          /*
            This means the email had been verified
            but the account was not completed.
          */

          if (
            existing.rows[0]
              .email_verified
          ) {
            throw new Error(
              "An account with this email already exists."
            );
          }

          await pool.query(
            `
              UPDATE users
              SET
                password_hash = $1,
                email_verified = TRUE,
                updated_at = NOW()
              WHERE id = $2
            `,
            [
              passwordHash,
              existing.rows[0].id,
            ]
          );

          const result =
            await pool.query(
              `
                SELECT *
                FROM users
                WHERE id = $1
              `,
              [existing.rows[0].id]
            );

          user = result.rows[0];
        } else {
          const id =
            crypto.randomUUID();

          await pool.query(
            `
              INSERT INTO users
                (
                  id,
                  email,
                  password_hash,
                  email_verified
                )
              VALUES
                ($1, $2, $3, TRUE)
            `,
            [
              id,
              email,
              passwordHash,
            ]
          );

          const result =
            await pool.query(
              `
                SELECT *
                FROM users
                WHERE id = $1
              `,
              [id]
            );

          user = result.rows[0];
        }

        await pool.query(
          `
            INSERT INTO user_data
              (
                user_id,
                cabinet,
                global_stats,
                current_state
              )
            VALUES
              (
                $1,
                '[]'::jsonb,
                '{}'::jsonb,
                NULL
              )
            ON CONFLICT(user_id)
            DO NOTHING
          `,
          [user.id]
        );

        await pool.query("COMMIT");
      } catch (error) {
        await pool.query("ROLLBACK");
        throw error;
      }

      await loginUser(
        req,
        user,
        remember
      );

      res.json({
        user: publicUser(user),
      });
    } catch (error) {
      console.error(error);

      res.status(400).json({
        error:
          error.message ||
          "Unable to create account.",
      });
    }
  }
);

/* =========================================================
   Login — password
========================================================= */

app.post(
  "/api/auth/login/password",
  async (req, res) => {
    if (!databaseRequired(res)) {
      return;
    }

    try {
      const email = normalizeEmail(
        req.body.email
      );

      const password = String(
        req.body.password || ""
      );

      const remember =
        Boolean(req.body.remember);

      const result = await pool.query(
        `
          SELECT *
          FROM users
          WHERE email = $1
          LIMIT 1
        `,
        [email]
      );

      if (!result.rowCount) {
        return res.status(401).json({
          error:
            "Incorrect email or password.",
        });
      }

      const user = result.rows[0];

      if (!user.email_verified) {
        return res.status(403).json({
          error:
            "Please verify your email before logging in.",
        });
      }

      const valid =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!valid) {
        return res.status(401).json({
          error:
            "Incorrect email or password.",
        });
      }

      await loginUser(
        req,
        user,
        remember
      );

      res.json({
        user: publicUser(user),
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Unable to log in.",
      });
    }
  }
);

/* =========================================================
   Login — request email code
========================================================= */

app.post(
  "/api/auth/login/request-code",
  async (req, res) => {
    if (!databaseRequired(res)) {
      return;
    }

    try {
      const email = normalizeEmail(
        req.body.email
      );

      if (!validEmail(email)) {
        return res.status(400).json({
          error:
            "Please enter a valid email address.",
        });
      }

      const result = await pool.query(
        `
          SELECT id, email_verified
          FROM users
          WHERE email = $1
          LIMIT 1
        `,
        [email]
      );

      /*
        Don't reveal whether an account exists.
      */

      if (
        !result.rowCount ||
        !result.rows[0].email_verified
      ) {
        return res.json({
          ok: true,
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
  }
);

/* =========================================================
   Login — email code
========================================================= */

app.post(
  "/api/auth/login/code",
  async (req, res) => {
    if (!databaseRequired(res)) {
      return;
    }

    try {
      const email = normalizeEmail(
        req.body.email
      );

      const code = String(
        req.body.code || ""
      ).trim();

      const remember =
        Boolean(req.body.remember);

      if (!/^\d{6}$/.test(code)) {
        return res.status(400).json({
          error:
            "Please enter the 6-digit code.",
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

      const result = await pool.query(
        `
          SELECT *
          FROM users
          WHERE email = $1
          AND email_verified = TRUE
          LIMIT 1
        `,
        [email]
      );

      if (!result.rowCount) {
        return res.status(401).json({
          error:
            "Unable to log in with this code.",
        });
      }

      const user = result.rows[0];

      await loginUser(
        req,
        user,
        remember
      );

      res.json({
        user: publicUser(user),
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Unable to log in.",
      });
    }
  }
);

/* =========================================================
   Password reset — request reset link
========================================================= */

app.post(
  "/api/auth/password-reset/request",
  async (req, res) => {
    if (!databaseRequired(res)) {
      return;
    }

    const genericMessage =
      "If an account exists for this email, a password reset link has been sent.";

    try {
      const email = normalizeEmail(
        req.body.email
      );

      const result = await pool.query(
        `
          SELECT *
          FROM users
          WHERE email = $1
          AND email_verified = TRUE
          LIMIT 1
        `,
        [email]
      );

      /*
        Always return the same response
        so people cannot discover registered emails.
      */

      if (!result.rowCount) {
        return res.json({
          ok: true,
          message: genericMessage,
        });
      }

      const user = result.rows[0];

      /*
        Invalidate old reset tokens.
      */

      await pool.query(
        `
          UPDATE password_reset_tokens
          SET used_at = NOW()
          WHERE user_id = $1
          AND used_at IS NULL
        `,
        [user.id]
      );

      const rawToken =
        generateResetToken();

      await pool.query(
        `
          INSERT INTO password_reset_tokens
            (
              user_id,
              token_hash,
              expires_at
            )
          VALUES
            (
              $1,
              $2,
              NOW() + INTERVAL '30 minutes'
            )
        `,
        [
          user.id,
          hashValue(rawToken),
        ]
      );

      const base =
        APP_URL ||
        `${req.protocol}://${req.get("host")}`;

      const resetLink =
        `${base}/reset-password?reset=` +
        encodeURIComponent(rawToken);

      await sendMail(
        email,

        "The Lexicon — reset your password",

        `
Use this link to reset your The Lexicon password.

${resetLink}

This link expires in ${RESET_TTL_MINUTES} minutes.
        `.trim(),

        `
          <div style="font-family:Arial,sans-serif">
            <p>
              Someone requested a password reset
              for your The Lexicon account.
            </p>

            <p>
              <a
                href="${resetLink}"
                style="
                  display:inline-block;
                  padding:12px 20px;
                  background:#76353d;
                  color:white;
                  text-decoration:none;
                "
              >
                Reset your password
              </a>
            </p>

            <p>
              This link expires in
              ${RESET_TTL_MINUTES} minutes.
            </p>

            <p>
              If you did not request this,
              you can safely ignore this email.
            </p>
          </div>
        `
      );

      res.json({
        ok: true,
        message: genericMessage,
      });
    } catch (error) {
      console.error(error);

      /*
        Don't reveal internal errors or
        whether the email exists.
      */

      res.json({
        ok: true,
        message: genericMessage,
      });
    }
  }
);

/* =========================================================
   Password reset — complete
========================================================= */

app.post(
  "/api/auth/password-reset/complete",
  async (req, res) => {
    if (!databaseRequired(res)) {
      return;
    }

    try {
      const token = String(
        req.body.token || ""
      );

      const password = String(
        req.body.password || ""
      );

      const remember =
        Boolean(req.body.remember);

      if (!token) {
        return res.status(400).json({
          error:
            "Invalid or missing reset token.",
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          error:
            "Password must be at least 8 characters.",
        });
      }

      const result = await pool.query(
        `
          SELECT
            u.*,
            prt.id AS reset_id
          FROM password_reset_tokens prt
          JOIN users u
            ON u.id = prt.user_id
          WHERE
            prt.token_hash = $1
            AND prt.used_at IS NULL
            AND prt.expires_at > NOW()
          LIMIT 1
        `,
        [hashValue(token)]
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

      await pool.query("BEGIN");

      try {
        await pool.query(
          `
            UPDATE users
            SET
              password_hash = $1,
              updated_at = NOW()
            WHERE id = $2
          `,
          [
            passwordHash,
            user.id,
          ]
        );

        await pool.query(
          `
            UPDATE password_reset_tokens
            SET used_at = NOW()
            WHERE id = $1
          `,
          [user.reset_id]
        );

        /*
          Invalidate all other reset tokens.
        */

        await pool.query(
          `
            UPDATE password_reset_tokens
            SET used_at = NOW()
            WHERE
              user_id = $1
              AND used_at IS NULL
          `,
          [user.id]
        );

        await pool.query("COMMIT");
      } catch (error) {
        await pool.query("ROLLBACK");
        throw error;
      }

      await loginUser(
        req,
        user,
        remember
      );

      res.json({
        user: publicUser(user),
      });
    } catch (error) {
      console.error(error);

      res.status(400).json({
        error:
          "Unable to reset the password.",
      });
    }
  }
);

/* =========================================================
   Logout
========================================================= */

app.post(
  "/api/auth/logout",
  async (req, res) => {
    try {
      await destroySession(req);

      res.clearCookie("connect.sid");

      res.json({
        ok: true,
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Unable to log out.",
      });
    }
  }
);

/* =========================================================
   User data — download
========================================================= */

app.get(
  "/api/data",
  async (req, res) => {
    if (!databaseRequired(res)) {
      return;
    }

    if (!req.session.userId) {
      return res.status(401).json({
        error: "Not logged in.",
      });
    }

    try {
      const result = await pool.query(
        `
          SELECT
            cabinet,
            global_stats,
            current_state
          FROM user_data
          WHERE user_id = $1
          LIMIT 1
        `,
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

        globalStats:
          row.global_stats,

        currentState:
          row.current_state,
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Unable to load your data.",
      });
    }
  }
);

/* =========================================================
   User data — upload/save
========================================================= */

app.put(
  "/api/data",
  async (req, res) => {
    if (!databaseRequired(res)) {
      return;
    }

    if (!req.session.userId) {
      return res.status(401).json({
        error: "Not logged in.",
      });
    }

    try {
      const cabinet =
        Array.isArray(req.body.cabinet)
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
        `
          INSERT INTO user_data
            (
              user_id,
              cabinet,
              global_stats,
              current_state,
              updated_at
            )
          VALUES
            (
              $1,
              $2::jsonb,
              $3::jsonb,
              $4::jsonb,
              NOW()
            )

          ON CONFLICT(user_id)
          DO UPDATE SET
            cabinet =
              EXCLUDED.cabinet,

            global_stats =
              EXCLUDED.global_stats,

            current_state =
              EXCLUDED.current_state,

            updated_at =
              NOW()
        `,
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
          "Unable to save your data.",
      });
    }
  }
);

/* =========================================================
   DeepSeek vocabulary generation
========================================================= */

app.post(
  "/api/generate",
  async (req, res) => {
    try {
      const { words } = req.body;

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

      const cleanedWords = words
        .map((word) =>
          String(word).trim()
        )
        .filter(Boolean);

      if (!cleanedWords.length) {
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

NEVER split, segment, decompose,
shorten, or reinterpret an input word.

The number of vocabulary entries MUST
match the number of valid input words.

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
      "synonyms": [
        "word1",
        "word2",
        "word3"
      ],
      "antonyms": [
        "word1",
        "word2"
      ],
      "root": "A concise explanation of the word origin or root.",
      "cognates": [
        "word1",
        "word2"
      ]
    }
  ]
}

Rules:

1. Keep the original word spelling exactly as provided.
2. Never split one input word into multiple words.
3. Create exactly one entry for each input word.
4. The number of entries must match the input.
5. Definitions must be clear and concise.
6. Generate exactly three example sentences.
7. Examples must be natural and grammatically correct.
8. Examples should demonstrate meaningful usage.
9. Avoid repetitive examples.
10. Provide useful synonyms when possible.
11. Provide useful antonyms when possible.
12. Explain root or etymology briefly when possible.
13. Provide useful cognates when possible.
14. Use empty arrays or strings when appropriate.
15. Do not add extra fields.
16. Return JSON only.
`;

      const userPrompt = `
Generate the vocabulary library
for these words:

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

      for (
        let i = 0;
        i < expectedWords.length;
        i++
      ) {
        if (
          returnedWords[i] !==
          expectedWords[i]
        ) {
          return res.status(502).json({
            error:
              "DeepSeek did not preserve the original vocabulary words",
          });
        }
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
        "DeepSeek server error:",
        error
      );

      res.status(500).json({
        error:
          "Internal server error",
      });
    }
  }
);

/* =========================================================
   Password reset page
========================================================= */

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

/* =========================================================
   Static website
========================================================= */

app.use(
  express.static(
    path.join(
      __dirname,
      "public"
    )
  )
);

/* =========================================================
   Start
========================================================= */

async function startServer() {
  try {
    await initializeDatabase();

    app.listen(
      PORT,
      () => {
        console.log(
          `Server running on port ${PORT}`
        );
      }
    );
  } catch (error) {
    console.error(
      "Failed to initialize server:",
      error
    );

    process.exit(1);
  }
}

startServer();
