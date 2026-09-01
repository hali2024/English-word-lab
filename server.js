const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const { Pool } = require('pg');
const pgSession = require('connect-pg-simple')(session);

const app = express();

app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL || '';

const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl:
        DATABASE_URL.includes('railway') ||
        process.env.NODE_ENV === 'production'
          ? { rejectUnauthorized: false }
          : undefined
    })
  : null;

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  crypto.randomBytes(32).toString('hex');

const APP_URL = (process.env.APP_URL || '').replace(/\/+$/, '');

const CODE_TTL = 10;
const RESET_TTL = 30;
const REGISTER_TTL = 15;


// ============================================================
// Middleware
// ============================================================

app.use(express.json({ limit: '500kb' }));

const secureCookie =
  process.env.NODE_ENV === 'production' ||
  !!process.env.RAILWAY_ENVIRONMENT_NAME;

const sessionOptions = {
  name: 'lexicon.sid',

  secret: SESSION_SECRET,

  resave: false,

  saveUninitialized: false,

  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: secureCookie,
    path: '/',
    maxAge: null
  }
};

if (pool) {
  sessionOptions.store = new pgSession({
    pool,
    tableName: 'user_sessions',
    createTableIfMissing: true
  });
}

app.use(session(sessionOptions));


// API responses must never be cached.
// This is especially important for login/session checks on mobile browsers.

app.use('/api/auth', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

app.use('/api/data', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});


// ============================================================
// Utility
// ============================================================

function requireDB(res) {
  if (!pool) {
    res.status(503).json({
      error:
        'Database is not configured. Add DATABASE_URL in Railway.'
    });

    return false;
  }

  return true;
}


function emailOf(value) {
  return String(value || '')
    .trim()
    .toLowerCase();
}


function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}


function hash(value) {
  return crypto
    .createHash('sha256')
    .update(String(value))
    .digest('hex');
}


function code() {
  return String(
    crypto.randomInt(0, 1000000)
  ).padStart(6, '0');
}


function userPublic(user) {
  return {
    id: user.id,
    email: user.email,
    emailVerified: !!user.email_verified
  };
}


function remember(req, yes) {
  req.session.cookie.maxAge = yes
    ? 30 * 24 * 60 * 60 * 1000
    : null;
}


function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save(error => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}


async function loginSession(
  req,
  user,
  rememberDevice
) {
  req.session.userId = user.id;
  req.session.userEmail = user.email;

  delete req.session.registerEmail;
  delete req.session.registerVerifiedEmail;

  remember(req, rememberDevice);

  await saveSession(req);
}


// ============================================================
// Database initialization
// ============================================================

async function initDB() {
  if (!pool) {
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

      cabinet JSONB NOT NULL
        DEFAULT '[]'::jsonb,

      global_stats JSONB NOT NULL
        DEFAULT '{}'::jsonb,

      current_state JSONB,

      updated_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW()
    );

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
// Resend
// ============================================================

async function sendMail(
  to,
  subject,
  text,
  html
) {
  const apiKey =
    process.env.RESEND_API_KEY;

  const from =
    process.env.RESEND_FROM;

  if (!apiKey || !from) {
    throw new Error(
      'Email service is not configured.'
    );
  }

  const response = await fetch(
    'https://api.resend.com/emails',
    {
      method: 'POST',

      headers: {
        Authorization:
          `Bearer ${apiKey}`,

        'Content-Type':
          'application/json'
      },

      body: JSON.stringify({
        from,
        to,
        subject,
        text,
        html
      })
    }
  );

  if (!response.ok) {
    const errorText =
      await response.text();

    console.error(
      'Resend API error:',
      errorText
    );

    throw new Error(
      'Unable to send email.'
    );
  }

  return response.json();
}


// ============================================================
// Email verification codes
// ============================================================

async function issueCode(
  email,
  purpose
) {
  const recent =
    await pool.query(
      `
      SELECT 1
      FROM email_codes
      WHERE email=$1
        AND purpose=$2
        AND created_at >
          NOW() - INTERVAL '60 seconds'
      LIMIT 1
      `,
      [email, purpose]
    );

  if (recent.rowCount) {
    throw new Error(
      'Please wait a minute before requesting another code.'
    );
  }

  const verificationCode =
    code();

  await pool.query(
    `
    UPDATE email_codes
    SET consumed_at=NOW()
    WHERE email=$1
      AND purpose=$2
      AND consumed_at IS NULL
    `,
    [email, purpose]
  );

  await pool.query(
    `
    INSERT INTO email_codes(
      email,
      purpose,
      code_hash,
      expires_at
    )
    VALUES(
      $1,
      $2,
      $3,
      NOW() + INTERVAL '${CODE_TTL} minutes'
    )
    `,
    [
      email,
      purpose,
      hash(verificationCode)
    ]
  );

  const register =
    purpose === 'register';

  const subject =
    register
      ? 'The Lexicon — verify your email'
      : 'The Lexicon — your login code';

  const text =
    `Your The Lexicon ${
      register
        ? 'verification'
        : 'login'
    } code is ${verificationCode}. ` +
    `It expires in ${CODE_TTL} minutes.`;

  const html = `
    <div style="font-family:Arial,sans-serif">
      <p>
        Your The Lexicon
        ${register ? 'verification' : 'login'}
        code is:
      </p>

      <p style="font-size:32px;letter-spacing:8px">
        <strong>${verificationCode}</strong>
      </p>

      <p>
        This code expires in
        ${CODE_TTL} minutes.
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


async function verifyCode(
  email,
  purpose,
  verificationCode
) {
  const result =
    await pool.query(
      `
      SELECT id
      FROM email_codes
      WHERE email=$1
        AND purpose=$2
        AND code_hash=$3
        AND consumed_at IS NULL
        AND expires_at > NOW()
      ORDER BY created_at DESC
      LIMIT 1
      `,
      [
        email,
        purpose,
        hash(verificationCode)
      ]
    );

  if (!result.rowCount) {
    return false;
  }

  await pool.query(
    `
    UPDATE email_codes
    SET consumed_at=NOW()
    WHERE id=$1
    `,
    [result.rows[0].id]
  );

  return true;
}


// ============================================================
// Registration verification state
// ============================================================

async function markVerified(email) {
  await pool.query(
    `
    INSERT INTO register_verifications(
      email,
      verified_at,
      expires_at
    )
    VALUES(
      $1,
      NOW(),
      NOW() +
        INTERVAL '${REGISTER_TTL} minutes'
    )

    ON CONFLICT(email)

    DO UPDATE SET
      verified_at=NOW(),
      expires_at=
        NOW() +
        INTERVAL '${REGISTER_TTL} minutes'
    `,
    [email]
  );
}


async function isVerifiedForRegistration(
  email
) {
  const result =
    await pool.query(
      `
      SELECT 1
      FROM register_verifications
      WHERE email=$1
        AND expires_at > NOW()
      LIMIT 1
      `,
      [email]
    );

  return !!result.rowCount;
}


// ============================================================
// Health
// ============================================================

app.get(
  '/api/health',
  async (req, res) => {
    let database = false;

    if (pool) {
      try {
        await pool.query(
          'SELECT 1'
        );

        database = true;
      } catch (_) {}
    }

    res.json({
      ok: true,
      database,
      message:
        'English Word Lab server is running!'
    });
  }
);


// ============================================================
// REGISTER — REQUEST CODE
// ============================================================

app.post(
  '/api/auth/register/request-code',
  async (req, res) => {
    if (!requireDB(res)) {
      return;
    }

    try {
      const email =
        emailOf(req.body.email);

      if (!validEmail(email)) {
        return res.status(400).json({
          error:
            'Please enter a valid email address.'
        });
      }

      const existing =
        await pool.query(
          `
          SELECT email_verified
          FROM users
          WHERE email=$1
          `,
          [email]
        );

      if (
        existing.rowCount &&
        existing.rows[0].email_verified
      ) {
        return res.status(409).json({
          error:
            'An account with this email already exists. Please log in.'
        });
      }

      await pool.query(
        `
        DELETE FROM register_verifications
        WHERE email=$1
        `,
        [email]
      );

      await issueCode(
        email,
        'register'
      );

      req.session.registerEmail =
        email;

      await saveSession(req);

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(error);

      res.status(400).json({
        error:
          error.message ||
          'Unable to send verification code.'
      });
    }
  }
);


// ============================================================
// REGISTER — VERIFY CODE
// ============================================================

app.post(
  '/api/auth/register/verify',
  async (req, res) => {
    if (!requireDB(res)) {
      return;
    }

    try {
      const email =
        emailOf(req.body.email);

      const verificationCode =
        String(
          req.body.code || ''
        ).trim();

      if (!validEmail(email)) {
        return res.status(400).json({
          error:
            'Please enter a valid email address.'
        });
      }

      if (
        !/^\d{6}$/.test(
          verificationCode
        )
      ) {
        return res.status(400).json({
          error:
            'Enter the 6-digit code.'
        });
      }

      const valid =
        await verifyCode(
          email,
          'register',
          verificationCode
        );

      if (!valid) {
        return res.status(400).json({
          error:
            'That code is invalid or has expired.'
        });
      }

      await markVerified(email);

      req.session.registerEmail =
        email;

      req.session.registerVerifiedEmail =
        email;

      await saveSession(req);

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          'Unable to verify the email address.'
      });
    }
  }
);


// ============================================================
// REGISTER — CREATE ACCOUNT
// ============================================================

app.post(
  '/api/auth/register',
  async (req, res) => {
    if (!requireDB(res)) {
      return;
    }

    const client =
      await pool.connect();

    try {
      const email =
        emailOf(req.body.email);

      const password =
        String(
          req.body.password || ''
        );

      if (!validEmail(email)) {
        return res.status(400).json({
          error:
            'Please enter a valid email address.'
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          error:
            'Password must be at least 8 characters.'
        });
      }

      /*
       * IMPORTANT:
       *
       * Email verification is stored
       * in PostgreSQL rather than relying
       * only on the browser session.
       *
       * This prevents the old bug where:
       *
       * Verify email
       *      ↓
       * Enter password
       *      ↓
       * Create account
       *      ↓
       * "Please verify your email"
       *
       * could appear again.
       */

      const verified =
        await isVerifiedForRegistration(
          email
        );

      if (!verified) {
        return res.status(400).json({
          error:
            'Please verify your email first. The verification may have expired; please request a new code.'
        });
      }

      const existing =
        await pool.query(
          `
          SELECT id,email_verified
          FROM users
          WHERE email=$1
          `,
          [email]
        );

      if (
        existing.rowCount &&
        existing.rows[0].email_verified
      ) {
        return res.status(409).json({
          error:
            'An account with this email already exists. Please log in.'
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const userId =
        crypto.randomUUID();

      await client.query(
        'BEGIN'
      );

      await client.query(
        `
        INSERT INTO users(
          id,
          email,
          password_hash,
          email_verified,
          created_at,
          updated_at
        )
        VALUES(
          $1,
          $2,
          $3,
          TRUE,
          NOW(),
          NOW()
        )

        ON CONFLICT(email)

        DO UPDATE SET
          password_hash=
            EXCLUDED.password_hash,
          email_verified=TRUE,
          updated_at=NOW()
        `,
        [
          userId,
          email,
          passwordHash
        ]
      );

      const userResult =
        await client.query(
          `
          SELECT *
          FROM users
          WHERE email=$1
          `,
          [email]
        );

      const user =
        userResult.rows[0];

      await client.query(
        `
        INSERT INTO user_data(
          user_id,
          cabinet,
          global_stats,
          current_state,
          updated_at
        )
        VALUES(
          $1,
          '[]'::jsonb,
          '{}'::jsonb,
          NULL,
          NOW()
        )

        ON CONFLICT(user_id)
        DO NOTHING
        `,
        [user.id]
      );

      await client.query(
        `
        DELETE FROM register_verifications
        WHERE email=$1
        `,
        [email]
      );

      await client.query(
        'COMMIT'
      );

      await loginSession(
        req,
        user,
        false
      );

      res.json({
        user:
          userPublic(user)
      });
    } catch (error) {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch (_) {}

      console.error(error);

      res.status(500).json({
        error:
          'Unable to create the account.'
      });
    } finally {
      client.release();
    }
  }
);


// ============================================================
// LOGIN — PASSWORD
// ============================================================

app.post(
  '/api/auth/login/password',
  async (req, res) => {
    if (!requireDB(res)) {
      return;
    }

    try {
      const email =
        emailOf(req.body.email);

      const password =
        String(
          req.body.password || ''
        );

      if (!validEmail(email)) {
        return res.status(400).json({
          error:
            'Please enter a valid email address.'
        });
      }

      const result =
        await pool.query(
          `
          SELECT *
          FROM users
          WHERE email=$1
            AND email_verified=TRUE
          `,
          [email]
        );

      if (!result.rowCount) {
        return res.status(401).json({
          error:
            'Incorrect email or password.'
        });
      }

      const user =
        result.rows[0];

      const valid =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!valid) {
        return res.status(401).json({
          error:
            'Incorrect email or password.'
        });
      }

      await loginSession(
        req,
        user,
        !!req.body.remember
      );

      res.json({
        user:
          userPublic(user)
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          'Unable to log in.'
      });
    }
  }
);


// ============================================================
// LOGIN — REQUEST EMAIL CODE
// ============================================================

app.post(
  '/api/auth/login/request-code',
  async (req, res) => {
    if (!requireDB(res)) {
      return;
    }

    try {
      const email =
        emailOf(req.body.email);

      if (!validEmail(email)) {
        return res.status(400).json({
          error:
            'Please enter a valid email address.'
        });
      }

      const result =
        await pool.query(
          `
          SELECT email_verified
          FROM users
          WHERE email=$1
          `,
          [email]
        );

      if (
        !result.rowCount ||
        !result.rows[0].email_verified
      ) {
        return res.status(400).json({
          error:
            'No verified account was found for that email.'
        });
      }

      await issueCode(
        email,
        'login'
      );

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(error);

      res.status(400).json({
        error:
          error.message ||
          'Unable to send login code.'
      });
    }
  }
);


// ============================================================
// LOGIN — EMAIL CODE
// ============================================================

app.post(
  '/api/auth/login/code',
  async (req, res) => {
    if (!requireDB(res)) {
      return;
    }

    try {
      const email =
        emailOf(req.body.email);

      const verificationCode =
        String(
          req.body.code || ''
        ).trim();

      if (!validEmail(email)) {
        return res.status(400).json({
          error:
            'Please enter a valid email address.'
        });
      }

      if (
        !/^\d{6}$/.test(
          verificationCode
        )
      ) {
        return res.status(400).json({
          error:
            'Enter the 6-digit code.'
        });
      }

      const result =
        await pool.query(
          `
          SELECT *
          FROM users
          WHERE email=$1
            AND email_verified=TRUE
          `,
          [email]
        );

      if (!result.rowCount) {
        return res.status(401).json({
          error:
            'Unable to verify that account.'
        });
      }

      const valid =
        await verifyCode(
          email,
          'login',
          verificationCode
        );

      if (!valid) {
        return res.status(401).json({
          error:
            'That code is invalid or has expired.'
        });
      }

      await loginSession(
        req,
        result.rows[0],
        !!req.body.remember
      );

      res.json({
        user:
          userPublic(
            result.rows[0]
          )
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          'Unable to log in with email code.'
      });
    }
  }
);


// ============================================================
// REMEMBER THIS DEVICE
// ============================================================

app.post(
  '/api/auth/session-preference',
  async (req, res) => {
    if (!req.session.userId) {
      return res.status(401).json({
        error:
          'Not logged in.'
      });
    }

    try {
      remember(
        req,
        !!req.body.remember
      );

      await saveSession(req);

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          'Unable to update session.'
      });
    }
  }
);


// ============================================================
// CURRENT USER
// ============================================================

app.get(
  '/api/auth/me',
  async (req, res) => {
    if (!requireDB(res)) {
      return;
    }

    if (!req.session.userId) {
      return res.status(401).json({
        error:
          'Not logged in.'
      });
    }

    try {
      const result =
        await pool.query(
          `
          SELECT *
          FROM users
          WHERE id=$1
          `,
          [req.session.userId]
        );

      if (!result.rowCount) {
        req.session.destroy(
          () => {}
        );

        return res.status(401).json({
          error:
            'Session expired.'
        });
      }

      res.json({
        user:
          userPublic(
            result.rows[0]
          )
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          'Unable to check session.'
      });
    }
  }
);


// ============================================================
// LOGOUT
// ============================================================

app.post(
  '/api/auth/logout',
  (req, res) => {
    req.session.destroy(
      error => {
        res.clearCookie(
          'lexicon.sid',
          { path: '/' }
        );

        /*
         * Remove the old cookie too.
         * This lets existing users upgrade
         * cleanly from the previous build.
         */

        res.clearCookie(
          'connect.sid',
          { path: '/' }
        );

        if (error) {
          return res.status(500).json({
            error:
              'Unable to log out.'
          });
        }

        res.json({
          ok: true
        });
      }
    );
  }
);


// ============================================================
// PASSWORD RESET — REQUEST
// ============================================================

app.post(
  '/api/auth/password-reset/request',
  async (req, res) => {
    if (!requireDB(res)) {
      return;
    }

    const generic =
      'If that account exists, a reset link has been sent.';

    try {
      const email =
        emailOf(req.body.email);

      if (!validEmail(email)) {
        return res.json({
          ok: true,
          message: generic
        });
      }

      const result =
        await pool.query(
          `
          SELECT *
          FROM users
          WHERE email=$1
            AND email_verified=TRUE
          `,
          [email]
        );

      if (!result.rowCount) {
        return res.json({
          ok: true,
          message: generic
        });
      }

      const user =
        result.rows[0];

      await pool.query(
        `
        UPDATE password_reset_tokens
        SET used_at=NOW()
        WHERE user_id=$1
          AND used_at IS NULL
        `,
        [user.id]
      );

      const rawToken =
        crypto.randomBytes(32)
          .toString('hex');

      await pool.query(
        `
        INSERT INTO password_reset_tokens(
          user_id,
          token_hash,
          expires_at
        )
        VALUES(
          $1,
          $2,
          NOW() +
            INTERVAL '${RESET_TTL} minutes'
        )
        `,
        [
          user.id,
          hash(rawToken)
        ]
      );

      const base =
        APP_URL ||
        `${req.protocol}://${req.get('host')}`;

      const link =
        `${base}/reset-password?reset=` +
        encodeURIComponent(
          rawToken
        );

      await sendMail(
        email,

        'The Lexicon — reset your password',

        `Use this link to reset your The Lexicon password. ` +
        `It expires in ${RESET_TTL} minutes:\n\n${link}`,

        `
        <div style="font-family:Arial,sans-serif">
          <p>
            Use the secure link below to reset
            your The Lexicon password.
          </p>

          <p>
            <a href="${link}">
              Reset your password
            </a>
          </p>

          <p>
            This link expires in
            ${RESET_TTL} minutes.
          </p>
        </div>
        `
      );

      res.json({
        ok: true,
        message: generic
      });
    } catch (error) {
      console.error(error);

      /*
       * Do not reveal whether an email
       * belongs to an account.
       */

      res.json({
        ok: true,
        message: generic
      });
    }
  }
);


// ============================================================
// PASSWORD RESET — COMPLETE
// ============================================================

app.post(
  '/api/auth/password-reset/complete',
  async (req, res) => {
    if (!requireDB(res)) {
      return;
    }

    const client =
      await pool.connect();

    try {
      const token =
        String(
          req.body.token || ''
        );

      const password =
        String(
          req.body.password || ''
        );

      if (
        !token ||
        password.length < 8
      ) {
        return res.status(400).json({
          error:
            'Invalid reset request or password.'
        });
      }

      const result =
        await client.query(
          `
          SELECT
            u.*,
            prt.id AS reset_id
          FROM password_reset_tokens prt
          JOIN users u
            ON u.id=prt.user_id
          WHERE
            prt.token_hash=$1
            AND prt.used_at IS NULL
            AND prt.expires_at>NOW()
          LIMIT 1
          `,
          [hash(token)]
        );

      if (!result.rowCount) {
        return res.status(400).json({
          error:
            'This reset link is invalid or has expired.'
        });
      }

      const user =
        result.rows[0];

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      await client.query(
        'BEGIN'
      );

      await client.query(
        `
        UPDATE users
        SET
          password_hash=$1,
          updated_at=NOW()
        WHERE id=$2
        `,
        [
          passwordHash,
          user.id
        ]
      );

      await client.query(
        `
        UPDATE password_reset_tokens
        SET used_at=NOW()
        WHERE user_id=$1
          AND used_at IS NULL
        `,
        [user.id]
      );

      await client.query(
        'COMMIT'
      );

      await loginSession(
        req,
        user,
        false
      );

      res.json({
        user:
          userPublic(user)
      });
    } catch (error) {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch (_) {}

      console.error(error);

      res.status(400).json({
        error:
          'Unable to reset the password.'
      });
    } finally {
      client.release();
    }
  }
);


// ============================================================
// USER DATA — GET
// ============================================================

app.get(
  '/api/data',
  async (req, res) => {
    if (!requireDB(res)) {
      return;
    }

    if (!req.session.userId) {
      return res.status(401).json({
        error:
          'Not logged in.'
      });
    }

    try {
      const result =
        await pool.query(
          `
          SELECT
            cabinet,
            global_stats,
            current_state,
            updated_at
          FROM user_data
          WHERE user_id=$1
          `,
          [req.session.userId]
        );

      if (!result.rowCount) {
        return res.json({
          cabinet: [],
          globalStats: {},
          currentState: null,
          updatedAt: null
        });
      }

      const row =
        result.rows[0];

      res.json({
        cabinet:
          row.cabinet,

        globalStats:
          row.global_stats,

        currentState:
          row.current_state,

        updatedAt:
          row.updated_at
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          'Unable to load user data.'
      });
    }
  }
);


// ============================================================
// USER DATA — SAVE
// ============================================================

app.put(
  '/api/data',
  async (req, res) => {
    if (!requireDB(res)) {
      return;
    }

    if (!req.session.userId) {
      return res.status(401).json({
        error:
          'Not logged in.'
      });
    }

    try {
      const cabinet =
        Array.isArray(
          req.body.cabinet
        )
          ? req.body.cabinet
          : [];

      const globalStats =
        req.body.globalStats &&
        typeof req.body.globalStats ===
          'object'
          ? req.body.globalStats
          : {};

      const currentState =
        req.body.currentState ??
        null;

      await pool.query(
        `
        INSERT INTO user_data(
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
          cabinet=
            EXCLUDED.cabinet,

          global_stats=
            EXCLUDED.global_stats,

          current_state=
            EXCLUDED.current_state,

          updated_at=
            NOW()
        `,
        [
          req.session.userId,

          JSON.stringify(
            cabinet
          ),

          JSON.stringify(
            globalStats
          ),

          JSON.stringify(
            currentState
          )
        ]
      );

      const saved =
        await pool.query(
          `
          SELECT updated_at
          FROM user_data
          WHERE user_id=$1
          `,
          [req.session.userId]
        );

      res.json({
        ok: true,

        updatedAt:
          saved.rows[0]
            ?.updated_at ||
          null
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          'Unable to save user data.'
      });
    }
  }
);


// ============================================================
// FEEDBACK
// ============================================================

app.post(
  '/api/feedback',
  async (req, res) => {
    try {
      const message = String(req.body?.message || '').trim();

      if (!message) {
        return res.status(400).json({
          error: 'Please enter your feedback.'
        });
      }

      if (message.length > 5000) {
        return res.status(400).json({
          error: 'Feedback is too long.'
        });
      }

      const recipient =
        process.env.FEEDBACK_TO ||
        'feedback@lexiconoftheworld.win';

      await sendMail(
        recipient,
        'The Lexicon Feedback',
        message,
        `<div style=\"font-family:Arial,sans-serif;white-space:pre-wrap\">${message.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>`
      );

      res.json({ ok: true });
    } catch (error) {
      console.error('Feedback email error:', error);

      res.status(500).json({
        error: 'Unable to send feedback right now. Please try again later.'
      });
    }
  }
);


// ============================================================
// DeepSeek
// ============================================================

async function deepseek(
  words,
  one = false
) {
  if (
    !process.env.DEEPSEEK_API_KEY
  ) {
    throw new Error(
      'DeepSeek API key is not configured'
    );
  }

  const list =
    words
      .map(String)
      .map(x => x.trim())
      .filter(Boolean);

  const system = one
    ? `
You are an English vocabulary learning assistant.

The user provides exactly ONE English vocabulary word.

Return valid JSON only in this exact structure:

{
  "words": [
    {
      "word": "exact input word",
      "definition": "clear concise English definition",
      "examples": [
        "sentence 1",
        "sentence 2",
        "sentence 3"
      ],
      "synonyms": [],
      "antonyms": [],
      "root": "brief accurate root/etymology",
      "cognates": []
    }
  ]
}

Preserve the input word exactly.

Return exactly one item.

Return exactly three useful example sentences.

Never split or replace the word.
`
    : `
You are an English vocabulary learning assistant.

The user provides a list of English vocabulary words.

Return valid JSON only with this structure:

{
  "words": [
    {
      "word": "exact input",
      "definition": "clear concise definition",
      "examples": [
        "sentence 1",
        "sentence 2",
        "sentence 3"
      ],
      "synonyms": [],
      "antonyms": [],
      "root": "brief accurate root/etymology",
      "cognates": []
    }
  ]
}

Return exactly one entry per input word.

Preserve spelling exactly.

Never split a word.

Provide exactly three natural useful example sentences.

Do not add extra fields.
`;

  const user =
    one
      ? `Generate one vocabulary entry for this exact word:\n${list[0]}`
      : `Generate the vocabulary library for these words:\n${list.join('\n')}`;

  const response =
    await fetch(
      'https://api.deepseek.com/chat/completions',
      {
        method: 'POST',

        headers: {
          'Content-Type':
            'application/json',

          Authorization:
            `Bearer ${process.env.DEEPSEEK_API_KEY}`
        },

        body: JSON.stringify({
          model:
            'deepseek-v4-flash',

          thinking: {
            type: 'disabled'
          },

          messages: [
            {
              role: 'system',
              content: system
            },

            {
              role: 'user',
              content: user
            }
          ],

          response_format: {
            type: 'json_object'
          },

          max_tokens:
            one
              ? 2000
              : 6000,

          stream: false
        })
      }
    );

  if (!response.ok) {
    console.error(
      'DeepSeek API error:',
      await response.text()
    );

    throw new Error(
      'DeepSeek API request failed'
    );
  }

  const data =
    await response.json();

  const content =
    data?.choices?.[0]
      ?.message?.content;

  if (!content) {
    throw new Error(
      'DeepSeek returned an empty response'
    );
  }

  let result;

  try {
    result =
      JSON.parse(content);
  } catch (_) {
    throw new Error(
      'DeepSeek returned invalid JSON'
    );
  }

  if (
    !Array.isArray(
      result.words
    ) ||
    result.words.length !==
      list.length
  ) {
    throw new Error(
      'DeepSeek returned an incorrect number of vocabulary entries'
    );
  }

  result.words =
    result.words.map(
      (item, index) => ({
        word:
          list[index],

        definition:
          String(
            item?.definition ||
              ''
          ).trim(),

        examples:
          Array.isArray(
            item?.examples
          )
            ? item.examples
                .map(
                  value =>
                    String(
                      value || ''
                    ).trim()
                )
                .filter(Boolean)
                .slice(0, 3)
            : [],

        synonyms:
          Array.isArray(
            item?.synonyms
          )
            ? item.synonyms
                .map(
                  value =>
                    String(
                      value || ''
                    ).trim()
                )
                .filter(Boolean)
            : [],

        antonyms:
          Array.isArray(
            item?.antonyms
          )
            ? item.antonyms
                .map(
                  value =>
                    String(
                      value || ''
                    ).trim()
                )
                .filter(Boolean)
            : [],

        root:
          String(
            item?.root || ''
          ).trim(),

        cognates:
          Array.isArray(
            item?.cognates
          )
            ? item.cognates
                .map(
                  value =>
                    String(
                      value || ''
                    ).trim()
                )
                .filter(Boolean)
            : []
      })
    );

  for (
    const item of result.words
  ) {
    if (!item.definition) {
      throw new Error(
        `DeepSeek did not return a definition for "${item.word}"`
      );
    }

    if (
      item.examples.length !==
      3
    ) {
      throw new Error(
        `DeepSeek did not return exactly three examples for "${item.word}"`
      );
    }
  }

  return result;
}


// ============================================================
// DeepSeek — full library
// ============================================================

app.post(
  '/api/generate',
  async (req, res) => {
    try {
      const words =
        Array.isArray(
          req.body.words
        )
          ? req.body.words
          : [];

      if (!words.length) {
        return res.status(400).json({
          error:
            'Please provide at least one word'
        });
      }

      if (words.length > 50) {
        return res.status(400).json({
          error:
            'Maximum 50 words per request'
        });
      }

      res.json(
        await deepseek(
          words,
          false
        )
      );
    } catch (error) {
      console.error(error);

      res.status(502).json({
        error:
          error.message ||
          'Unable to generate vocabulary'
      });
    }
  }
);


// ============================================================
// DeepSeek — single word
// ============================================================

app.post(
  '/api/generate-one',
  async (req, res) => {
    try {
      const word =
        String(
          req.body?.word || ''
        ).trim();

      if (!word) {
        return res.status(400).json({
          error:
            'Please provide a word.'
        });
      }

      if (word.length > 200) {
        return res.status(400).json({
          error:
            'The word is too long.'
        });
      }

      res.json(
        await deepseek(
          [word],
          true
        )
      );
    } catch (error) {
      console.error(error);

      res.status(502).json({
        error:
          error.message ||
          'Unable to generate this word right now. Please try again.'
      });
    }
  }
);


// ============================================================
// Reset password page
// ============================================================

app.get(
  '/reset-password',
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'public',
        'index.html'
      )
    );
  }
);


// ============================================================
// Static website
// ============================================================

app.use(
  express.static(
    path.join(
      __dirname,
      'public'
    )
  )
);


// ============================================================
// Start
// ============================================================

initDB()
  .then(() => {
    console.log(
      'Database initialized.'
    );

    app.listen(
      PORT,
      () => {
        console.log(
          `Server running on port ${PORT}`
        );
      }
    );
  })
  .catch(error => {
    console.error(
      'Database initialization failed:',
      error
    );

    process.exit(1);
  });
