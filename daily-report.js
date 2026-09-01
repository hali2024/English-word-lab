const { Pool } = require('pg');

const DATABASE_URL = process.env.DATABASE_URL || '';
const REPORT_TIMEZONE = process.env.REPORT_TIMEZONE || 'Asia/Tokyo';
const REPORT_FROM = process.env.RESEND_FROM || '';
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const TEST_EMAIL = String(process.env.REPORT_TEST_EMAIL || '').trim().toLowerCase();
const TEST_MODE = String(process.env.REPORT_TEST_MODE || '').toLowerCase() === 'true';

if (!DATABASE_URL) {
  console.error('DATABASE_URL is not configured.');
  process.exit(1);
}

if (!RESEND_API_KEY || !REPORT_FROM) {
  console.error('RESEND_API_KEY and RESEND_FROM are required.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl:
    DATABASE_URL.includes('railway') ||
    process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : undefined
});

function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  }[char]));
}

function plural(number, singular, pluralForm = `${singular}s`) {
  return Number(number) === 1 ? singular : pluralForm;
}

function formatNumber(number) {
  return Number(number || 0).toLocaleString('en-US');
}

function formatDate(dateValue, timeZone) {
  return new Intl.DateTimeFormat('en-US', {
    timeZone,
    month: 'short',
    day: 'numeric',
    year: 'numeric'
  }).format(new Date(dateValue));
}

function buildTextEmail({ email, startTime, endTime, stats }) {
  const lines = [
    'THE LEXICON',
    '',
    `Your learning report for ${email}`,
    `${formatDate(startTime, REPORT_TIMEZONE)} — ${formatDate(endTime, REPORT_TIMEZONE)}`,
    '',
    `Words encountered: ${formatNumber(stats.practiceCount)}`,
    `Unique words: ${formatNumber(stats.uniqueWords)}`,
    `Words learned: ${formatNumber(stats.learnedCount)}`,
    `Words spelled: ${formatNumber(stats.spellingCount)}`,
    `Mistakes: ${formatNumber(stats.mistakeCount)}`,
    '',
    'Most practised words:'
  ];

  if (!stats.topPractice.length) {
    lines.push('No practice activity recorded.');
  } else {
    stats.topPractice.forEach((item, index) => {
      lines.push(`${index + 1}. ${item.word} — ${item.count} ${plural(item.count, 'time')}`);
    });
  }

  lines.push('', 'Keep going. See you tomorrow.', '— The Lexicon');
  return lines.join('\n');
}

function buildHTML({ startTime, endTime, stats, testMode }) {
  const topRows = stats.topPractice.length
    ? stats.topPractice.map((item, index) => `
        <tr>
          <td style="padding:9px 0;color:#777;font:14px Arial,sans-serif;width:34px;">${index + 1}</td>
          <td style="padding:9px 0;color:#222;font:600 15px Arial,sans-serif;">${escapeHTML(item.word)}</td>
          <td style="padding:9px 0;text-align:right;color:#777;font:14px Arial,sans-serif;">${formatNumber(item.count)} ${escapeHTML(plural(item.count, 'time'))}</td>
        </tr>`).join('')
    : `
        <tr>
          <td colspan="3" style="padding:12px 0;color:#777;font:14px Arial,sans-serif;">No practice activity recorded.</td>
        </tr>`;

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>The Lexicon Daily Report</title>
</head>
<body style="margin:0;padding:0;background:#f4f1ea;">
  <div style="width:100%;background:#f4f1ea;padding:32px 12px;box-sizing:border-box;">
    <div style="max-width:620px;margin:0 auto;background:#fff;border:1px solid #ddd8ce;">
      <div style="padding:28px 30px;background:#20201d;color:#fff;">
        <div style="font:600 12px/1.2 Arial,sans-serif;letter-spacing:3px;">THE LEXICON</div>
        <div style="margin-top:16px;font:400 28px/1.2 Georgia,serif;">Your daily learning report</div>
        ${testMode ? '<div style="margin-top:10px;font:12px Arial,sans-serif;color:#ddd;">TEST EMAIL — this was sent only to the test address.</div>' : ''}
      </div>

      <div style="padding:30px;">
        <div style="font:14px/1.6 Arial,sans-serif;color:#777;">${escapeHTML(formatDate(startTime, REPORT_TIMEZONE))} — ${escapeHTML(formatDate(endTime, REPORT_TIMEZONE))}</div>

        <div style="margin-top:24px;border-top:1px solid #e4e0d8;border-bottom:1px solid #e4e0d8;">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse;">
            <tr>
              <td style="padding:18px 8px 18px 0;width:50%;vertical-align:top;">
                <div style="font:30px Georgia,serif;color:#20201d;">${formatNumber(stats.practiceCount)}</div>
                <div style="margin-top:5px;font:12px Arial,sans-serif;letter-spacing:1px;text-transform:uppercase;color:#777;">Words studied</div>
              </td>
              <td style="padding:18px 0 18px 8px;width:50%;vertical-align:top;">
                <div style="font:30px Georgia,serif;color:#20201d;">${formatNumber(stats.uniqueWords)}</div>
                <div style="margin-top:5px;font:12px Arial,sans-serif;letter-spacing:1px;text-transform:uppercase;color:#777;">Unique words</div>
              </td>
            </tr>
            <tr>
              <td style="padding:0 8px 18px 0;width:50%;vertical-align:top;">
                <div style="font:24px Georgia,serif;color:#20201d;">${formatNumber(stats.learnedCount)}</div>
                <div style="margin-top:5px;font:12px Arial,sans-serif;letter-spacing:1px;text-transform:uppercase;color:#777;">Words learned</div>
              </td>
              <td style="padding:0 0 18px 8px;width:50%;vertical-align:top;">
                <div style="font:24px Georgia,serif;color:#20201d;">${formatNumber(stats.spellingCount)}</div>
                <div style="margin-top:5px;font:12px Arial,sans-serif;letter-spacing:1px;text-transform:uppercase;color:#777;">Words spelled</div>
              </td>
            </tr>
            <tr>
              <td colspan="2" style="padding:0 0 20px;">
                <div style="font:24px Georgia,serif;color:#20201d;">${formatNumber(stats.mistakeCount)}</div>
                <div style="margin-top:5px;font:12px Arial,sans-serif;letter-spacing:1px;text-transform:uppercase;color:#777;">Mistakes</div>
              </td>
            </tr>
          </table>
        </div>

        <div style="margin-top:30px;">
          <div style="font:600 12px Arial,sans-serif;letter-spacing:2px;text-transform:uppercase;color:#777;">Most practised words</div>
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-top:12px;border-collapse:collapse;">
            ${topRows}
          </table>
        </div>

        <div style="margin-top:28px;padding-top:20px;border-top:1px solid #e4e0d8;color:#777;font:13px/1.7 Arial,sans-serif;">
          ${stats.practiceCount
            ? `You studied ${formatNumber(stats.practiceCount)} ${escapeHTML(plural(stats.practiceCount, 'time'))} across ${formatNumber(stats.uniqueWords)} ${escapeHTML(plural(stats.uniqueWords, 'unique word'))} during this report window.`
            : 'No study activity was recorded during this report window.'}
        </div>
      </div>

      <div style="padding:20px 30px;background:#f8f6f1;color:#888;font:12px/1.6 Arial,sans-serif;">
        The Lexicon · Automated daily learning report
      </div>
    </div>
  </div>
</body>
</html>`;
}

async function sendMail(to, subject, text, html, idempotencyKey) {
  const headers = {
    Authorization: `Bearer ${RESEND_API_KEY}`,
    'Content-Type': 'application/json'
  };

  if (idempotencyKey) {
    headers['Idempotency-Key'] = idempotencyKey;
  }

  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers,
    body: JSON.stringify({
      from: REPORT_FROM,
      to: [to],
      subject,
      text,
      html
    })
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Resend API error ${response.status}: ${body}`);
  }

  return response.json();
}

async function getReportWindow() {
  if (TEST_MODE) {
    const result = await pool.query(`
      SELECT
        NOW() - INTERVAL '24 hours' AS start_time,
        NOW() AS end_time,
        (NOW() AT TIME ZONE $1)::date AS report_date
    `, [REPORT_TIMEZONE]);
    return result.rows[0];
  }

  const result = await pool.query(`
    WITH local_clock AS (
      SELECT NOW() AT TIME ZONE $1 AS local_now
    ), anchor AS (
      SELECT
        CASE
          WHEN local_now >= date_trunc('day', local_now) + INTERVAL '7 hours'
            THEN date_trunc('day', local_now) + INTERVAL '7 hours'
          ELSE date_trunc('day', local_now) + INTERVAL '7 hours' - INTERVAL '24 hours'
        END AS local_end
      FROM local_clock
    )
    SELECT
      (local_end - INTERVAL '24 hours') AT TIME ZONE $1 AS start_time,
      local_end AT TIME ZONE $1 AS end_time,
      local_end::date AS report_date
    FROM anchor
  `, [REPORT_TIMEZONE]);

  return result.rows[0];
}

async function getUsers() {
  if (TEST_EMAIL) {
    const result = await pool.query(`
      SELECT id, email
      FROM users
      WHERE email=$1
    `, [TEST_EMAIL]);
    return result.rows;
  }

  const result = await pool.query(`
    SELECT id, email
    FROM users
    WHERE email_verified=TRUE
    ORDER BY id
  `);
  return result.rows;
}

async function getStats(userId, startTime, endTime) {
  const result = await pool.query(`
    SELECT
      event_type,
      word,
      COUNT(*)::int AS count
    FROM study_events
    WHERE user_id=$1
      AND created_at >= $2
      AND created_at < $3
    GROUP BY event_type, word
    ORDER BY count DESC
  `, [userId, startTime, endTime]);

  let practiceCount = 0;
  let learnedCount = 0;
  let spellingCount = 0;
  let mistakeCount = 0;
  const practiceByWord = new Map();
  const uniqueWords = new Set();

  for (const row of result.rows) {
    const count = Number(row.count || 0);

    if (row.event_type === 'practice') {
      practiceCount += count;
      if (row.word) {
        practiceByWord.set(row.word, count);
        uniqueWords.add(row.word);
      }
    } else if (row.event_type === 'learned') {
      learnedCount += count;
      if (row.word) uniqueWords.add(row.word);
    } else if (row.event_type === 'spelling') {
      spellingCount += count;
      if (row.word) uniqueWords.add(row.word);
    } else if (row.event_type === 'mistake') {
      mistakeCount += count;
      if (row.word) uniqueWords.add(row.word);
    }
  }

  const topPractice = [...practiceByWord.entries()]
    .map(([word, count]) => ({ word, count }))
    .sort((a, b) => b.count - a.count || a.word.localeCompare(b.word))
    .slice(0, 10);

  return {
    practiceCount,
    learnedCount,
    spellingCount,
    mistakeCount,
    uniqueWords: uniqueWords.size,
    topPractice
  };
}

async function claimReport(userId, reportDate) {
  const result = await pool.query(`
    INSERT INTO daily_email_logs(user_id, report_date)
    VALUES($1, $2)
    ON CONFLICT(user_id, report_date) DO NOTHING
    RETURNING id
  `, [userId, reportDate]);

  return result.rowCount > 0;
}

async function releaseReportClaim(userId, reportDate) {
  await pool.query(`
    DELETE FROM daily_email_logs
    WHERE user_id=$1 AND report_date=$2
  `, [userId, reportDate]);
}

async function main() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS study_events (
        id BIGSERIAL PRIMARY KEY,
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        event_type TEXT NOT NULL,
        word TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS study_events_user_time
        ON study_events(user_id, created_at);

      CREATE TABLE IF NOT EXISTS daily_email_logs (
        id BIGSERIAL PRIMARY KEY,
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        report_date DATE NOT NULL,
        sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(user_id, report_date)
      );
    `);

    const window = await getReportWindow();
    const users = await getUsers();

    if (!users.length) {
      console.log('No matching users found.');
      return;
    }

    console.log(`Report window: ${window.start_time.toISOString()} -> ${window.end_time.toISOString()}`);
    console.log(`Timezone: ${REPORT_TIMEZONE}`);
    console.log(`Users selected: ${users.length}`);

    for (const user of users) {
      let claimed = false;

      if (!TEST_MODE) {
        claimed = await claimReport(user.id, window.report_date);
        if (!claimed) {
          console.log(`Skipping ${user.email}: report already sent/claimed for ${window.report_date}.`);
          continue;
        }
      }

      const recipient = TEST_EMAIL || user.email;
      const stats = await getStats(user.id, window.start_time, window.end_time);
      const text = buildTextEmail({
        email: recipient,
        startTime: window.start_time,
        endTime: window.end_time,
        stats
      });
      const html = buildHTML({
        startTime: window.start_time,
        endTime: window.end_time,
        stats,
        testMode: TEST_MODE
      });

      try {
        const subject = TEST_MODE
          ? 'The Lexicon — Daily Learning Report (TEST)'
          : 'The Lexicon — Your Daily Learning Report';

        const idempotencyKey = `lexicon-daily-report-${window.report_date}-${user.id}`;
        const response = await sendMail(
          recipient,
          subject,
          text,
          html,
          idempotencyKey
        );

        console.log(`Sent ${recipient}:`, response);
      } catch (error) {
        if (claimed) {
          await releaseReportClaim(user.id, window.report_date);
        }
        throw error;
      }
    }
  } finally {
    await pool.end();
  }
}

main().catch(error => {
  console.error('Daily report failed:', error);
  process.exitCode = 1;
});
