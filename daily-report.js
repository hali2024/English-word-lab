const { Pool } = require('pg');
const crypto = require('crypto');

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
          <td style="padding:11px 0;color:#a19d94;font:13px Arial,sans-serif;width:34px;vertical-align:middle;">
            ${String(index + 1).padStart(2, '0')}
          </td>
          <td style="padding:11px 0;color:#292824;font:600 15px Georgia,serif;vertical-align:middle;">
            ${escapeHTML(item.word)}
          </td>
          <td style="padding:11px 0;text-align:right;color:#8b877f;font:13px Arial,sans-serif;vertical-align:middle;">
            ${formatNumber(item.count)} ${escapeHTML(plural(item.count, 'time'))}
          </td>
        </tr>`).join('')
    : `
        <tr>
          <td colspan="3" style="padding:14px 0;color:#8b877f;font:14px/1.6 Arial,sans-serif;">
            A quiet day of study. Your next word is waiting.
          </td>
        </tr>`;

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>The Lexicon — Your Daily Learning</title>
</head>

<body style="margin:0;padding:0;background:#eeece6;">

  <div style="width:100%;background:#eeece6;padding:36px 12px;box-sizing:border-box;">

    <div style="max-width:640px;margin:0 auto;background:#fbfaf7;border:1px solid #d9d5cc;">

      <!-- HEADER -->
      <div style="padding:34px 38px 32px;background:#242421;color:#f8f6f0;">

        <div style="font:600 11px/1.2 Arial,sans-serif;letter-spacing:4px;">
          THE LEXICON
        </div>

        <div style="margin-top:24px;font:400 31px/1.2 Georgia,serif;">
          Good morning, wordsmith.
        </div>

        <div style="margin-top:12px;max-width:450px;color:#d7d4cc;font:14px/1.7 Georgia,serif;">
          A little note from your Lexicon, with a look back at the words
          you spent time with yesterday.
        </div>

        ${testMode
          ? '<div style="margin-top:18px;font:10px Arial,sans-serif;letter-spacing:1.5px;text-transform:uppercase;color:#aaa79f;">Test edition · sent only to the test address</div>'
          : ''}
      </div>


      <!-- INTRO -->
      <div style="padding:34px 38px 0;">

        <div style="color:#77736b;font:13px/1.6 Arial,sans-serif;">
          ${escapeHTML(formatDate(startTime, REPORT_TIMEZONE))}
          &nbsp;&nbsp;—&nbsp;&nbsp;
          ${escapeHTML(formatDate(endTime, REPORT_TIMEZONE))}
        </div>

        <div style="margin-top:24px;color:#292824;font:400 20px/1.55 Georgia,serif;">
          Hello again.
        </div>

        <div style="margin-top:9px;color:#706c64;font:14px/1.8 Arial,sans-serif;">
          Here is your little record of yesterday's journey through language.
          No matter how many words you met, every encounter counts.
        </div>

      </div>


      <!-- MAIN STATISTICS -->
      <div style="padding:30px 38px 0;">

        <div style="border-top:1px solid #dcd8cf;border-bottom:1px solid #dcd8cf;">

          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse;">

            <tr>

              <td style="padding:22px 14px 20px 0;width:50%;vertical-align:top;border-bottom:1px solid #e5e1d9;">

                <div style="font:400 31px/1 Georgia,serif;color:#292824;">
                  ${formatNumber(stats.practiceCount)}
                </div>

                <div style="margin-top:8px;font:600 10px/1.3 Arial,sans-serif;letter-spacing:1.7px;text-transform:uppercase;color:#8b877f;">
                  Words studied
                </div>

              </td>


              <td style="padding:22px 0 20px 14px;width:50%;vertical-align:top;border-bottom:1px solid #e5e1d9;">

                <div style="font:400 31px/1 Georgia,serif;color:#292824;">
                  ${formatNumber(stats.uniqueWords)}
                </div>

                <div style="margin-top:8px;font:600 10px/1.3 Arial,sans-serif;letter-spacing:1.7px;text-transform:uppercase;color:#8b877f;">
                  Unique words
                </div>

              </td>

            </tr>


            <tr>

              <td style="padding:21px 14px 22px 0;width:50%;vertical-align:top;">

                <div style="font:400 25px/1 Georgia,serif;color:#292824;">
                  ${formatNumber(stats.learnedCount)}
                </div>

                <div style="margin-top:8px;font:600 10px/1.3 Arial,sans-serif;letter-spacing:1.7px;text-transform:uppercase;color:#8b877f;">
                  Words learned
                </div>

              </td>


              <td style="padding:21px 0 22px 14px;width:50%;vertical-align:top;">

                <div style="font:400 25px/1 Georgia,serif;color:#292824;">
                  ${formatNumber(stats.spellingCount)}
                </div>

                <div style="margin-top:8px;font:600 10px/1.3 Arial,sans-serif;letter-spacing:1.7px;text-transform:uppercase;color:#8b877f;">
                  Words spelled
                </div>

              </td>

            </tr>

          </table>

        </div>

      </div>


      <!-- MISTAKES -->
      <div style="padding:25px 38px 0;">

        <div style="padding:19px 20px;background:#f1eee7;border-left:2px solid #353530;">

          <div style="font:400 24px/1 Georgia,serif;color:#292824;">
            ${formatNumber(stats.mistakeCount)}
          </div>

          <div style="margin-top:7px;font:600 10px/1.3 Arial,sans-serif;letter-spacing:1.7px;text-transform:uppercase;color:#8b877f;">
            Mistakes made
          </div>

          <div style="margin-top:9px;color:#77736b;font:13px/1.65 Arial,sans-serif;">
            Mistakes are part of remembering. They give tomorrow's practice
            somewhere to begin.
          </div>

        </div>

      </div>


      <!-- TOP WORDS -->
      <div style="padding:34px 38px 0;">

        <div style="font:600 10px/1.3 Arial,sans-serif;letter-spacing:2px;text-transform:uppercase;color:#8b877f;">
          A few words from yesterday
        </div>

        <div style="margin-top:7px;color:#292824;font:400 19px/1.45 Georgia,serif;">
          Your most practised words
        </div>


        <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
          style="margin-top:17px;border-collapse:collapse;border-top:1px solid #dedad2;">

          ${topRows}

        </table>

      </div>


      <!-- CLOSING NOTE -->
      <div style="padding:31px 38px 0;">

        <div style="border-top:1px solid #dedad2;padding-top:25px;color:#6f6b63;font:14px/1.85 Georgia,serif;">

          ${stats.practiceCount
            ? `You spent time with <strong style="color:#292824;font-weight:normal;">${formatNumber(stats.practiceCount)} ${escapeHTML(plural(stats.practiceCount, 'word'))}</strong> across <strong style="color:#292824;font-weight:normal;">${formatNumber(stats.uniqueWords)} ${escapeHTML(plural(stats.uniqueWords, 'unique word'))}</strong> during this little window of study.`
            : 'There was no recorded study activity during this little window. That is quite all right. The Lexicon will be here when you are ready.'}

        </div>

      </div>


      <!-- WEBSITE CTA -->
      <div style="padding:34px 38px 38px;text-align:center;">

        <div style="margin-bottom:19px;color:#292824;font:400 20px/1.45 Georgia,serif;">
          Shall we meet again?
        </div>

        <div style="margin-bottom:21px;color:#77736b;font:13px/1.7 Arial,sans-serif;">
          Your cabinet is waiting, and there are still words to discover.
        </div>

        <a href="https://lexicon-cx9.pages.dev"
          style="display:inline-block;padding:13px 25px;background:#292925;color:#f8f6f0;text-decoration:none;font:600 11px/1 Arial,sans-serif;letter-spacing:1.8px;text-transform:uppercase;">
          Enter The Lexicon
        </a>

      </div>


      <!-- FOOTER -->
      <div style="padding:22px 38px;background:#e9e6de;border-top:1px solid #d9d5cc;">

        <div style="color:#77736b;font:11px/1.6 Arial,sans-serif;letter-spacing:.3px;">
          The Lexicon
        </div>

        <div style="margin-top:4px;color:#99958d;font:11px/1.6 Arial,sans-serif;">
          A quiet place for words, memory, and practice.
        </div>

      </div>

    </div>

  </div>

</body>
</html>`;
}

async function sendMail(to, subject, text, html, idempotencyKey) {
  const payload = {
    from: REPORT_FROM,
    to: [to],
    subject,
    text,
    html
  };

  const payloadHash = crypto
    .createHash('sha256')
    .update(JSON.stringify(payload))
    .digest('hex')
    .slice(0, 32);

  const headers = {
    Authorization: `Bearer ${RESEND_API_KEY}`,
    'Content-Type': 'application/json'
  };

  if (idempotencyKey) {
    headers['Idempotency-Key'] = `${idempotencyKey}-${payloadHash}`;
  }

  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers,
    body: JSON.stringify(payload)
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

      if (row.word) {
        uniqueWords.add(row.word);
      }

    } else if (row.event_type === 'spelling') {
      spellingCount += count;

      if (row.word) {
        uniqueWords.add(row.word);
      }

    } else if (row.event_type === 'mistake') {
      mistakeCount += count;

      if (row.word) {
        uniqueWords.add(row.word);
      }
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

    console.log(`Mode: ${TEST_MODE ? 'TEST' : 'PRODUCTION'}`);
    console.log(`Test email configured: ${Boolean(TEST_EMAIL)}`);
    console.log(`Report date: ${window.report_date}`);

    if (!users.length) {
      console.log('No matching users found.');
      return;
    }

    console.log(
      `Report window: ${window.start_time.toISOString()} -> ${window.end_time.toISOString()}`
    );

    console.log(`Timezone: ${REPORT_TIMEZONE}`);
    console.log(`Users selected: ${users.length}`);

    for (const user of users) {
      let claimed = false;

      if (!TEST_MODE) {
        claimed = await claimReport(user.id, window.report_date);

        if (!claimed) {
          console.log(
            `Skipping ${user.email}: report already sent/claimed for ${window.report_date}.`
          );
          continue;
        }
      }

      const recipient = TEST_EMAIL || user.email;

      const stats = await getStats(
        user.id,
        window.start_time,
        window.end_time
      );

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

        const idempotencyKey = TEST_MODE
          ? `lexicon-daily-report-test-${Date.now()}-${user.id}`
          : `lexicon-daily-report-${window.report_date}-${user.id}`;

        console.log(
          `Sending ${recipient}: report_date=${window.report_date}, user_id=${user.id}`
        );

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
