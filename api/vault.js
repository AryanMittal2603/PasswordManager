// Vercel serverless function: shared storage for the encrypted vault, backed by
// one cell of a Google Sheet. The service-account key stays here (server-side,
// from an env var) and never reaches the browser. The vault blob is already
// encrypted client-side, so the Sheet only ever holds ciphertext.
//
// Env vars (set in Vercel → Project → Settings → Environment Variables):
//   GOOGLE_SERVICE_ACCOUNT  the FULL service-account JSON (one value)
//   SHEET_ID                spreadsheet id (defaults to the one provided)
//   SHEET_NAME              tab name (defaults to "Sheet1")
//
// Uses only Node built-ins (crypto + global fetch) — no npm dependencies.

const crypto = require('crypto');

const SHEET_ID = process.env.SHEET_ID || '1OT35q7-_izPw5gyuL0VJs6SLiQpuJcTv9ey9yS_G09I';
const SHEET_NAME = process.env.SHEET_NAME || 'Sheet1';
const CELL = 'A1';
const TOKEN_URI = 'https://oauth2.googleapis.com/token';

function getCreds() {
  const raw = process.env.GOOGLE_SERVICE_ACCOUNT;
  if (!raw) throw new Error('GOOGLE_SERVICE_ACCOUNT env var is not set');
  const creds = JSON.parse(raw);
  // Tolerate keys whose newlines got escaped when pasted into an env var.
  if (creds.private_key && creds.private_key.includes('\\n')) {
    creds.private_key = creds.private_key.replace(/\\n/g, '\n');
  }
  return creds;
}

// Mint a short-lived OAuth access token via the service-account JWT grant.
async function getAccessToken() {
  const creds = getCreds();
  const now = Math.floor(Date.now() / 1000);
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const unsigned =
    b64({ alg: 'RS256', typ: 'JWT' }) + '.' +
    b64({
      iss: creds.client_email,
      scope: 'https://www.googleapis.com/auth/spreadsheets',
      aud: creds.token_uri || TOKEN_URI,
      iat: now,
      exp: now + 3600,
    });
  const signature = crypto.createSign('RSA-SHA256').update(unsigned).sign(creds.private_key, 'base64url');
  const assertion = `${unsigned}.${signature}`;

  const res = await fetch(creds.token_uri || TOKEN_URI, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
    }),
  });
  if (!res.ok) throw new Error('token request failed: ' + (await res.text()));
  return (await res.json()).access_token;
}

module.exports = async (req, res) => {
  try {
    const token = await getAccessToken();
    const range = `${SHEET_NAME}!${CELL}`;
    const base = `https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}/values/${encodeURIComponent(range)}`;

    if (req.method === 'GET') {
      const r = await fetch(base, { headers: { Authorization: `Bearer ${token}` } });
      if (!r.ok) return res.status(502).json({ error: 'sheet read failed: ' + (await r.text()) });
      const data = await r.json();
      const vault = (data.values && data.values[0] && data.values[0][0]) || null;
      return res.status(200).json({ vault });
    }

    if (req.method === 'POST') {
      let body = req.body;
      if (typeof body === 'string') { try { body = JSON.parse(body); } catch { body = null; } }
      if (!body || typeof body.vault !== 'string') {
        return res.status(400).json({ error: 'expected JSON { vault: "<string>" }' });
      }
      const r = await fetch(`${base}?valueInputOption=RAW`, {
        method: 'PUT',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ values: [[body.vault]] }),
      });
      if (!r.ok) return res.status(502).json({ error: 'sheet write failed: ' + (await r.text()) });
      return res.status(200).json({ ok: true });
    }

    return res.status(405).json({ error: 'method not allowed' });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
};
