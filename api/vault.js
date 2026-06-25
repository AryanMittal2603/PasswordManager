// Vercel serverless function: shared vault stored as readable Google Sheet columns.
//   "Sheet1" (credentials): ID | Folder | Title | Username | URL | Notes | Password | Updated
//   "Users"  (accounts):    Username | Role | Permissions | Salt | WrappedVK
// Password / WrappedVK cells stay encrypted ("iv:ct"). Uses only Node built-ins.
// Raw Node req/res (no framework helpers) for max runtime compatibility.

const crypto = require('crypto');

const SHEET_ID = process.env.SHEET_ID || '1OT35q7-_izPw5gyuL0VJs6SLiQpuJcTv9ey9yS_G09I';
const CRED_TAB = process.env.SHEET_NAME || 'Sheet1';
const USERS_TAB = 'Users';
const TOKEN_URI = 'https://oauth2.googleapis.com/token';
const PERMS = ['view', 'create', 'edit', 'delete'];
const CRED_HEADERS = ['ID', 'Folder', 'Title', 'Username', 'URL', 'Notes', 'Password', 'Updated'];
const USER_HEADERS = ['Username', 'Role', 'Permissions', 'Salt', 'WrappedVK'];

function send(res, status, obj) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((resolve) => {
    if (req.body !== undefined && req.body !== null) return resolve(req.body);
    let data = '';
    req.on('data', (c) => { data += c; });
    req.on('end', () => resolve(data));
    req.on('error', () => resolve(''));
  });
}

function getCreds() {
  const raw = process.env.GOOGLE_SERVICE_ACCOUNT;
  if (!raw) throw new Error('GOOGLE_SERVICE_ACCOUNT env var is not set');
  const creds = JSON.parse(raw);
  if (creds.private_key && creds.private_key.includes('\\n')) creds.private_key = creds.private_key.replace(/\\n/g, '\n');
  return creds;
}

async function getAccessToken() {
  if (typeof fetch === 'undefined') throw new Error('global fetch unavailable (Node < 18 on Vercel)');
  const creds = getCreds();
  const now = Math.floor(Date.now() / 1000);
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const unsigned = b64({ alg: 'RS256', typ: 'JWT' }) + '.' + b64({
    iss: creds.client_email, scope: 'https://www.googleapis.com/auth/spreadsheets',
    aud: creds.token_uri || TOKEN_URI, iat: now, exp: now + 3600,
  });
  const signature = crypto.createSign('RSA-SHA256').update(unsigned).sign(creds.private_key, 'base64url');
  const res = await fetch(creds.token_uri || TOKEN_URI, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${unsigned}.${signature}` }),
  });
  if (!res.ok) throw new Error('token request failed: ' + (await res.text()));
  return (await res.json()).access_token;
}

const apiUrl = (p) => `https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}${p}`;
async function gget(range, token) {
  const r = await fetch(apiUrl(`/values/${encodeURIComponent(range)}`), { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error('read ' + range + ': ' + (await r.text()));
  return (await r.json()).values || [];
}
async function gclear(range, token) {
  await fetch(apiUrl(`/values/${encodeURIComponent(range)}:clear`), { method: 'POST', headers: { Authorization: `Bearer ${token}` } });
}
async function gupdate(range, values, token) {
  const r = await fetch(apiUrl(`/values/${encodeURIComponent(range)}?valueInputOption=RAW`), {
    method: 'PUT', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ values }),
  });
  if (!r.ok) throw new Error('write ' + range + ': ' + (await r.text()));
}
async function ensureUsersTab(token) {
  const r = await fetch(apiUrl('?fields=sheets.properties.title'), { headers: { Authorization: `Bearer ${token}` } });
  const meta = await r.json();
  const exists = (meta.sheets || []).some((s) => s.properties.title === USERS_TAB);
  if (!exists) {
    await fetch(apiUrl(':batchUpdate'), {
      method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ requests: [{ addSheet: { properties: { title: USERS_TAB } } }] }),
    });
  }
}

const fmtCipher = (c) => (c && c.iv ? `${c.iv}:${c.ct}` : '');
function parseCipher(s) { if (!s) return null; const i = String(s).indexOf(':'); return i < 0 ? null : { iv: s.slice(0, i), ct: s.slice(i + 1) }; }
const fmtPerms = (p) => PERMS.filter((k) => p && p[k]).join(',');
function parsePerms(s) { const set = new Set(String(s || '').split(',').map((x) => x.trim())); return Object.fromEntries(PERMS.map((k) => [k, set.has(k)])); }

module.exports = async (req, res) => {
  try {
    if ((req.url || '').includes('debug')) {
      return send(res, 200, { ok: true, node: process.version, hasFetch: typeof fetch !== 'undefined', hasEnv: !!process.env.GOOGLE_SERVICE_ACCOUNT });
    }

    const token = await getAccessToken();
    await ensureUsersTab(token);

    if (req.method === 'GET') {
      const [credRows, userRows] = await Promise.all([gget(`${CRED_TAB}!A2:H`, token), gget(`${USERS_TAB}!A2:E`, token)]);
      const entries = credRows.filter((r) => r[0]).map((r) => ({
        id: Number(r[0]), folder: r[1] || 'General', title: r[2] || '', username: r[3] || '', url: r[4] || '', notes: r[5] || '', pwd: parseCipher(r[6]),
      }));
      const users = userRows.filter((r) => r[0]).map((r) => ({
        username: r[0], role: r[1] || 'member', perms: parsePerms(r[2]), salt: r[3] || '', wrapped: parseCipher(r[4]),
      }));
      const nextId = entries.reduce((m, e) => Math.max(m, e.id), 0) + 1;
      return send(res, 200, { version: 2, users, entries, nextId });
    }

    if (req.method === 'POST') {
      let doc = await readBody(req);
      if (typeof doc === 'string') { try { doc = JSON.parse(doc); } catch { doc = null; } }
      if (!doc || !Array.isArray(doc.users) || !Array.isArray(doc.entries)) return send(res, 400, { error: 'expected { users:[], entries:[] }' });
      const credRows = doc.entries.map((e) => [e.id, e.folder || 'General', e.title || '', e.username || '', e.url || '', e.notes || '', fmtCipher(e.pwd), e.updated || new Date().toISOString().slice(0, 10)]);
      const userRows = doc.users.map((u) => [u.username, u.role || 'member', fmtPerms(u.perms), u.salt || '', fmtCipher(u.wrapped)]);
      await gclear(`${CRED_TAB}!A:H`, token);
      await gclear(`${USERS_TAB}!A:E`, token);
      await gupdate(`${CRED_TAB}!A1`, [CRED_HEADERS, ...credRows], token);
      await gupdate(`${USERS_TAB}!A1`, [USER_HEADERS, ...userRows], token);
      return send(res, 200, { ok: true });
    }

    return send(res, 405, { error: 'method not allowed' });
  } catch (e) {
    return send(res, 500, { error: (e && e.message) || String(e) });
  }
};
