'use strict';
require('dotenv').config();
const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const { db, seedAdmin } = require('./db');
const { requireAuth, requireAdmin } = require('./auth');

if (!process.env.JWT_SECRET || !process.env.MASTER_KEY) {
  console.error('Missing JWT_SECRET or MASTER_KEY. Copy .env.example to .env and fill them in.');
  process.exit(1);
}

seedAdmin();

const app = express();

// Behind a reverse proxy (Caddy/nginx/PaaS), trust it so `secure` cookies and
// client IPs (for rate limiting) work. Enable only in production.
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

// Security headers. The UI is self-hosted with no inline scripts, so a strict CSP is fine.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"],
    },
  },
}));

app.use(express.json({ limit: '64kb' }));
app.use(cookieParser());

// Coarse global limit on the API to blunt abuse/scraping (login has a stricter one).
app.use('/api', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
}));

app.use('/api/auth', require('./routes/auth'));
app.use('/api/users', require('./routes/users'));
app.use('/api/credentials', require('./routes/credentials'));

// Admin-only audit log.
app.get('/api/audit', requireAuth, requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT 200').all();
  res.json({ events: rows });
});

app.use(express.static(path.join(__dirname, '..', 'public')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n  Team Password Vault running at http://localhost:${PORT}\n`);
});
