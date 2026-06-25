'use strict';
require('dotenv').config();
const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');

const { db, seedAdmin } = require('./db');
const { requireAuth, requireAdmin } = require('./auth');

if (!process.env.JWT_SECRET || !process.env.MASTER_KEY) {
  console.error('Missing JWT_SECRET or MASTER_KEY. Copy .env.example to .env and fill them in.');
  process.exit(1);
}

seedAdmin();

const app = express();
app.use(express.json());
app.use(cookieParser());

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
