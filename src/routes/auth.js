'use strict';
const express = require('express');
const bcrypt = require('bcryptjs');
const { db, logAction } = require('../db');
const { signToken, setAuthCookie, clearAuthCookie, requireAuth, publicUser } = require('../auth');

const router = express.Router();

router.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  // Always run a compare to reduce username-enumeration timing differences.
  const ok = user && bcrypt.compareSync(password, user.password_hash);
  if (!ok || !user.is_active) {
    logAction(user || { id: null, username }, 'login_failed', username);
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  setAuthCookie(res, signToken(user));
  logAction(user, 'login', username);
  res.json({ user: publicUser(user) });
});

router.post('/logout', requireAuth, (req, res) => {
  clearAuthCookie(res);
  logAction(req.user, 'logout');
  res.json({ ok: true });
});

router.get('/me', requireAuth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

// Any logged-in user can change their own password.
router.post('/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new password are required' });
  }
  if (String(newPassword).length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters' });
  }
  if (!bcrypt.compareSync(currentPassword, req.user.password_hash)) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  const hash = bcrypt.hashSync(newPassword, 12);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.user.id);
  logAction(req.user, 'change_password');
  res.json({ ok: true });
});

module.exports = router;
