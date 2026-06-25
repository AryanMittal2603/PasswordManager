'use strict';
const express = require('express');
const bcrypt = require('bcryptjs');
const { db, logAction } = require('../db');
const { requireAuth, requireAdmin, publicUser } = require('../auth');

const router = express.Router();

// All routes here are admin-only.
router.use(requireAuth, requireAdmin);

router.get('/', (req, res) => {
  const users = db.prepare('SELECT * FROM users ORDER BY role DESC, username').all();
  res.json({ users: users.map(publicUser) });
});

router.post('/', (req, res) => {
  const { username, email, password, role } = req.body || {};
  const perms = normalizePerms(req.body);
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  if (String(password).length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  const exists = db.prepare('SELECT 1 FROM users WHERE username = ?').get(username);
  if (exists) return res.status(409).json({ error: 'Username already taken' });

  const isAdmin = role === 'admin';
  const hash = bcrypt.hashSync(password, 12);
  const info = db.prepare(`
    INSERT INTO users (username, email, password_hash, role, can_view, can_create, can_edit, can_delete)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    username, email || '', hash, isAdmin ? 'admin' : 'member',
    isAdmin ? 1 : perms.can_view,
    isAdmin ? 1 : perms.can_create,
    isAdmin ? 1 : perms.can_edit,
    isAdmin ? 1 : perms.can_delete,
  );
  logAction(req.user, 'user_create', username);
  const created = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
  res.status(201).json({ user: publicUser(created) });
});

// Update a member's permissions / active state.
router.patch('/:id', (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.role === 'admin') {
    return res.status(400).json({ error: 'Admin permissions cannot be changed here' });
  }
  const perms = normalizePerms({ ...target, ...req.body });
  const isActive = req.body.is_active === undefined ? target.is_active : (req.body.is_active ? 1 : 0);
  db.prepare(`
    UPDATE users SET can_view=?, can_create=?, can_edit=?, can_delete=?, is_active=? WHERE id=?
  `).run(perms.can_view, perms.can_create, perms.can_edit, perms.can_delete, isActive, target.id);
  logAction(req.user, 'user_update', target.username, JSON.stringify({ ...perms, is_active: isActive }));
  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(target.id);
  res.json({ user: publicUser(updated) });
});

// Admin resets a user's password.
router.post('/:id/reset-password', (req, res) => {
  const { newPassword } = req.body || {};
  if (!newPassword || String(newPassword).length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters' });
  }
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(newPassword, 12), target.id);
  logAction(req.user, 'user_reset_password', target.username);
  res.json({ ok: true });
});

router.delete('/:id', (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.id === req.user.id) {
    return res.status(400).json({ error: 'You cannot delete your own account' });
  }
  if (target.role === 'admin') {
    const admins = db.prepare("SELECT COUNT(*) AS n FROM users WHERE role='admin'").get().n;
    if (admins <= 1) return res.status(400).json({ error: 'Cannot delete the last admin' });
  }
  db.prepare('DELETE FROM users WHERE id = ?').run(target.id);
  logAction(req.user, 'user_delete', target.username);
  res.json({ ok: true });
});

function normalizePerms(src) {
  return {
    can_view: src.can_view ? 1 : 0,
    can_create: src.can_create ? 1 : 0,
    can_edit: src.can_edit ? 1 : 0,
    can_delete: src.can_delete ? 1 : 0,
  };
}

module.exports = router;
