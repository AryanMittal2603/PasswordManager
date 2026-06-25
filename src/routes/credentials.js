'use strict';
const express = require('express');
const { db, logAction } = require('../db');
const { requireAuth, requirePerm } = require('../auth');
const { encrypt, decrypt } = require('../crypto');

const router = express.Router();
router.use(requireAuth);

// List entries (metadata only — never includes the password).
router.get('/', requirePerm('can_view'), (req, res) => {
  const rows = db.prepare(`
    SELECT id, title, folder, username, url, notes, created_at, updated_at
    FROM credentials ORDER BY folder, title
  `).all();
  res.json({ credentials: rows });
});

// Reveal a single password. Logged as an access event for the audit trail.
router.get('/:id/reveal', requirePerm('can_view'), (req, res) => {
  const row = db.prepare('SELECT * FROM credentials WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  let password;
  try {
    password = decrypt({ ciphertext: row.pw_ciphertext, iv: row.pw_iv, tag: row.pw_tag });
  } catch {
    return res.status(500).json({ error: 'Failed to decrypt (wrong MASTER_KEY or corrupted data)' });
  }
  logAction(req.user, 'credential_reveal', row.title);
  res.json({ password });
});

router.post('/', requirePerm('can_create'), (req, res) => {
  const { title, folder, username, url, notes, password } = req.body || {};
  if (!title || password === undefined || password === '') {
    return res.status(400).json({ error: 'Title and password are required' });
  }
  const enc = encrypt(password);
  const info = db.prepare(`
    INSERT INTO credentials (title, folder, username, url, notes, pw_ciphertext, pw_iv, pw_tag, created_by, updated_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(title, folder || 'General', username || '', url || '', notes || '',
         enc.ciphertext, enc.iv, enc.tag, req.user.id, req.user.id);
  logAction(req.user, 'credential_create', title);
  res.status(201).json({ id: info.lastInsertRowid });
});

router.put('/:id', requirePerm('can_edit'), (req, res) => {
  const row = db.prepare('SELECT * FROM credentials WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  const { title, folder, username, url, notes, password } = req.body || {};

  // Only re-encrypt if a new password was supplied; otherwise keep the existing one.
  let enc = { ciphertext: row.pw_ciphertext, iv: row.pw_iv, tag: row.pw_tag };
  if (password) enc = encrypt(password);

  db.prepare(`
    UPDATE credentials SET title=?, folder=?, username=?, url=?, notes=?,
      pw_ciphertext=?, pw_iv=?, pw_tag=?, updated_by=?, updated_at=datetime('now')
    WHERE id=?
  `).run(
    title ?? row.title, folder ?? row.folder, username ?? row.username,
    url ?? row.url, notes ?? row.notes, enc.ciphertext, enc.iv, enc.tag, req.user.id, row.id
  );
  logAction(req.user, 'credential_update', title ?? row.title);
  res.json({ ok: true });
});

router.delete('/:id', requirePerm('can_delete'), (req, res) => {
  const row = db.prepare('SELECT * FROM credentials WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  db.prepare('DELETE FROM credentials WHERE id = ?').run(row.id);
  logAction(req.user, 'credential_delete', row.title);
  res.json({ ok: true });
});

module.exports = router;
