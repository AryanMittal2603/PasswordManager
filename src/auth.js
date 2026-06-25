'use strict';
const jwt = require('jsonwebtoken');
const { db } = require('./db');

const COOKIE = 'vault_token';

function signToken(user) {
  return jwt.sign({ uid: user.id }, process.env.JWT_SECRET, { expiresIn: '8h' });
}

function setAuthCookie(res, token) {
  res.cookie(COOKIE, token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 8 * 60 * 60 * 1000,
  });
}

function clearAuthCookie(res) {
  res.clearCookie(COOKIE);
}

// Populates req.user from the session cookie, or 401s.
function requireAuth(req, res, next) {
  const token = req.cookies[COOKIE];
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Session expired' });
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.uid);
  if (!user || !user.is_active) {
    return res.status(401).json({ error: 'Account not found or disabled' });
  }
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// Gate a route on a capability flag. Admins always pass.
function requirePerm(flag) {
  return (req, res, next) => {
    if (req.user.role === 'admin' || req.user[flag]) return next();
    return res.status(403).json({ error: `You do not have permission to ${flag.replace('can_', '')}` });
  };
}

// Strip secret fields before sending a user object to the client.
function publicUser(u) {
  return {
    id: u.id,
    username: u.username,
    email: u.email,
    role: u.role,
    can_view: !!u.can_view,
    can_create: !!u.can_create,
    can_edit: !!u.can_edit,
    can_delete: !!u.can_delete,
    is_active: !!u.is_active,
    created_at: u.created_at,
  };
}

module.exports = {
  signToken, setAuthCookie, clearAuthCookie,
  requireAuth, requireAdmin, requirePerm, publicUser,
};
