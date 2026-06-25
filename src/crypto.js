'use strict';
const crypto = require('crypto');

const ALGO = 'aes-256-gcm';

function getKey() {
  const hex = process.env.MASTER_KEY;
  if (!hex || hex.length !== 64) {
    throw new Error('MASTER_KEY must be a 64-char (32-byte) hex string. See .env.example.');
  }
  return Buffer.from(hex, 'hex');
}

// Encrypts a UTF-8 string. Returns { ciphertext, iv, tag } as base64 strings.
function encrypt(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, getKey(), iv);
  const ct = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  return {
    ciphertext: ct.toString('base64'),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
  };
}

// Reverses encrypt(). Throws if the data was tampered with (GCM auth tag check).
function decrypt({ ciphertext, iv, tag }) {
  const decipher = crypto.createDecipheriv(ALGO, getKey(), Buffer.from(iv, 'base64'));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  const pt = Buffer.concat([
    decipher.update(Buffer.from(ciphertext, 'base64')),
    decipher.final(),
  ]);
  return pt.toString('utf8');
}

module.exports = { encrypt, decrypt };
