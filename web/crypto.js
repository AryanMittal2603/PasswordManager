// Pure Web Crypto helpers — no DOM, so they run in both the browser and Node (for tests).
// Design: a random 256-bit Vault Key (VK) encrypts the vault contents. Each user's
// password (via PBKDF2) derives a key that *wraps* (encrypts) a copy of the VK. So every
// user unlocks the same vault with their own password — classic envelope encryption.

const enc = new TextEncoder();
const dec = new TextDecoder();

export const PBKDF2_ITERATIONS = 250000;

export function b64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
export function unb64(s) {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}
export function randomBytes(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return a;
}

// Derive an AES-GCM key from a password + salt.
export async function deriveKey(password, saltBytes, iterations = PBKDF2_ITERATIONS) {
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function aesEncrypt(key, dataBytes) {
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, dataBytes);
  return { iv: b64(iv), ct: b64(ct) };
}
export async function aesDecrypt(key, blob) {
  const out = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(blob.iv) }, key, unb64(blob.ct));
  return new Uint8Array(out);
}

export async function encryptJSON(key, obj) {
  return aesEncrypt(key, enc.encode(JSON.stringify(obj)));
}
export async function decryptJSON(key, blob) {
  return JSON.parse(dec.decode(await aesDecrypt(key, blob)));
}

// Import the raw 32-byte Vault Key as an AES-GCM CryptoKey.
export async function importVK(vkBytes) {
  return crypto.subtle.importKey('raw', vkBytes, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

// Wrap the VK for a user: returns { salt, wrapped:{iv,ct} } to store in plaintext metadata.
export async function wrapVKForPassword(vkBytes, password) {
  const salt = randomBytes(16);
  const userKey = await deriveKey(password, salt);
  const wrapped = await aesEncrypt(userKey, vkBytes);
  return { salt: b64(salt), wrapped };
}

// Unwrap the VK using a password. Throws if the password is wrong (GCM auth failure).
export async function unwrapVKWithPassword(authEntry, password) {
  const userKey = await deriveKey(password, unb64(authEntry.salt));
  return aesDecrypt(userKey, authEntry.wrapped); // -> vkBytes (Uint8Array)
}

// Strong random password generator.
export function generatePassword(length = 20) {
  const sets = {
    lower: 'abcdefghijkmnpqrstuvwxyz',
    upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
    digit: '23456789',
    sym: '!@#$%^&*()-_=+[]{}',
  };
  const all = Object.values(sets).join('');
  const pick = (set) => set[randomBytes(1)[0] % set.length];
  // Guarantee at least one of each class, then fill the rest.
  const out = [pick(sets.lower), pick(sets.upper), pick(sets.digit), pick(sets.sym)];
  while (out.length < length) out.push(pick(all));
  // Fisher–Yates shuffle with crypto randomness.
  for (let i = out.length - 1; i > 0; i--) {
    const j = randomBytes(1)[0] % (i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out.join('');
}
