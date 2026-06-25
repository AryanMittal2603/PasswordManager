// Runs the expensive PBKDF2 key derivation off the main thread so it never
// blocks UI updates (keeps INP low). The main thread posts {id, op, args};
// we reply {id, result} or {id, error}.
import * as C from './crypto.js';

self.onmessage = async (e) => {
  const { id, op, args } = e.data;
  try {
    let result;
    if (op === 'wrap') {
      // args: { vk: number[], password } -> { salt, wrapped }
      result = await C.wrapVKForPassword(new Uint8Array(args.vk), args.password);
    } else if (op === 'unwrap') {
      // args: { authEntry, password } -> number[] (VK bytes)
      const vk = await C.unwrapVKWithPassword(args.authEntry, args.password);
      result = Array.from(vk);
    } else {
      throw new Error('Unknown op: ' + op);
    }
    self.postMessage({ id, result });
  } catch (err) {
    self.postMessage({ id, error: err.message || String(err) });
  }
};
