# Team Password Vault — frontend-only (Vercel) version

A **static** password vault: no backend, no server. Everything runs in the browser.
Deploys to Vercel (or any static host) as-is.

## How it works

- The vault is encrypted with a random 256-bit **Vault Key (VK)** using AES-256-GCM.
- Each user's password (via PBKDF2, 250k iterations) derives a key that **wraps a copy of
  the VK** — so every team member unlocks the *same* vault with their *own* password
  (envelope encryption). All crypto uses the browser's built-in Web Crypto API.
- The encrypted vault is stored in the browser (`localStorage`) and can be **exported as a
  file** (`team-vault.json`) — that file *is* your database. Import it on another machine
  or browser to share/restore.

## Roles

- **Admin** (created on first run) manages users and grants each member permissions:
  **view / create / edit / delete**. Members only see and do what they're granted.

## Deploy to Vercel

The repo root [`vercel.json`](../vercel.json) tells Vercel to serve this `web/` folder as a
pure static site (it ignores the backend code). Just connect the GitHub repo to Vercel and
deploy — no environment variables, no build step.

To run locally, serve this folder with any static server, e.g.:

```bash
npx serve web
```

> Note: open it over `http://localhost` or `https://` — the Web Crypto API requires a
> secure context (it won't work from a `file://` URL).

## ⚠️ Important limitations (because there is no backend)

1. **Permissions are enforced in the UI, not cryptographically.** Anyone who can unlock the
   vault could, with effort, read all entries via browser devtools. For hard, server-enforced
   access control, use the backend version in the parent folder.
2. **No automatic sync.** Each browser holds its own copy. After adding/changing users or
   entries, use **⬇ Export** and share the file so teammates **Import** the latest version.
3. **No password recovery.** If the admin password is lost and no other admin exists, the
   vault cannot be decrypted. Keep a backup of the exported file and your password.
