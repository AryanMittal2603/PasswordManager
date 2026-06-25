# Team Password Vault

A self-hosted team password repository with role-based access control. Built with
Node.js + Express + SQLite. Stored passwords are encrypted at rest with AES-256-GCM.

## Features

- **1 admin + many members.** The admin manages accounts and grants access.
- **Per-user permissions** the admin controls: **view**, **create**, **edit**, **delete**.
- **Encryption at rest.** Every stored password is AES-256-GCM encrypted with a server
  master key; the SQLite file never holds plaintext passwords.
- **Audit log.** Logins, password reveals, and every create/edit/delete are recorded.
- **Sessions** via bcrypt-hashed login passwords + signed httpOnly cookies (8h expiry).
- Clean web UI — vault, user management, and audit views.

## Quick start

```bash
npm install
npm start
```

Open http://localhost:3000 and log in as `admin` with the `ADMIN_PASSWORD` from your
`.env`. **Change that password immediately** via the "Change password" button.

> Secrets in `.env` (`MASTER_KEY`, `JWT_SECRET`, `ADMIN_PASSWORD`) were auto-generated
> on setup. To run elsewhere, copy `.env.example` to `.env` and generate keys with
> `openssl rand -hex 32`.

## Deploy with Docker (recommended for production)

The image runs as a non-root user with `NODE_ENV=production` and persists the
database in a named volume.

```bash
# 1. Ensure .env exists with real secrets (see .env.example).
# 2. Build and run:
docker compose up -d --build
```

The app listens on port 3000. **Put a reverse proxy with HTTPS in front of it**
(e.g. Caddy, which auto-provisions Let's Encrypt certs) — never expose the raw
HTTP port to the internet. Example Caddyfile:

```
vault.yourdomain.com {
    reverse_proxy localhost:3000
}
```

To back up, copy the volume's `vault.db` and store your `MASTER_KEY` separately.

## Production hardening (built in)

- **Login rate limiting** — 10 attempts per IP per 15 min, then `429`.
- **Global API rate limiting** — 300 requests per IP per 15 min.
- **Security headers** via Helmet — strict Content-Security-Policy, HSTS,
  `X-Frame-Options`, etc.
- **`trust proxy`** enabled under `NODE_ENV=production` so `secure` cookies and
  per-client rate limiting work correctly behind a reverse proxy.

## How permissions work

| Role     | Capabilities                                                              |
|----------|--------------------------------------------------------------------------|
| `admin`  | Full access. Manages users, grants/revokes permissions, sees audit log.  |
| `member` | Exactly the capabilities the admin toggles: view / create / edit / delete.|

The admin adds users under the **Users** tab, sets each one's permission checkboxes,
and can disable, delete, or reset passwords for any member. Members only see the
**Vault** tab and can do only what they've been granted. Revealing a password is
logged as an access event.

## Security notes

- **`MASTER_KEY` is the crown jewel.** If you lose it, all stored passwords are
  unrecoverable. If it leaks, anyone with the DB file can decrypt everything. Back it
  up somewhere safe and separate from the database.
- `.env` and `data/*.db` are gitignored — never commit them.
- This uses **server-side encryption** (the server can decrypt). That's appropriate for
  a trusted internal tool. It is not zero-knowledge/end-to-end encrypted.
- **Before exposing this to the internet:** put it behind HTTPS (set `NODE_ENV=production`
  so cookies are sent `secure`), add rate limiting on `/api/auth/login`, take regular
  encrypted DB backups, and consider per-folder access scoping if teams need isolation.

## Project layout

```
src/
  server.js              app wiring + audit endpoint
  db.js                  SQLite schema, admin seeding, audit logging
  crypto.js              AES-256-GCM encrypt/decrypt
  auth.js                JWT cookies + requireAuth / requireAdmin / requirePerm
  routes/auth.js         login, logout, me, change-password
  routes/users.js        admin user + permission management
  routes/credentials.js  vault CRUD + reveal (permission-gated)
public/                  single-page web UI (index.html, app.js, style.css)
data/vault.db            SQLite database (gitignored)
```

## API summary

| Method | Path                            | Permission        |
|--------|---------------------------------|-------------------|
| POST   | `/api/auth/login`               | public            |
| POST   | `/api/auth/logout`              | authenticated     |
| GET    | `/api/auth/me`                  | authenticated     |
| POST   | `/api/auth/change-password`     | authenticated     |
| GET    | `/api/credentials`              | `view`            |
| GET    | `/api/credentials/:id/reveal`   | `view`            |
| POST   | `/api/credentials`              | `create`          |
| PUT    | `/api/credentials/:id`          | `edit`            |
| DELETE | `/api/credentials/:id`          | `delete`          |
| GET    | `/api/users`                    | admin             |
| POST   | `/api/users`                    | admin             |
| PATCH  | `/api/users/:id`                | admin             |
| POST   | `/api/users/:id/reset-password` | admin             |
| DELETE | `/api/users/:id`                | admin             |
| GET    | `/api/audit`                    | admin             |
