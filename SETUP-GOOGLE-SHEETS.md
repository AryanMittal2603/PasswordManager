# Shared vault via Google Sheets — setup

The vault is stored (encrypted) in one cell of a Google Sheet so the whole team
shares it: the admin creates it once, everyone else just logs in. The browser
encrypts before sending, so the Sheet only ever holds ciphertext.

```
Browser (encrypts)  ──►  /api/vault (Vercel function, holds the key)  ──►  Google Sheet cell A1
```

## One-time setup

### 1. Rotate the leaked key ⚠️
The key shared in chat is compromised. In **Google Cloud Console → IAM & Admin →
Service Accounts**, delete the old key and create a **new** one (ideally on a
*dedicated* service account, not the Compute Engine default).

### 2. Enable the API + share the Sheet
- Enable **Google Sheets API** for the project (APIs & Services → Library).
- Open the Sheet → **Share** → add the service-account email
  (`...@developer.gserviceaccount.com` / your new SA) as **Editor**.

### 3. Set the Vercel environment variable
In **Vercel → Project → Settings → Environment Variables** add:

| Name                     | Value                                              |
|--------------------------|----------------------------------------------------|
| `GOOGLE_SERVICE_ACCOUNT` | the **entire** service-account JSON (paste it all) |
| `SHEET_ID`               | `1OT35q7-_izPw5gyuL0VJs6SLiQpuJcTv9ey9yS_G09I` *(optional; this is the default)* |
| `SHEET_NAME`             | `Sheet1` *(optional; default)*                     |

Redeploy after adding them.

### 4. Use it
Open the site → **Create your vault** (admin) → add team members. Everyone else
opens the same URL and logs in; they automatically receive the shared vault.
The header shows **☁ synced** when changes have been saved to the Sheet.

## Notes & limits
- **Zero-knowledge:** Google / the service account never see plaintext — only the
  encrypted blob. Losing the admin password still means losing the vault.
- **Concurrency:** simple last-write-wins. Fine for a small team; simultaneous
  edits by two people can overwrite each other. Use **⬇ Export** for backups.
- **Cell size:** a Google Sheets cell holds ~50,000 characters, which is plenty
  for hundreds of entries. Very large vaults would need splitting across cells.
- **Local dev:** run `vercel dev` (so `/api/vault` works) with the same env vars
  in a local `.env`. Without the function, the app falls back to local-only.
