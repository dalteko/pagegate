# PageGate

Password-protected HTML page sharing. Upload an HTML file, set a password, get a shareable link that expires in 30 days.

**Live at [pagegate.app](https://pagegate.app)**

## How it works

1. Upload an `.html` file and set a password
2. Get a shareable link (e.g. `pagegate.app/Ab3xK9mz`)
3. Anyone with the link enters the password to view the page
4. Page auto-expires after 30 days

## Security

- **Encryption at rest** — Files are encrypted on disk with AES-256-GCM. The encryption key is derived from the user's password via PBKDF2 (100k iterations). The server cannot read uploaded content without the password.
- **Sandboxed rendering** — Unlocked pages render in a sandboxed iframe (`sandbox="allow-scripts allow-forms allow-popups"`, no `allow-same-origin`). Uploaded HTML cannot access PageGate's cookies, localStorage, or API endpoints.
- **Password hashing** — Passwords are hashed with bcrypt (10 salt rounds) for verification. The hash and encryption key are derived independently.
- **Rate limiting** — 10 password attempts per IP per page per hour.
- **Auto-expiration** — Expired pages are deleted from both the database and disk every 24 hours.
- **No tracking of content** — PageGate has no way to read what users upload. Passwords are not stored.

## Tech stack

- **Backend:** Node.js + Express
- **Database:** SQLite (better-sqlite3) with WAL mode
- **Storage:** Encrypted files on disk (AES-256-GCM)
- **Auth:** bcrypt for password verification, PBKDF2 for encryption key derivation
- **Frontend:** Vanilla HTML/CSS/JS (no framework)
- **Analytics:** Plausible (privacy-friendly, no cookies)
- **Hosting:** Railway

## Project structure

```
├── docs/
│   ├── PRD.md          # Product requirements (tiered plans rollout)
│   └── TIERS.md        # Tier specification (read this first)
├── server/
│   ├── index.js        # Express app, API routes, cleanup scheduler
│   ├── db.js           # SQLite schema, queries, migrations
│   ├── storage.js      # File I/O for page blobs (no crypto)
│   ├── crypto.js       # AES-256-GCM, both password-derived and master-key paths
│   └── tiers.js        # Tier rules registry (single source of truth)
├── public/
│   ├── index.html      # Upload page
│   ├── view.html       # Password prompt + sandboxed content frame
│   ├── app.js          # Upload logic, history, drag-drop
│   └── style.css       # Styles
├── data/               # SQLite database (gitignored)
└── uploads/            # Encrypted page files (gitignored)
```

## API

### `POST /api/upload`

Upload an HTML file with a password.

- **Body:** `multipart/form-data` with `file` (.html, max 10MB — see `server/tiers.js`) and `password`
- **Response:** `{ pageId, url, expiresAt }`

### `POST /api/verify/:pageId`

Verify a password and retrieve the decrypted HTML.

- **Body:** `{ "password": "..." }`
- **Response:** `{ html }` on success
- **Errors:** `401` wrong password, `404` not found/expired, `429` rate limited

### `GET /:pageId`

Serves the password prompt page (`view.html`).

## Running locally

```bash
git clone https://github.com/dalteko/pagegate.git
cd pagegate
npm install
npm start
# → http://localhost:3457
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3457` | Server port |
| `BASE_URL` | _(auto-detected)_ | Public URL for link generation (e.g. `https://pagegate.app`) |
| `DATA_DIR` | `./data` | SQLite database directory |
| `UPLOADS_DIR` | `./uploads` | Encrypted file storage directory |
| `PRO_ENABLED` | `false` | Enables Clerk auth, Stripe billing, custom URLs, custom expiration, and the Pro dashboard. Set to `true` only when the required Pro variables below are configured. |
| `CLERK_PUBLISHABLE_KEY` | _(required when Pro is enabled)_ | Clerk browser publishable key |
| `CLERK_SECRET_KEY` | _(required when Pro is enabled)_ | Clerk backend secret key |
| `STRIPE_SECRET_KEY` | _(required when Pro is enabled)_ | Stripe secret API key |
| `STRIPE_WEBHOOK_SECRET` | _(required when Pro is enabled)_ | Stripe webhook signing secret |
| `STRIPE_PRICE_ID` | _(required when Pro is enabled)_ | Stripe recurring price ID for the Pro plan |
| `PAGE_KEY_MASTER` | _(required when Pro is enabled)_ | 32-byte server master key (64 hex chars or 44 base64 chars). Wraps per-page encryption keys for account/Pro tiers so server-side password reset works. Generate: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`. **Rotate carefully — losing this key makes all account/Pro pages unreadable.** |

When `PRO_ENABLED` is not `true`, PageGate runs in free mode: uploads still work, but Clerk auth, Stripe billing, custom URLs, custom expiration, and dashboard APIs are disabled. When `PRO_ENABLED=true`, the server validates the required Pro variables at startup and exits before serving traffic if any are missing.

## Analytics events (Plausible)

| Event | Properties | Description |
|---|---|---|
| `Upload` | `filename`, `size` | A page was uploaded |
| `Unlock` | `page` | A page was successfully unlocked |
| `Unlock Failed` | `page`, `reason` | Password attempt failed (`wrong_password`, `expired`, `rate_limited`) |

## License

MIT
