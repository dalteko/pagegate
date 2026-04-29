# PageGate

Password-protected HTML page sharing in three tiers — anonymous, free account, and Pro. See [`docs/TIERS.md`](docs/TIERS.md) for the full per-tier rules and [`docs/PRD.md`](docs/PRD.md) for the why.

**Live at [pagegate.app](https://pagegate.app)**

## How it works

1. Drop in an `.html` file (or paste HTML), set a password
2. Get a shareable link (e.g. `pagegate.app/Ab3xK9mz`)
3. Anyone with the link enters the password to view the page
4. Pages auto-expire — 24 hours for anonymous, 7 days for free accounts, configurable for Pro

| | Anonymous | Free account | Pro ($5/mo) |
|---|---|---|---|
| Account required | No | Yes | Yes |
| Expiry | 24 hours | 7 days | Custom (up to forever) |
| Active links | Unlimited (ephemeral) | 3 | 100 |
| View cap | 300 (fixed) | 1,000 (fixed) | Custom per link |
| Custom slugs (`/my-landing-page`) | — | — | ✓ |
| Public pages (no password) | — | — | ✓ |
| Edit-in-place (HTML / password / expiry / slug) | — | — | ✓ |
| Server-side password reset | — | ✓ | ✓ |
| Dashboard with view counts | — | ✓ | ✓ |

## Security & privacy — read this carefully

PageGate runs **two distinct encryption paths** by tier. The trade-off is intentional and called out in the privacy policy.

- **Anonymous uploads are end-to-end encrypted.** The AES-256-GCM key is derived from the page password via PBKDF2 (100k iterations). The password is bcrypt-hashed for verification, but never stored in any reversible form. We genuinely cannot read your content. Forgotten password = unrecoverable, by design.
- **Account uploads (free or Pro) are encrypted at rest with a server-held master key.** A random per-page key is generated, wrapped with the `PAGE_KEY_MASTER` env var, and stored in the database. This is what makes account-driven password reset and Pro edit-in-place possible. The honest trade-off: the operator could decrypt account content with the master key, where the anonymous tier they cannot.

Other security properties — uniform across tiers:

- **Sandboxed rendering** — Unlocked pages render in a sandboxed iframe (`sandbox="allow-scripts allow-forms allow-popups"`, no `allow-same-origin`). Uploaded HTML cannot access PageGate's cookies, localStorage, or API endpoints.
- **Password hashing** — All page passwords are bcrypt-hashed (10 salt rounds) for verification. Anonymous pages additionally derive their encryption key from the password.
- **Rate limiting** — 10 password attempts per IP per page per hour.
- **Auto-expiration** — Expired pages are removed from both the database and disk every 24 hours.
- **Per-page view cap** — Pages lock once they hit their view limit (300 anonymous, 1,000 free, configurable for Pro). Same UX as expiry, distinct copy.

## Tech stack

- **Backend:** Node.js + Express
- **Database:** SQLite (better-sqlite3) with WAL mode
- **Storage:** Encrypted files on disk (AES-256-GCM)
- **Auth:** Clerk for accounts, bcrypt for page passwords, PBKDF2 / master-key wrap for content encryption
- **Billing:** Stripe (Pro subscriptions, Customer Portal for management)
- **Frontend:** Vanilla HTML/CSS/JS (no framework)
- **Analytics:** Plausible (privacy-friendly, no cookies, site-only — never on uploaded pages)
- **Hosting:** Railway

## Project structure

```
├── docs/
│   ├── PRD.md          # Product requirements (tiered plans rollout)
│   └── TIERS.md        # Tier specification (read this first)
├── server/
│   ├── index.js        # Express app, routes, cleanup + grace-enforcement schedulers
│   ├── db.js           # SQLite schema, queries, additive migrations
│   ├── storage.js      # File I/O for page blobs (no crypto)
│   ├── crypto.js       # AES-256-GCM, both password-derived and master-key paths
│   ├── tiers.js        # Tier rules registry (single source of truth)
│   └── config.js       # Env-var validation
├── public/
│   ├── index.html      # Upload page
│   ├── dashboard.html  # Account / Pro dashboard
│   ├── view.html       # Password prompt + sandboxed content frame
│   ├── app.js          # Upload logic, drag-drop, auth UI
│   └── style.css       # Styles
├── test/
│   ├── crypto.js       # Round-trip tests for both crypto paths
│   └── smoke.js        # End-to-end server smoke test
├── data/               # SQLite database (gitignored)
└── uploads/            # Encrypted page files (gitignored)
```

## API

### `POST /api/upload`

Upload an HTML file with a password.

- **Body** (`multipart/form-data`):
  - `file` — `.html`, max 10 MB
  - `password` — required unless `isPublic=true` (Pro only)
  - `confirmPassword` — optional but recommended; server validates it matches if supplied
  - `slug` — optional, Pro only. Strict regex per `tiers.PRO_SLUG_REGEX`
  - `expiration` — optional, Pro only: `7`, `30`, `90`, `365`, or `never`
  - `isPublic` — optional, Pro only: `true` to skip the password gate
  - `viewCap` — optional, Pro only: positive integer (defaults to 1,000 for Pro)
- **Response:** `{ pageId, url, expiresAt, slug }`

### `POST /api/verify/:pageId`

Verify a password and retrieve the decrypted HTML. For public Pro pages, password is not required.

- **Body:** `{ "password": "..." }` (omit for public pages)
- **Response:** `{ html }` on success
- **Errors:** `401` wrong password, `404` not found/expired, `410` view limit reached, `429` rate limited

### `GET /api/pages` (signed-in)

List the calling user's pages. Response includes `viewCount`, `viewCap`, `isPublic`, per-action capability flags (`canDelete`, `canEdit`, `passwordResettable`), and the grace-period `keptAfterGrace` flag.

### `PATCH /api/pages/:pageId` (Pro)

Edit-in-place: replace HTML, change slug / expiration / `isPublic` / `viewCap`. Multipart, all fields optional.

### `POST /api/pages/:pageId/password/reset` (signed-in)

Reset the page password without supplying the old one. Wrapped-key pages only (account/Pro). Anonymous pages return 400 with `reason: 'not_resettable'`.

### `POST /api/pages/:pageId/keep` (Pro / grace)

Mark a page to survive Pro-downgrade enforcement. Body: `{ "keep": boolean }`.

### `DELETE /api/pages/:pageId` (Pro)

Permanently delete a page. Tier 2 cannot delete by spec — must wait for expiry.

### `GET /:pageIdOrSlug`

Serves the password prompt (`view.html`) with SSR-injected page metadata so public pages auto-unlock and Pro pages hide the "Hosted on PageGate" footer.

## Running locally

```bash
git clone https://github.com/dalteko/pagegate.git
cd pagegate
npm install
npm test       # crypto round-trip + server smoke
npm start      # → http://localhost:3457
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3457` | Server port |
| `BASE_URL` | _(auto-detected)_ | Public URL for link generation (e.g. `https://pagegate.app`) |
| `DATA_DIR` | `./data` | SQLite database directory |
| `UPLOADS_DIR` | `./uploads` | Encrypted file storage directory |
| `PRO_ENABLED` | `false` | Enables Clerk auth, Stripe billing, account/Pro tiers. Set to `true` only when the required vars below are configured. |
| `CLERK_PUBLISHABLE_KEY` | _(required when Pro is enabled)_ | Clerk browser publishable key |
| `CLERK_SECRET_KEY` | _(required when Pro is enabled)_ | Clerk backend secret key |
| `STRIPE_SECRET_KEY` | _(required when Pro is enabled)_ | Stripe secret API key |
| `STRIPE_WEBHOOK_SECRET` | _(required when Pro is enabled)_ | Stripe webhook signing secret |
| `STRIPE_PRICE_ID` | _(required when Pro is enabled)_ | Stripe recurring price ID for the Pro plan |
| `PAGE_KEY_MASTER` | _(required when Pro is enabled)_ | 32-byte server master key (64 hex chars or 44 base64 chars). Wraps per-page encryption keys for account/Pro tiers so server-side password reset works. Generate: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`. **Rotate carefully — losing this key makes all account/Pro pages unreadable.** |

When `PRO_ENABLED` is not `true`, PageGate runs in anonymous-only mode: uploads still work, but accounts, billing, dashboard, and the master-key crypto path are disabled. When `PRO_ENABLED=true`, the server validates the required vars at startup and refuses to serve traffic if any are missing.

## Analytics events (Plausible)

| Event | Properties | Description |
|---|---|---|
| `Upload` | `filename`, `size` | A page was uploaded |
| `Unlock` | `page` | A page was successfully unlocked |
| `Unlock Failed` | `page`, `reason` | `wrong_password`, `expired`, `view_cap`, `rate_limited` |

## License

MIT
