# PageGate Tiers

Three tiers, with privacy and permanence as the main axes.

| | Tier 1 — Free anonymous | Tier 2 — Free account | Tier 3 — Pro ($5/mo) |
|---|---|---|---|
| Account required | No | Yes | Yes |
| Expiry | 1 day (fixed) | 7 days (fixed) | Custom, up to forever |
| Max links | Unlimited create, but ephemeral | 3 (cannot delete) | 100 |
| Custom slugs | No (random) | No (random) | Yes |
| Public (no password) pages | Yes | Yes | Yes |
| See link in dashboard | No (shown once at upload) | Yes | Yes |
| Reset page password | No | Yes (no old password needed) | Yes (no old password needed) |
| Edit HTML / expiry / slug after upload | No | No | Yes |
| Per-page analytics (total views) | No | No | Yes |
| "Made with PageGate" footer | Shown | Shown | Hidden |
| File size limit | 10 MB | 10 MB | 10 MB |

10 MB is a flat cap for everyone — rich HTML pages are almost always well under 1 MB, and the only way to exceed 10 MB is base64-embedding heavy media, which is an anti-pattern. Not worth gating.

---

## Tier 1 — Free, anonymous

The "fire and forget" tier. Designed for one-off shares.

- Upload flow: pick file → optionally set password → confirm password if set → receive link → done.
- Once the upload screen is dismissed, the link is not shown again. No history, no recovery.
- Password-protected anonymous pages use password-derived encryption. The password is never stored (only its bcrypt hash and the PBKDF2 salt are stored). If the user forgets it, the page is unrecoverable — by design.
- No-password anonymous pages use the server-wrapped key path because there is no password to derive a key from.
- Page expires 24h after upload.
- Random slug only.
- "Made with PageGate" footer shown.
- Spam: monitor for abuse; add per-IP creation cap reactively if it shows up.

## Tier 2 — Free, account

The "I want to keep track of what I shared" tier.

- Clerk account required.
- Dashboard shows: link URL, expiry, view count. **Password is never shown** (not stored in any retrievable form).
- Password reset: account holder can reset the password from the dashboard without knowing the old one. The page key stays server-wrapped; the server rotates the bcrypt password hash. (See [Crypto model](#crypto-model).)
- Hard cap of 3 links. At 3, must wait for one to expire (7-day max) before creating another. Cannot manually delete.
- Password is optional; public pages skip the password prompt but remain encrypted at rest.
- Random slug only. No edit-in-place. No analytics beyond the dashboard view count.
- "Made with PageGate" footer shown.

## Tier 3 — Pro

Everything Tier 2 has, plus:

- **Custom expiry**: preset durations, including no expiry ("forever").
- **100 links** total.
- **Custom slugs**: must be 3+ hyphenated word groups, each ≥2 chars, lowercase alphanumeric only, total length ≤60. Example: `kevins-landing-page`. Regex: `^[a-z0-9]{2,}(-[a-z0-9]{2,}){2,}$`. First-come-first-served — no squatting protection.
- **Reserved namespace** (cannot be claimed): `/api`, `/login`, `/sign-in`, `/sign-up`, `/dashboard`, `/pricing`, `/account`, `/settings`, `/admin`, `/health`, `/webhook`, `/privacy`, `/terms`, `/favicon`, `/style`, `/app`. Extend as new routes are added.
- **Public pages**: option to skip the password entirely. Page is just a link, anyone with the URL can view. Server-held key.
- **Edit-in-place**: replace HTML, change password, change expiry, change slug after upload.
- **Analytics**: total view count per page, visible in the dashboard. No referrers, no geography, no unique-visitor tracking.
- **Pro footer**: no "Made with PageGate" branding on the unlock or content frame.

---

## Cross-tier rules

### Anonymous → account upgrade
Tier 1 links are orphaned. They do not migrate to a new account, even if created from the same browser/IP. (Consistent with the "complete forgetfulness" promise.)

### Pro downgrade (subscription lapses)

**Day 0–30 — full grace period.** All Pro links stay fully live and editable. Custom slugs, public pages, and custom expirations keep working. Dashboard shows a banner: "Your Pro lapsed. Renew, or pick 3 links to keep before [date]." User can pick which 3 to keep at any point during grace.

**Day 30 — Tier 2 enforced.**
- 3 surviving links: user-picked, or auto-picked by most-recently-viewed if user ignored the banner.
- Custom slugs on surviving links released → replaced with random IDs.
- Public/password state is preserved on surviving links.
- All other links permanently deleted.
- Surviving links inherit Tier 2 rules going forward (7-day clock starts at cutoff).

### Slug collisions
First-come-first-served. No reservation/squatting protection.

---

## Crypto model

| Tier | Server can decrypt stored content without the page password? | Mechanism |
|---|---|---|
| Tier 1 with password | **No** | AES key derived from page password via PBKDF2; password never stored. Forgotten = lost. |
| Tier 1 without password | **Yes** | No password exists, so PageGate uses the server-wrapped key path and skips the password prompt. |
| Tier 2 | **Yes** (UX-gated) | Page key is server-held (encrypted at rest with a server master key). Password is bcrypt-verified to gate access; reset works without old password. |
| Tier 3 | **Yes** (UX-gated) | Same as Tier 2 for password-protected pages. Public pages have no password gate at all. |

A previous README claim ("the server cannot read uploaded content without the password") is only true for Tier 1. Marketing/README copy needs to be honest:

> *"Anonymous stored pages use password-derived encryption — without the page password, they cannot be recovered. Account uploads are encrypted at rest with a server-wrapped page key, which enables dashboard recovery and password reset but is not zero-knowledge."*

---

## Implementation notes (pointers, not full design)

- Existing schema has `users.is_pro` and Stripe wiring (`STRIPE_PRICE_ID`, `stripe_events` table). Pro plumbing is mostly there; needs Tier 2 limits + Tier 1 anonymous polish layered on top.
- New schema fields likely needed on `pages`: `owner_clerk_id` (nullable for Tier 1), `slug` (separate column, distinct from random `pageId`), `is_public`, `display_name`, `view_count`, `tier_at_creation`, `archived_at`, `expires_at` (nullable for Pro "forever"). `view_cap` may remain as a legacy column for old databases but is not enforced.
- Server master key: env var (e.g. `PAGE_KEY_MASTER`). Per-page wrapped key stored in DB for Tier 2/3.
- Slug validation: regex above + reserved-namespace denylist + total length ≤60.
- Anonymous upload: confirm-password input, validated client-side and server-side.
