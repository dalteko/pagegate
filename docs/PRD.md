# PageGate PRD — Tiered Plans & Account Experience

**Status:** Draft
**Owner:** Kevin Ryu
**Last updated:** 2026-04-28

---

## Summary

PageGate is currently a single-mode product: upload an HTML file, set a password, get a 30-day link. Stripe and Clerk are plumbed in, but there's no functional difference between a paying user and an anonymous one. This PRD introduces a three-tier plan structure (anonymous, free account, Pro) so the product can serve distinct use cases — one-off shares, light persistent use, and power use — and so the existing $5/mo Pro plan has something to actually unlock.

The full tier specification lives in [TIERS.md](./TIERS.md). This document covers the *why*, scoping, phasing, and success measures.

---

## Problem

Today PageGate treats every user the same: 30-day expiry, password-required, no dashboard, no recovery, no link history, no per-page differentiation. This causes three concrete problems:

1. **Casual users get more permanence than they want.** Someone sharing a one-off draft doesn't need a 30-day link sitting on a server. They want to share it and forget it.
2. **Returning users have no path to value.** A user who comes back wanting to manage past uploads has nothing to manage. There's no reason to create an account.
3. **Pro has no product story.** Stripe is wired, but there's nothing differentiated to sell. The $5/mo plan is currently a tip jar.

## Goals

- Give each user type — drive-by, returning casual, power user — an experience tuned to how they actually use the product.
- Establish a credible Pro tier with concrete unlocks worth $5/mo.
- Create a natural funnel: anonymous → account → Pro, with each step solving a real pain from the prior step.
- Keep the privacy-first identity intact for the anonymous tier; be honest about the trade-offs for account tiers.

## Non-goals

- Custom domains (`links.mycompany.com`). Possibly never.
- End-to-end encryption for account-tier pages. We accept server-held keys for Tier 2/3 to enable account-driven password reset.
- Detailed analytics (referrers, geography, unique visitors). Total view count only.
- Team/org accounts, sharing, collaboration.
- API access for programmatic uploads.
- Migration of anonymous links into accounts. Anonymous is anonymous.

---

## Users

| Persona | Tier | Use case |
|---|---|---|
| **Drive-by sharer** | Tier 1 — anonymous | Quick one-off: send a draft to a friend, share a mockup, post a single page. Doesn't want an account, doesn't want it to stick around. |
| **Returning casual** | Tier 2 — free account | Wants to keep track of what they've shared, recover if they forget the password, but volume is low (1–3 active pages). |
| **Power user** | Tier 3 — Pro | Uses PageGate routinely. Wants memorable URLs, longer/no expiry, public landing pages, edit-in-place, larger inventory. |

---

## Requirements

The full tier breakdown is in [TIERS.md](./TIERS.md). Headline requirements:

### Tier 1 — Free, anonymous
- 1-day expiry, 300-view cap, 10 MB file limit.
- Confirm-password on upload (typo = dead page otherwise).
- Link shown once, never recoverable.
- Genuinely zero-knowledge: server cannot read content without the user's password.

### Tier 2 — Free, account
- 7-day fixed expiry, 3 links max (no delete), 1,000-view cap.
- Dashboard with link URL + expiry + view count. Password not displayed.
- Account-driven password reset (no need to know old password).
- Random slug, no public pages, no edit-in-place, no analytics.

### Tier 3 — Pro ($5/mo)
- Custom expiry up to "forever", 100 links, custom view caps.
- Custom hyphenated slugs (3+ word groups, 2+ chars each, ≤60 chars total) with reserved-namespace denylist.
- Public pages (no password).
- Edit-in-place: HTML, password, expiry, slug.
- Per-page total-view analytics.
- No "Made with PageGate" footer.

### Cross-tier
- Pro downgrade: 30-day grace period (everything keeps working) → user picks 3 to keep → enforce Tier 2 at day 30. Auto-pick most-recently-viewed if user ignores banner.
- View-limit-reached UX matches expiry UX (different copy).
- Slug collisions: first-come-first-served.

---

## Privacy & honest copy

The current README states *"the server cannot read uploaded content without the password."* That's only true for Tier 1 under the new model. The README and any public-facing copy must be revised to:

> *"Anonymous uploads are end-to-end encrypted — even we can't read them. Account uploads are encrypted at rest and protected by your account password, recoverable if you lose the password."*

This trade-off is intentional. Account users want recovery; recovery requires server-held keys; that breaks zero-knowledge. We don't pretend otherwise.

---

## Phasing

Sequential, not parallel. Each phase is shippable on its own.

| Phase | Scope | User-visible change |
|---|---|---|
| **1. Foundation** | Schema migration, server-master-key crypto path for accounts, Tier 1 password-derived path preserved. Refactor existing pages to new schema. | None (silent migration). |
| **2. Tier 1 polish** | 1-day expiry, 300-view cap, confirm-password input, link-shown-once flow. | Anonymous expiry shortens; new confirm-password step. |
| **3. Tier 2** | Dashboard, password reset UI, 3-link cap, 7-day expiry, 1,000-view cap, branding footer logic. | Logged-in users see dashboard + can reset passwords. |
| **4. Tier 3** | Custom slugs (+ reserved namespace), public pages, custom view caps, edit-in-place, per-page analytics. | Pro subscribers unlock the full feature set. |
| **5. Pro downgrade** | Stripe webhook handler for cancel/lapse, 30-day grace, banner UI, link-selection flow, day-30 enforcement job. | Lapsed Pro users get the grace experience instead of an immediate cliff. |
| **6. Copy + polish** | README rewrite, marketing/landing copy update, view-cap UI polish, edge-case cleanup. | Honest privacy claims; cleaner UX. |

Estimated total: 2–3 weeks of focused work. Each phase is roughly 1–4 days.

---

## Success metrics

To instrument once Tier 2 + Tier 3 are live:

- **Anonymous → account conversion**: % of Tier 1 uploaders who create an account within 7 days.
- **Account → Pro conversion**: % of Tier 2 accounts who upgrade to Pro within 30 days.
- **Pro retention**: month-over-month subscription retention.
- **Active-link distribution**: median active links per Tier 2 and Tier 3 user. Helps validate the 3-link and 100-link caps are right-sized.
- **Tier 1 "wall hit" rate**: % of anonymous flows where the user later tries to recover a link they uploaded anonymously. (Strong tier-2 motivation signal.)
- **Pro downgrade churn**: of users who lapse Pro, % who renew during the 30-day grace vs. % who let it cut down.

No specific targets committed — these are baselines to instrument and iterate against.

---

## Risks

- **Crypto refactor regressions.** Phase 1 touches the encryption path and existing live pages. Migration must be reversible and well-tested. Mitigation: dry-run migration on a snapshot of `data/` and `uploads/` before running on prod.
- **Stripe webhook complexity.** Phase 5's downgrade flow depends on reliable webhook handling. Idempotency table already exists (`stripe_events`); test failure modes (failed payment, voluntary cancel, payment retry success).
- **Custom-slug squatting.** Even with first-come-first-served, low-effort users could grab high-value slugs (`my-portfolio`). The reserved namespace doesn't prevent this. Acceptable risk for now; revisit if it becomes a complaint.
- **Tier 2 cap frustration.** "Can't delete" is unusual. If users churn over it, reconsider — could allow 1 delete/week or similar. Wait for signal.
- **Pro feature breadth.** Phase 4 is the largest single phase. Could be split into 4a (slugs + public) and 4b (edit-in-place + analytics) if it's too much to land at once.

---

## Open questions

None blocking. Items to revisit after launch:

- Is 100 links the right Pro ceiling, or higher?
- Should Tier 2 get a "delete with cooldown" instead of pure no-delete?
- Should we add per-IP creation rate limits proactively, or wait for spam?
- Should custom-slug squatting protection be added (e.g. trademark-style report flow)?
