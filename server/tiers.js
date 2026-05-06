// Single source of truth for tier rules.
//
// Every per-tier limit, validation rule, and feature flag in PageGate flows
// through this file. If a future engineer needs to know "what does Pro
// unlock?" or "how many active links does Free allow?", read this file — never
// hardcode tier rules elsewhere.
//
// Spec: docs/TIERS.md. This module is the executable mirror of that doc.

const TIER = Object.freeze({
  ANONYMOUS: 1, // Tier 1 — no account
  ACCOUNT: 2,   // Tier 2 — free account
  PRO: 3,       // Tier 3 — paid
});

// Per-tier rule table. `null` means "unlimited" or "user-configurable" — see
// the field-specific note in each rule for which.
const RULES = Object.freeze({
  [TIER.ANONYMOUS]: Object.freeze({
    label: 'Anonymous',
    expiryDays: 1,            // fixed
    maxLinks: null,           // unlimited create, but ephemeral
    fileSizeMb: 10,
    customSlug: false,
    customExpiry: false,
    allowPublic: true,        // password optional via toggle
    editInPlace: false,
    analytics: false,
    passwordReset: false,     // forgotten = lost
    showInDashboard: false,   // shown once at upload, never again
    footerHidden: false,      // "Hosted by pagegate.app" shown
    cryptoMode: 'password',   // password-protected anon → zero-knowledge; no-password anon falls back to wrapped
  }),
  [TIER.ACCOUNT]: Object.freeze({
    label: 'Account',
    expiryDays: 7,            // fixed
    maxLinks: 3,              // hard cap; cannot delete, must wait for expiry
    fileSizeMb: 10,
    customSlug: false,
    customExpiry: false,
    allowPublic: true,
    editInPlace: false,
    analytics: false,
    passwordReset: true,      // server-held key allows reset without old password
    showInDashboard: true,    // url + expiry + view count (password never shown)
    footerHidden: false,
    cryptoMode: 'wrapped',    // random page key wrapped with server master key
  }),
  [TIER.PRO]: Object.freeze({
    label: 'Pro',
    expiryDays: null,         // user-set, up to "forever"
    maxLinks: 100,
    fileSizeMb: 10,
    customSlug: true,
    customExpiry: true,
    allowPublic: true,        // password optional
    editInPlace: true,        // html / password / expiry / slug
    analytics: true,          // total view count per page
    passwordReset: true,
    showInDashboard: true,
    footerHidden: true,
    cryptoMode: 'wrapped',
  }),
});

// Routes and other reserved paths that cannot be claimed as Pro slugs.
// Keep in sync with the express route table — extend whenever a new top-level
// route is added.
const RESERVED_SLUGS = Object.freeze(new Set([
  'api',
  'login',
  'sign-in',
  'sign-up',
  'dashboard',
  'pricing',
  'account',
  'settings',
  'admin',
  'health',
  'webhook',
  'privacy',
  'terms',
  'favicon',
  'style',
  'app',
]));

// Pro slug rule per TIERS.md:
// - lowercase alphanumeric
// - 3+ hyphenated word groups, each ≥ 2 chars
// - total length ≤ 60
const PRO_SLUG_REGEX = /^[a-z0-9]{2,}(-[a-z0-9]{2,}){2,}$/;
const PRO_SLUG_MAX_LEN = 60;

// Returns the tier for a user record (or null for anonymous).
// `user` is the row from the `users` table, or null.
// `isProActive` callback decides whether the user has effective Pro access
// — the caller passes this in because Pro state includes the grace-period
// rules in index.js (`isUserPro`). Keeping the rule here would duplicate
// it; keeping the input dependency explicit is clearer.
function tierFor(user, { isProActive } = {}) {
  if (!user) return TIER.ANONYMOUS;
  if (typeof isProActive === 'function' && isProActive(user)) return TIER.PRO;
  return TIER.ACCOUNT;
}

function rulesFor(tier) {
  const r = RULES[tier];
  if (!r) throw new Error(`Unknown tier: ${tier}`);
  return r;
}

// Returns null if valid, else a short user-facing error string.
function validateProSlug(slug) {
  if (!slug) return 'Slug is required';
  if (slug.length > PRO_SLUG_MAX_LEN) return `Slug must be ${PRO_SLUG_MAX_LEN} characters or fewer`;
  if (!PRO_SLUG_REGEX.test(slug)) return 'Slug must be 3+ hyphenated word groups (each 2+ chars), lowercase alphanumeric';
  if (RESERVED_SLUGS.has(slug)) return 'This slug is reserved';
  return null;
}

module.exports = {
  TIER,
  RULES,
  RESERVED_SLUGS,
  PRO_SLUG_REGEX,
  PRO_SLUG_MAX_LEN,
  tierFor,
  rulesFor,
  validateProSlug,
};
