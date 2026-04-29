const PRO_ENABLED = process.env.PRO_ENABLED === 'true';

const REQUIRED_PRO_ENV = [
  'CLERK_PUBLISHABLE_KEY',
  'CLERK_SECRET_KEY',
  'STRIPE_SECRET_KEY',
  'STRIPE_WEBHOOK_SECRET',
  'STRIPE_PRICE_ID',
  // Server master key for Tier 2/3 page encryption (see server/crypto.js).
  // Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
  'PAGE_KEY_MASTER',
];

function validateConfig() {
  if (!PRO_ENABLED) return;

  const missing = REQUIRED_PRO_ENV.filter((name) => !process.env[name]);
  if (missing.length > 0) {
    throw new Error(
      `PRO_ENABLED=true requires these environment variables: ${missing.join(', ')}`
    );
  }

  // PAGE_KEY_MASTER must not just be present — it must be the right shape.
  // Otherwise a malformed key (e.g. typo, wrong base64) silently persists
  // through startup and only blows up on the first Tier 2/3 upload, which
  // could be weeks after deploy. Fail at boot instead. We require the
  // module here (not at top-level) so the free-mode code path doesn't pull
  // crypto.js into config.js's load order.
  const { loadMasterKey } = require('./crypto');
  try {
    loadMasterKey();
  } catch (err) {
    throw new Error(`PAGE_KEY_MASTER is invalid: ${err.message}`);
  }
}

validateConfig();

module.exports = {
  proEnabled: PRO_ENABLED,
};
