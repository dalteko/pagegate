const PRO_ENABLED = process.env.PRO_ENABLED === 'true';

const REQUIRED_PRO_ENV = [
  'CLERK_PUBLISHABLE_KEY',
  'CLERK_SECRET_KEY',
  'STRIPE_SECRET_KEY',
  'STRIPE_WEBHOOK_SECRET',
  'STRIPE_PRICE_ID',
];

function validateConfig() {
  if (!PRO_ENABLED) return;

  const missing = REQUIRED_PRO_ENV.filter((name) => !process.env[name]);
  if (missing.length > 0) {
    throw new Error(
      `PRO_ENABLED=true requires these environment variables: ${missing.join(', ')}`
    );
  }
}

validateConfig();

module.exports = {
  proEnabled: PRO_ENABLED,
};
