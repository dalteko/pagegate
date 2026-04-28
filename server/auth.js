const db = require('./db');
const config = require('./config');

function requireAuth(req, res, next) {
  if (!config.proEnabled) {
    return res.status(404).json({ error: 'Pro features are disabled' });
  }
  if (!req.session?.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  const user = db.getUserById(req.session.userId);
  if (!user) {
    req.session.destroy(() => {});
    return res.status(401).json({ error: 'Not authenticated' });
  }
  req.user = user;
  next();
}

function optionalAuth(req, res, next) {
  if (!config.proEnabled) {
    req.user = null;
  } else if (req.session?.userId) {
    req.user = db.getUserById(req.session.userId) || null;
  } else {
    req.user = null;
  }
  next();
}

function requirePro(req, res, next) {
  if (req.user?.subscription_status !== 'active') {
    return res.status(403).json({ error: 'Pro subscription required' });
  }
  next();
}

module.exports = { requireAuth, requirePro, optionalAuth };
