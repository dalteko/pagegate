const db = require('./db');

let stripe;
function getStripe() {
  if (!stripe) {
    stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
  }
  return stripe;
}

async function createCheckoutSession(userId, email, stripeCustomerId, baseUrl) {
  const params = {
    mode: 'subscription',
    line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
    success_url: `${baseUrl}/dashboard.html?checkout=success`,
    cancel_url: `${baseUrl}/dashboard.html`,
    client_reference_id: userId,
    metadata: { userId },
  };

  if (stripeCustomerId) {
    params.customer = stripeCustomerId;
  } else {
    params.customer_email = email;
  }

  return getStripe().checkout.sessions.create(params);
}

async function createPortalSession(stripeCustomerId, baseUrl) {
  return getStripe().billingPortal.sessions.create({
    customer: stripeCustomerId,
    return_url: `${baseUrl}/dashboard.html`,
  });
}

function handleWebhook(rawBody, signature) {
  const event = getStripe().webhooks.constructEvent(
    rawBody,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET
  );

  if (db.hasProcessedStripeEvent(event.id)) {
    return { received: true, skipped: true };
  }

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      const userId = session.client_reference_id;
      if (userId && session.customer) {
        db.updateUserStripe(userId, session.customer, 'active');
      }
      break;
    }
    case 'customer.subscription.updated': {
      const sub = event.data.object;
      const user = db.getUserByStripeCustomer(sub.customer);
      if (user) {
        const status = sub.status === 'active' ? 'active' : (sub.status === 'past_due' ? 'past_due' : 'canceled');
        db.updateSubscriptionStatus(user.id, status);
      }
      break;
    }
    case 'customer.subscription.deleted': {
      const sub = event.data.object;
      const user = db.getUserByStripeCustomer(sub.customer);
      if (user) {
        db.updateSubscriptionStatus(user.id, 'none');
        db.expireUserPages(user.id);
      }
      break;
    }
  }

  db.markStripeEventProcessed(event.id, event.type);
  return { received: true };
}

module.exports = { createCheckoutSession, createPortalSession, handleWebhook };
