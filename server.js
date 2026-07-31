const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const Stripe = require('stripe');

const app = express();
const port = Number(process.env.PORT) || 3000;
const jwtSecret = process.env.JWT_SECRET || 'dev-secret-change-me';
const stripeSecretKey = process.env.STRIPE_SECRET_KEY || '';
const stripeWebhookSecret = process.env.STRIPE_WEBHOOK_SECRET || '';
const stripePriceIds = {
  pro: process.env.STRIPE_PRICE_PRO || '',
  business: process.env.STRIPE_PRICE_BUSINESS || ''
};
const stripeSuccessUrl = process.env.STRIPE_SUCCESS_URL || '';
const stripeCancelUrl = process.env.STRIPE_CANCEL_URL || '';
const databasePath = process.env.DATABASE_PATH || path.join(__dirname, 'data', 'app.db');

const plans = {
  free: {
    id: 'free',
    name: 'Starter',
    priceUsd: 0,
    requestsPerMonth: 100,
    features: ['Basic text analysis', 'Community support']
  },
  pro: {
    id: 'pro',
    name: 'Growth',
    priceUsd: 19,
    requestsPerMonth: 5000,
    features: ['Higher rate limits', 'Priority support', 'Advanced summaries']
  },
  business: {
    id: 'business',
    name: 'Scale',
    priceUsd: 99,
    requestsPerMonth: 50000,
    features: ['Unlimited team seats', 'SLA', 'Custom analytics']
  }
};

let stripe = null;
if (stripeSecretKey) {
  stripe = new Stripe(stripeSecretKey, { apiVersion: '2024-12-18.acacia' });
}

function ensureDatabaseFile() {
  fs.mkdirSync(path.dirname(databasePath), { recursive: true });
}

function initializeDatabase() {
  ensureDatabaseFile();
  const db = new Database(databasePath);
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      plan_id TEXT NOT NULL DEFAULT 'free',
      subscription_status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS api_keys (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      key TEXT UNIQUE NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS usage (
      user_id TEXT NOT NULL,
      month_key TEXT NOT NULL,
      request_count INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (user_id, month_key)
    );

    CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys (user_id);
    CREATE INDEX IF NOT EXISTS idx_usage_month ON usage (user_id, month_key);
  `);
  return db;
}

const db = initializeDatabase();

function getPlan(planId) {
  return plans[planId] || plans.free;
}

function generateApiKey() {
  return `sk_${crypto.randomBytes(18).toString('hex')}`;
}

function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email, planId: user.planId }, jwtSecret, { expiresIn: '7d' });
}

function hashPassword(password) {
  return bcrypt.hashSync(password, 10);
}

function verifyPassword(password, hash) {
  return bcrypt.compareSync(password, hash);
}

function getMonthKey(date = new Date()) {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
}

function normalizeUser(row) {
  return {
    id: row.id,
    email: row.email,
    passwordHash: row.password_hash,
    planId: row.plan_id,
    subscriptionStatus: row.subscription_status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    apiKeys: []
  };
}

function normalizeApiKey(row) {
  return {
    id: row.id,
    key: row.key,
    createdAt: row.created_at
  };
}

function getUserById(id) {
  const row = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!row) {
    return null;
  }

  const user = normalizeUser(row);
  const apiKeys = db.prepare('SELECT id, key, created_at FROM api_keys WHERE user_id = ? ORDER BY created_at').all(id);
  user.apiKeys = apiKeys.map(normalizeApiKey);
  return user;
}

function getUserByEmail(email) {
  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
  if (!row) {
    return null;
  }
  return getUserById(row.id);
}

function getUserByApiKey(apiKey) {
  const row = db.prepare('SELECT user_id FROM api_keys WHERE key = ?').get(apiKey);
  if (!row) {
    return null;
  }
  return getUserById(row.user_id);
}

function createUserRecord(payload) {
  return {
    id: crypto.randomUUID(),
    email: payload.email,
    passwordHash: hashPassword(payload.password),
    planId: payload.planId || 'free',
    subscriptionStatus: 'active',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
}

function createApiKey(userId) {
  const apiKey = {
    id: crypto.randomUUID(),
    key: generateApiKey(),
    createdAt: new Date().toISOString()
  };
  db.prepare('INSERT INTO api_keys (id, user_id, key, created_at) VALUES (?, ?, ?, ?)').run(apiKey.id, userId, apiKey.key, apiKey.createdAt);
  return apiKey;
}

function getAuthenticatedUser(req, res) {
  const authHeader = req.headers.authorization || '';
  const apiKey = req.headers['x-api-key'] || req.headers['X-API-Key'];

  if (apiKey) {
    const user = getUserByApiKey(apiKey);
    if (!user) {
      res.status(401).json({ ok: false, error: 'Invalid API key.' });
      return null;
    }
    return user;
  }

  const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!bearerMatch) {
    res.status(401).json({ ok: false, error: 'Missing bearer token or API key.' });
    return null;
  }

  try {
    const decoded = jwt.verify(bearerMatch[1], jwtSecret);
    const user = getUserById(decoded.sub);
    if (!user) {
      res.status(401).json({ ok: false, error: 'User not found.' });
      return null;
    }
    return user;
  } catch (error) {
    res.status(401).json({ ok: false, error: 'Invalid or expired token.' });
    return null;
  }
}

function getUsageCount(user) {
  const monthKey = getMonthKey();
  const row = db.prepare('SELECT request_count FROM usage WHERE user_id = ? AND month_key = ?').get(user.id, monthKey);
  return row ? row.request_count : 0;
}

function incrementUsage(user) {
  const monthKey = getMonthKey();
  db.prepare(`
    INSERT INTO usage (user_id, month_key, request_count)
    VALUES (?, ?, 1)
    ON CONFLICT(user_id, month_key) DO UPDATE SET request_count = request_count + 1
  `).run(user.id, monthKey);
}

function applyPlanChange(user, planId) {
  const plan = getPlan(planId);
  const updatedAt = new Date().toISOString();
  db.prepare('UPDATE users SET plan_id = ?, subscription_status = ?, updated_at = ? WHERE id = ?').run(plan.id, 'active', updatedAt, user.id);
  user.planId = plan.id;
  user.subscriptionStatus = 'active';
  user.updatedAt = updatedAt;
}

function buildCheckoutSessionArgs(req, currentUser, selectedPlan) {
  const successUrl = stripeSuccessUrl || `${req.protocol}://${req.get('host')}/billing/success?session_id={CHECKOUT_SESSION_ID}`;
  const cancelUrl = stripeCancelUrl || `${req.protocol}://${req.get('host')}/billing/cancel`;
  const lineItems = [];

  if (stripePriceIds[selectedPlan.id]) {
    lineItems.push({ price: stripePriceIds[selectedPlan.id], quantity: 1 });
  } else {
    lineItems.push({
      price_data: {
        currency: 'usd',
        unit_amount: Math.round(selectedPlan.priceUsd * 100),
        recurring: { interval: 'month' },
        product_data: { name: `${selectedPlan.name} plan` }
      },
      quantity: 1
    });
  }

  return {
    mode: 'subscription',
    line_items: lineItems,
    success_url: successUrl,
    cancel_url: cancelUrl,
    customer_email: currentUser.email,
    metadata: { planId: selectedPlan.id, userId: currentUser.id },
    submit_type: 'subscribe'
  };
}

function tokenize(text) {
  return (text.match(/\b[\w'-]+\b/g) || []).map((word) => word.toLowerCase());
}

function analyzeText(text) {
  const words = tokenize(text);
  const sentences = text.split(/(?<=[.!?])\s+/).filter((fragment) => fragment.trim().length > 0);
  const wordCount = words.length;
  const sentenceCount = sentences.length || 1;
  const avgWordsPerSentence = Math.round((wordCount / sentenceCount) * 10) / 10;
  const longWords = words.filter((word) => word.length > 8).length;
  const readabilityScore = Math.max(0, Math.min(100, Math.round(100 - (avgWordsPerSentence * 2.5) - (longWords * 1.5))));
  const topKeywords = Object.entries(
    words.reduce((accumulator, word) => {
      if (word.length <= 3 || ['the', 'and', 'for', 'that', 'with', 'this', 'your'].includes(word)) {
        return accumulator;
      }
      accumulator[word] = (accumulator[word] || 0) + 1;
      return accumulator;
    }, {})
  )
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([word, count]) => ({ word, count }));

  const positiveWords = ['good', 'great', 'excellent', 'amazing', 'success', 'fast', 'clear', 'easy', 'trusted', 'valuable'];
  const negativeWords = ['bad', 'slow', 'hard', 'broken', 'confusing', 'risk', 'weak', 'poor', 'expensive', 'difficult'];
  const sentimentTokens = words.filter((word) => positiveWords.includes(word) || negativeWords.includes(word));
  const positiveHits = sentimentTokens.filter((word) => positiveWords.includes(word)).length;
  const negativeHits = sentimentTokens.filter((word) => negativeWords.includes(word)).length;
  let sentiment = 'neutral';
  if (positiveHits > negativeHits) sentiment = 'positive';
  else if (negativeHits > positiveHits) sentiment = 'negative';

  return {
    textLength: text.length,
    wordCount,
    sentenceCount,
    averageWordsPerSentence: avgWordsPerSentence,
    readabilityScore,
    readingTimeMinutes: Math.max(1, Math.ceil(wordCount / 200)),
    topKeywords,
    sentiment,
    summary: text.trim().split(/\s+/).slice(0, 24).join(' ') || 'No content provided.'
  };
}

app.use(cors());
app.use((req, res, next) => {
  if (req.path === '/billing/webhook') {
    return express.raw({ type: 'application/json' })(req, res, next);
  }
  return express.json()(req, res, next);
});

app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'content-intelligence-api', status: 'healthy' });
});

app.get('/', (req, res) => {
  res.json({
    ok: true,
    message: 'Sellable content intelligence API',
    plans: Object.values(plans),
    docs: ['POST /auth/register', 'POST /auth/login', 'POST /api-keys', 'POST /v1/analyze', 'POST /billing/checkout']
  });
});

app.get('/plans', (req, res) => {
  res.json({ ok: true, plans: Object.values(plans) });
});

app.post('/auth/register', (req, res) => {
  const { email, password, planId } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ ok: false, error: 'Email and password are required.' });
  }

  const selectedPlan = getPlan(planId || 'free');
  const user = createUserRecord({ email, password, planId: selectedPlan.id });

  try {
    db.prepare('INSERT INTO users (id, email, password_hash, plan_id, subscription_status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(user.id, user.email.toLowerCase(), user.passwordHash, user.planId, user.subscriptionStatus, user.createdAt, user.updatedAt);

    const apiKey = createApiKey(user.id);
    user.apiKeys = [apiKey];

    res.status(201).json({
      ok: true,
      token: signToken(user),
      user: {
        id: user.id,
        email: user.email,
        planId: user.planId,
        subscriptionStatus: user.subscriptionStatus,
        apiKey: apiKey.key
      }
    });
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ ok: false, error: 'Email already registered.' });
    }
    return res.status(500).json({ ok: false, error: 'Unable to create account.' });
  }
});

app.post('/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ ok: false, error: 'Email and password are required.' });
  }

  const user = getUserByEmail(email);
  if (!user || !verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({ ok: false, error: 'Invalid credentials.' });
  }

  res.json({ ok: true, token: signToken(user), user: { id: user.id, email: user.email, planId: user.planId, subscriptionStatus: user.subscriptionStatus } });
});

app.get('/me', (req, res) => {
  const user = getAuthenticatedUser(req, res);
  if (!user) return;

  const currentUser = getUserById(user.id);
  if (!currentUser) {
    return res.status(404).json({ ok: false, error: 'User not found.' });
  }

  res.json({
    ok: true,
    user: {
      id: currentUser.id,
      email: currentUser.email,
      planId: currentUser.planId,
      subscriptionStatus: currentUser.subscriptionStatus,
      usageThisMonth: getUsageCount(currentUser),
      apiKeys: currentUser.apiKeys.map((key) => ({ id: key.id, createdAt: key.createdAt }))
    }
  });
});

app.post('/api-keys', (req, res) => {
  const user = getAuthenticatedUser(req, res);
  if (!user) return;

  const currentUser = getUserById(user.id);
  if (!currentUser) {
    return res.status(404).json({ ok: false, error: 'User not found.' });
  }

  const newApiKey = createApiKey(currentUser.id);
  res.status(201).json({ ok: true, apiKey: newApiKey });
});

app.get('/v1/usage', (req, res) => {
  const user = getAuthenticatedUser(req, res);
  if (!user) return;

  const currentUser = getUserById(user.id);
  if (!currentUser) {
    return res.status(404).json({ ok: false, error: 'User not found.' });
  }

  const plan = getPlan(currentUser.planId);
  const usageThisMonth = getUsageCount(currentUser);
  res.json({
    ok: true,
    plan: plan.id,
    usageThisMonth,
    limit: plan.requestsPerMonth,
    remaining: Math.max(0, plan.requestsPerMonth - usageThisMonth)
  });
});

app.post('/v1/analyze', (req, res) => {
  const user = getAuthenticatedUser(req, res);
  if (!user) return;

  const currentUser = getUserById(user.id);
  if (!currentUser) {
    return res.status(404).json({ ok: false, error: 'User not found.' });
  }

  const body = req.body || {};
  const text = typeof body.text === 'string' ? body.text : (typeof body.content === 'string' ? body.content : '');
  if (!text.trim()) {
    return res.status(400).json({ ok: false, error: 'Provide a non-empty text field.' });
  }

  const plan = getPlan(currentUser.planId);
  const usageThisMonth = getUsageCount(currentUser);
  if (usageThisMonth >= plan.requestsPerMonth) {
    return res.status(429).json({
      ok: false,
      error: 'Monthly quota reached.',
      plan: plan.id,
      upgradeUrl: 'https://example.com/pricing',
      remaining: 0
    });
  }

  incrementUsage(currentUser);

  res.json({
    ok: true,
    analysis: analyzeText(text),
    plan: currentUser.planId,
    usageThisMonth: getUsageCount(currentUser),
    remaining: Math.max(0, plan.requestsPerMonth - getUsageCount(currentUser))
  });
});

app.post('/billing/checkout', async (req, res) => {
  const user = getAuthenticatedUser(req, res);
  if (!user) return;

  const { planId } = req.body || {};
  const selectedPlan = getPlan(planId || 'pro');
  const currentUser = getUserById(user.id);
  if (!currentUser) {
    return res.status(404).json({ ok: false, error: 'User not found.' });
  }

  if (stripe && stripeSecretKey) {
    try {
      const session = await stripe.checkout.sessions.create(buildCheckoutSessionArgs(req, currentUser, selectedPlan));
      return res.json({ ok: true, mode: 'stripe', checkoutUrl: session.url, plan: selectedPlan.id, planPriceUsd: selectedPlan.priceUsd, stripePriceId: stripePriceIds[selectedPlan.id] || null });
    } catch (error) {
      return res.status(500).json({ ok: false, error: error.message });
    }
  }

  applyPlanChange(currentUser, selectedPlan.id);

  res.json({
    ok: true,
    mode: 'mock',
    plan: selectedPlan.id,
    planPriceUsd: selectedPlan.priceUsd,
    checkoutUrl: `https://example.com/billing/checkout/${selectedPlan.id}`,
    message: 'Billing is mocked locally. Add Stripe credentials to enable real checkout.'
  });
});

app.post('/billing/webhook', async (req, res) => {
  const signature = req.headers['stripe-signature'];
  const payload = req.body ? (Buffer.isBuffer(req.body) ? JSON.parse(req.body.toString('utf8')) : req.body) : {};

  if (!stripeWebhookSecret) {
    if (payload.type === 'checkout.session.completed') {
      const planId = payload.data?.object?.metadata?.planId || 'pro';
      const userId = payload.data?.object?.metadata?.userId;
      const email = payload.data?.object?.customer_email || '';
      const user = userId ? getUserById(userId) : getUserByEmail(email);
      if (user) {
        applyPlanChange(user, planId);
      }
    }

    return res.json({ ok: true, received: payload.type || 'mock-event', mode: 'mock' });
  }

  if (!signature) {
    return res.status(400).json({ ok: false, error: 'Stripe signature missing.' });
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, signature, stripeWebhookSecret);
  } catch (error) {
    return res.status(400).json({ ok: false, error: `Webhook signature verification failed: ${error.message}` });
  }

  if (event.type === 'checkout.session.completed') {
    const planId = event.data.object.metadata?.planId || 'pro';
    const userId = event.data.object.metadata?.userId;
    const email = event.data.object.customer_email || '';
    const user = userId ? getUserById(userId) : getUserByEmail(email);
    if (user) {
      applyPlanChange(user, planId);
    }
  }

  if (event.type === 'customer.subscription.deleted') {
    const customerEmail = event.data.object.customer_email || '';
    const user = getUserByEmail(customerEmail);
    if (user) {
      applyPlanChange(user, 'free');
    }
  }

  res.json({ ok: true, received: event.type });
});

app.get('/billing/success', (req, res) => {
  res.json({ ok: true, message: 'Checkout succeeded. Your plan will be activated after the webhook confirms the subscription.', sessionId: req.query.session_id || null });
});

app.get('/billing/cancel', (req, res) => {
  res.json({ ok: true, message: 'Checkout was cancelled.' });
});

app.listen(port, () => {
  console.log(`SaaS API listening on http://localhost:${port}`);
  console.log(`Database path: ${databasePath}`);
});
