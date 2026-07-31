const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const Stripe = require('stripe');

const app = express();
const port = Number(process.env.PORT) || 3000;
const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  console.error('JWT_SECRET environment variable is required.');
  process.exit(1);
}
const stripeSecretKey = process.env.STRIPE_SECRET_KEY || '';
const stripeWebhookSecret = process.env.STRIPE_WEBHOOK_SECRET || '';
const storePath = process.env.DATA_FILE_PATH || path.join(__dirname, 'data', 'store.json');

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

function ensureStoreFile() {
  fs.mkdirSync(path.dirname(storePath), { recursive: true });
  if (!fs.existsSync(storePath)) {
    const initialStore = { users: [], subscriptions: [] };
    fs.writeFileSync(storePath, JSON.stringify(initialStore, null, 2));
  }
}

function loadStore() {
  ensureStoreFile();
  return JSON.parse(fs.readFileSync(storePath, 'utf8'));
}

function saveStore(store) {
  fs.writeFileSync(storePath, JSON.stringify(store, null, 2));
}

function getMonthKey(date = new Date()) {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
}

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

function getAuthenticatedUser(req, res) {
  const authHeader = req.headers.authorization || '';
  const apiKey = req.headers['x-api-key'] || req.headers['X-API-Key'];
  const store = loadStore();

  if (apiKey) {
    const user = store.users.find((candidate) => candidate.apiKeys.some((key) => key.key === apiKey));
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
    const user = store.users.find((candidate) => candidate.id === decoded.sub);
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

function ensureUserUsage(user) {
  if (!user.usage) {
    user.usage = {};
  }
}

function getUsageCount(user) {
  ensureUserUsage(user);
  const monthKey = getMonthKey();
  return user.usage[monthKey] || 0;
}

function incrementUsage(user) {
  ensureUserUsage(user);
  const monthKey = getMonthKey();
  user.usage[monthKey] = (user.usage[monthKey] || 0) + 1;
}

function createUserStoreRecord(payload) {
  return {
    id: crypto.randomUUID(),
    email: payload.email,
    passwordHash: hashPassword(payload.password),
    planId: payload.planId || 'free',
    subscriptionStatus: 'active',
    createdAt: new Date().toISOString(),
    usage: {},
    apiKeys: []
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

function applyPlanChange(user, planId) {
  const plan = getPlan(planId);
  user.planId = plan.id;
  user.subscriptionStatus = 'active';
}

app.use(cors());
app.use((req, res, next) => {
  if (req.path === '/billing/webhook') {
    return next();
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

  const store = loadStore();
  if (store.users.some((user) => user.email.toLowerCase() === String(email).toLowerCase())) {
    return res.status(409).json({ ok: false, error: 'Email already registered.' });
  }

  const selectedPlan = getPlan(planId || 'free');
  const user = createUserStoreRecord({ email, password, planId: selectedPlan.id });
  user.apiKeys.push({ id: crypto.randomUUID(), key: generateApiKey(), createdAt: new Date().toISOString() });
  store.users.push(user);
  saveStore(store);

  res.status(201).json({
    ok: true,
    token: signToken(user),
    user: {
      id: user.id,
      email: user.email,
      planId: user.planId,
      subscriptionStatus: user.subscriptionStatus,
      apiKey: user.apiKeys[0].key
    }
  });
});

app.post('/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ ok: false, error: 'Email and password are required.' });
  }

  const store = loadStore();
  const user = store.users.find((candidate) => candidate.email.toLowerCase() === String(email).toLowerCase());
  if (!user || !verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({ ok: false, error: 'Invalid credentials.' });
  }

  res.json({ ok: true, token: signToken(user), user: { id: user.id, email: user.email, planId: user.planId, subscriptionStatus: user.subscriptionStatus } });
});

app.get('/me', (req, res) => {
  const user = getAuthenticatedUser(req, res);
  if (!user) return;

  const store = loadStore();
  const currentUser = store.users.find((candidate) => candidate.id === user.id);
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

  const store = loadStore();
  const currentUser = store.users.find((candidate) => candidate.id === user.id);
  if (!currentUser) {
    return res.status(404).json({ ok: false, error: 'User not found.' });
  }

  const newApiKey = {
    id: crypto.randomUUID(),
    key: generateApiKey(),
    createdAt: new Date().toISOString()
  };
  currentUser.apiKeys.push(newApiKey);
  saveStore(store);

  res.status(201).json({ ok: true, apiKey: newApiKey });
});

app.get('/v1/usage', (req, res) => {
  const user = getAuthenticatedUser(req, res);
  if (!user) return;

  const store = loadStore();
  const currentUser = store.users.find((candidate) => candidate.id === user.id);
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

  const store = loadStore();
  const currentUser = store.users.find((candidate) => candidate.id === user.id);
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
  saveStore(store);

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
  const store = loadStore();
  const currentUser = store.users.find((candidate) => candidate.id === user.id);
  if (!currentUser) {
    return res.status(404).json({ ok: false, error: 'User not found.' });
  }

  if (stripe && stripeSecretKey) {
    try {
      const session = await stripe.checkout.sessions.create({
        mode: 'subscription',
        line_items: [{ price_data: { currency: 'usd', unit_amount: Math.round(selectedPlan.priceUsd * 100), recurring: { interval: 'month' }, product_data: { name: `${selectedPlan.name} plan` } }, quantity: 1 }],
        success_url: `${req.protocol}://${req.get('host')}/billing/success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${req.protocol}://${req.get('host')}/billing/cancel`,
        customer_email: currentUser.email,
        metadata: { planId: selectedPlan.id, userId: currentUser.id }
      });
      return res.json({ ok: true, mode: 'stripe', checkoutUrl: session.url, plan: selectedPlan.id, planPriceUsd: selectedPlan.priceUsd });
    } catch (error) {
      return res.status(500).json({ ok: false, error: error.message });
    }
  }

  applyPlanChange(currentUser, selectedPlan.id);
  saveStore(store);

  res.json({
    ok: true,
    mode: 'mock',
    plan: selectedPlan.id,
    planPriceUsd: selectedPlan.priceUsd,
    checkoutUrl: `https://example.com/billing/checkout/${selectedPlan.id}`,
    message: 'Billing is mocked locally. Add Stripe credentials to enable real checkout.'
  });
});

app.post('/billing/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const signature = req.headers['stripe-signature'];
  const payload = req.body ? (Buffer.isBuffer(req.body) ? JSON.parse(req.body.toString('utf8')) : req.body) : {};

  if (!stripeWebhookSecret) {
    if (payload.type === 'checkout.session.completed') {
      const planId = payload.data?.object?.metadata?.planId || 'pro';
      const userId = payload.data?.object?.metadata?.userId;
      const email = payload.data?.object?.customer_email || '';
      const store = loadStore();
      const user = store.users.find((candidate) => (userId && candidate.id === userId) || candidate.email.toLowerCase() === String(email).toLowerCase());
      if (user) {
        applyPlanChange(user, planId);
        saveStore(store);
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
    const store = loadStore();
    const user = store.users.find((candidate) => (userId && candidate.id === userId) || candidate.email.toLowerCase() === String(email).toLowerCase());
    if (user) {
      applyPlanChange(user, planId);
      saveStore(store);
    }
  }

  res.json({ ok: true, received: event.type });
});

app.listen(port, () => {
  console.log(`SaaS API listening on http://localhost:${port}`);
});
