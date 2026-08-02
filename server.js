require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const port = Number(process.env.PORT) || 3000;
const jwtSecret = process.env.JWT_SECRET || (process.env.NODE_ENV === 'production' ? '' : crypto.randomBytes(32).toString('hex'));
if (!process.env.JWT_SECRET) {
  if (process.env.NODE_ENV === 'production') {
    console.error('JWT_SECRET environment variable is required in production.');
    process.exit(1);
  }
  console.warn('JWT_SECRET not set; using a generated development secret.');
}
const adminApiKey = process.env.ADMIN_API_KEY || '';
const payfastMerchantId = process.env.PAYFAST_MERCHANT_ID || '';
const payfastMerchantKey = process.env.PAYFAST_MERCHANT_KEY || '';
const payfastPassphrase = process.env.PAYFAST_PASSPHRASE || '';
const payfastMode = (process.env.PAYFAST_MODE || 'sandbox').toLowerCase();
const payfastReturnUrl = process.env.PAYFAST_RETURN_URL || '';
const payfastCancelUrl = process.env.PAYFAST_CANCEL_URL || '';
const payfastNotifyUrl = process.env.PAYFAST_NOTIFY_URL || '';
const connectionString = process.env.DATABASE_URL || '';
const publicDir = path.join(__dirname, 'public');

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

const pool = connectionString ? new Pool({ connectionString }) : null;

class CheckoutError extends Error {
  constructor(message, statusCode = 500) {
    super(message);
    this.name = 'CheckoutError';
    this.statusCode = statusCode;
  }
}

async function initializeDatabase() {
  if (!pool) {
    throw new Error('DATABASE_URL is required.');
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      plan_id TEXT NOT NULL DEFAULT 'free',
      subscription_status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL
    );

    CREATE TABLE IF NOT EXISTS api_keys (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      key TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ NOT NULL
    );

    CREATE TABLE IF NOT EXISTS usage (
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      month_key TEXT NOT NULL,
      request_count INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (user_id, month_key)
    );

    CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys (user_id);
    CREATE INDEX IF NOT EXISTS idx_usage_month ON usage (user_id, month_key);
  `);
}

async function initialize() {
  if (!pool) {
    console.error('DATABASE_URL is required. Set it before starting the server.');
    process.exit(1);
  }

  try {
    await initializeDatabase();
    console.log('PostgreSQL schema initialized.');
  } catch (error) {
    console.error('Failed to initialize PostgreSQL:', error.message);
    process.exit(1);
  }
}

initialize();

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

async function getUserById(id) {
  const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  if (result.rows.length === 0) {
    return null;
  }

  const user = normalizeUser(result.rows[0]);
  const apiKeysResult = await pool.query('SELECT id, key, created_at FROM api_keys WHERE user_id = $1 ORDER BY created_at', [id]);
  user.apiKeys = apiKeysResult.rows.map(normalizeApiKey);
  return user;
}

async function getUserByEmail(email) {
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
  if (result.rows.length === 0) {
    return null;
  }
  return getUserById(result.rows[0].id);
}

async function getUserByApiKey(apiKey) {
  const result = await pool.query('SELECT user_id FROM api_keys WHERE key = $1', [apiKey]);
  if (result.rows.length === 0) {
    return null;
  }
  return getUserById(result.rows[0].user_id);
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

async function createApiKey(userId) {
  const apiKey = {
    id: crypto.randomUUID(),
    key: generateApiKey(),
    createdAt: new Date().toISOString()
  };
  await pool.query('INSERT INTO api_keys (id, user_id, key, created_at) VALUES ($1, $2, $3, $4)', [apiKey.id, userId, apiKey.key, apiKey.createdAt]);
  return apiKey;
}

async function getAuthenticatedUser(req, res) {
  const authHeader = req.headers.authorization || '';
  const apiKey = req.headers['x-api-key'] || req.headers['X-API-Key'];

  if (apiKey) {
    const user = await getUserByApiKey(apiKey);
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
    const user = await getUserById(decoded.sub);
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

async function getUsageCount(user) {
  const monthKey = getMonthKey();
  const result = await pool.query('SELECT request_count FROM usage WHERE user_id = $1 AND month_key = $2', [user.id, monthKey]);
  return result.rows[0] ? result.rows[0].request_count : 0;
}

async function incrementUsage(user) {
  const monthKey = getMonthKey();
  await pool.query(`
    INSERT INTO usage (user_id, month_key, request_count)
    VALUES ($1, $2, 1)
    ON CONFLICT (user_id, month_key) DO UPDATE SET request_count = usage.request_count + 1
  `, [user.id, monthKey]);
}

async function listAdminUsers() {
  const result = await pool.query(`
    SELECT u.id, u.email, u.plan_id, u.subscription_status, u.created_at, COALESCE(SUM(usage.request_count), 0) AS total_requests
    FROM users u
    LEFT JOIN usage ON usage.user_id = u.id
    GROUP BY u.id
    ORDER BY u.created_at DESC
  `);
  return result.rows;
}

async function getAdminMetrics() {
  const usersResult = await pool.query('SELECT COUNT(*)::int AS total_users FROM users');
  const subscriptionsResult = await pool.query("SELECT COUNT(*)::int AS active_subscriptions FROM users WHERE subscription_status = 'active'");
  const usageResult = await pool.query('SELECT COALESCE(SUM(request_count), 0)::int AS total_requests FROM usage');

  return {
    totalUsers: usersResult.rows[0].total_users,
    activeSubscriptions: subscriptionsResult.rows[0].active_subscriptions,
    totalRequests: usageResult.rows[0].total_requests
  };
}

async function updateUserPlan(userId, planId) {
  const plan = getPlan(planId || 'free');
  const updatedAt = new Date().toISOString();
  await pool.query('UPDATE users SET plan_id = $1, subscription_status = $2, updated_at = $3 WHERE id = $4', [plan.id, 'active', updatedAt, userId]);
}

async function applyPlanChange(user, planId) {
  const plan = getPlan(planId);
  const updatedAt = new Date().toISOString();
  await pool.query('UPDATE users SET plan_id = $1, subscription_status = $2, updated_at = $3 WHERE id = $4', [plan.id, 'active', updatedAt, user.id]);
  user.planId = plan.id;
  user.subscriptionStatus = 'active';
  user.updatedAt = updatedAt;
}

function requireAdmin(req, res) {
  if (!adminApiKey) {
    res.status(500).json({ ok: false, error: 'ADMIN_API_KEY is not configured.' });
    return false;
  }

  const providedKey = req.headers['x-admin-key'] || req.query.adminKey || '';
  if (!providedKey || providedKey !== adminApiKey) {
    res.status(401).json({ ok: false, error: 'Admin authentication required.' });
    return false;
  }

  return true;
}

function buildPayfastSignature(payload) {
  const fields = Object.entries(payload)
    .filter(([, value]) => value !== '' && value !== null && value !== undefined)
    .sort(([leftKey], [rightKey]) => leftKey.localeCompare(rightKey));

  const normalized = fields.map(([key, value]) => `${key}=${encodeURIComponent(String(value))}`).join('&');
  const passphraseSuffix = payfastPassphrase ? `&passphrase=${encodeURIComponent(payfastPassphrase)}` : '';
  return crypto.createHash('md5').update(`${normalized}${passphraseSuffix}`).digest('hex');
}

function buildPayfastCheckoutArgs(req, currentUser, selectedPlan) {
  if (!selectedPlan || selectedPlan.id === 'free' || Number(selectedPlan.priceUsd) <= 0) {
    throw new CheckoutError('Only paid plans can create a PayFast checkout request.', 400);
  }

  const baseUrl = process.env.PUBLIC_BASE_URL || `${req.protocol}://${req.get('host')}`;
  const returnUrl = payfastReturnUrl || `${baseUrl}/billing/payfast/return`;
  const cancelUrl = payfastCancelUrl || `${baseUrl}/billing/cancel`;
  const notifyUrl = payfastNotifyUrl || `${baseUrl}/billing/payfast/notify`;
  const paymentId = `${currentUser.id}-${Date.now()}`;
  const payload = {
    merchant_id: payfastMerchantId,
    merchant_key: payfastMerchantKey,
    return_url: returnUrl,
    cancel_url: cancelUrl,
    notify_url: notifyUrl,
    name_first: (currentUser.email || 'Customer').split('@')[0],
    name_last: 'User',
    email_address: currentUser.email,
    m_payment_id: paymentId,
    amount: Number(selectedPlan.priceUsd).toFixed(2),
    item_name: `${selectedPlan.name} plan`,
    item_description: `${selectedPlan.name} monthly subscription`,
    custom_str1: `${currentUser.id}|${selectedPlan.id}`,
    custom_str2: 'content-intelligence-api',
    email_confirmation: '1',
    confirmation_address: currentUser.email
  };

  const signature = buildPayfastSignature(payload);
  return {
    payload,
    signature,
    checkoutUrl: payfastMode === 'live'
      ? 'https://www.payfast.co.za/eng/process'
      : 'https://sandbox.payfast.co.za/eng/process'
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
app.use(express.static(publicDir));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/admin', (req, res) => {
  res.sendFile(path.join(publicDir, 'admin.html'));
});

app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'content-intelligence-api', status: 'healthy' });
});

app.get('/api', (req, res) => {
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

app.get('/api/admin/metrics', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  const metrics = await getAdminMetrics();
  res.json({ ok: true, ...metrics });
});

app.get('/api/admin/users', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  const users = await listAdminUsers();
  res.json({ ok: true, users });
});

app.post('/api/admin/users/:id/plan', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  const { planId } = req.body || {};
  const userId = req.params.id;
  if (!userId) {
    return res.status(400).json({ ok: false, error: 'A user ID is required.' });
  }

  try {
    await updateUserPlan(userId, planId);
    res.json({ ok: true, userId, planId: getPlan(planId || 'free').id });
  } catch (error) {
    res.status(500).json({ ok: false, error: 'Unable to update plan.' });
  }
});

app.post('/auth/register', async (req, res) => {
  const { email, password, planId } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ ok: false, error: 'Email and password are required.' });
  }

  const selectedPlan = getPlan(planId || 'free');
  const user = createUserRecord({ email, password, planId: selectedPlan.id });

  try {
    await pool.query('INSERT INTO users (id, email, password_hash, plan_id, subscription_status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)', [user.id, user.email.toLowerCase(), user.passwordHash, user.planId, user.subscriptionStatus, user.createdAt, user.updatedAt]);
    const apiKey = await createApiKey(user.id);
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
    if (error.code === '23505') {
      return res.status(409).json({ ok: false, error: 'Email already registered.' });
    }
    return res.status(500).json({ ok: false, error: 'Unable to create account.' });
  }
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ ok: false, error: 'Email and password are required.' });
  }

  const user = await getUserByEmail(email);
  if (!user || !verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({ ok: false, error: 'Invalid credentials.' });
  }

  res.json({ ok: true, token: signToken(user), user: { id: user.id, email: user.email, planId: user.planId, subscriptionStatus: user.subscriptionStatus } });
});

app.get('/me', async (req, res) => {
  const user = await getAuthenticatedUser(req, res);
  if (!user) return;

  const currentUser = await getUserById(user.id);
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
      usageThisMonth: await getUsageCount(currentUser),
      apiKeys: currentUser.apiKeys.map((key) => ({ id: key.id, createdAt: key.createdAt }))
    }
  });
});

app.post('/api-keys', async (req, res) => {
  const user = await getAuthenticatedUser(req, res);
  if (!user) return;

  const currentUser = await getUserById(user.id);
  if (!currentUser) {
    return res.status(404).json({ ok: false, error: 'User not found.' });
  }

  const newApiKey = await createApiKey(currentUser.id);
  res.status(201).json({ ok: true, apiKey: newApiKey });
});

app.get('/v1/usage', async (req, res) => {
  const user = await getAuthenticatedUser(req, res);
  if (!user) return;

  const currentUser = await getUserById(user.id);
  if (!currentUser) {
    return res.status(404).json({ ok: false, error: 'User not found.' });
  }

  const plan = getPlan(currentUser.planId);
  const usageThisMonth = await getUsageCount(currentUser);
  res.json({
    ok: true,
    plan: plan.id,
    usageThisMonth,
    limit: plan.requestsPerMonth,
    remaining: Math.max(0, plan.requestsPerMonth - usageThisMonth)
  });
});

app.post('/v1/analyze', async (req, res) => {
  const user = await getAuthenticatedUser(req, res);
  if (!user) return;

  const currentUser = await getUserById(user.id);
  if (!currentUser) {
    return res.status(404).json({ ok: false, error: 'User not found.' });
  }

  const body = req.body || {};
  const text = typeof body.text === 'string' ? body.text : (typeof body.content === 'string' ? body.content : '');
  if (!text.trim()) {
    return res.status(400).json({ ok: false, error: 'Provide a non-empty text field.' });
  }

  const plan = getPlan(currentUser.planId);
  const usageThisMonth = await getUsageCount(currentUser);
  if (usageThisMonth >= plan.requestsPerMonth) {
    return res.status(429).json({
      ok: false,
      error: 'Monthly quota reached.',
      plan: plan.id,
      upgradeUrl: '/pricing',
      remaining: 0
    });
  }

  await incrementUsage(currentUser);

  res.json({
    ok: true,
    analysis: analyzeText(text),
    plan: currentUser.planId,
    usageThisMonth: await getUsageCount(currentUser),
    remaining: Math.max(0, plan.requestsPerMonth - (await getUsageCount(currentUser)))
  });
});

app.post('/billing/checkout', async (req, res) => {
  const user = await getAuthenticatedUser(req, res);
  if (!user) return;

  const { planId } = req.body || {};
  const selectedPlan = getPlan(planId || 'pro');
  const currentUser = await getUserById(user.id);
  if (!currentUser) {
    return res.status(404).json({ ok: false, error: 'User not found.' });
  }

  const payfastEnabled = Boolean(payfastMerchantId && payfastMerchantKey);

  if (payfastEnabled) {
    try {
      const payfastCheckout = buildPayfastCheckoutArgs(req, currentUser, selectedPlan);
      const params = new URLSearchParams({
        ...payfastCheckout.payload,
        signature: payfastCheckout.signature
      });
      return res.json({ ok: true, mode: 'payfast', checkoutUrl: `${payfastCheckout.checkoutUrl}?${params.toString()}`, plan: selectedPlan.id, planPriceUsd: selectedPlan.priceUsd });
    } catch (error) {
      const statusCode = error instanceof CheckoutError ? error.statusCode : 500;
      const message = statusCode === 400 ? 'Select a paid plan to start checkout.' : 'Unable to start checkout right now.';
      return res.status(statusCode).json({ ok: false, error: message });
    }
  }

  await applyPlanChange(currentUser, selectedPlan.id);

  res.json({
    ok: true,
    mode: 'mock',
    plan: selectedPlan.id,
    planPriceUsd: selectedPlan.priceUsd,
    checkoutUrl: `/billing/checkout/${selectedPlan.id}`,
    message: 'Billing is in local test mode. Add PayFast credentials to enable real checkout.'
  });
});

app.post('/billing/payfast/notify', async (req, res) => {
  if (!payfastMerchantId || !payfastMerchantKey) {
    return res.status(400).send('PayFast is not configured.');
  }

  const payload = req.body || {};
  const expectedSignature = buildPayfastSignature(Object.fromEntries(Object.entries(payload).filter(([key]) => key !== 'signature')));
  if ((payload.signature || '').toLowerCase() !== expectedSignature.toLowerCase()) {
    return res.status(400).send('Invalid signature.');
  }

  if (payload.payment_status === 'COMPLETE' || payload.payment_status === 'PAID') {
    const customValue = payload.custom_str1 || '';
    const [userId, planId] = customValue.split('|');
    if (userId) {
      const user = await getUserById(userId);
      if (user) {
        await applyPlanChange(user, planId || 'pro');
      }
    }
  }

  res.status(200).send('OK');
});

app.get('/billing/payfast/return', (req, res) => {
  res.json({ ok: true, message: 'PayFast payment completed. Your plan will be activated after PayFast confirms the payment.' });
});

app.get('/billing/success', (req, res) => {
  res.json({ ok: true, message: 'Checkout succeeded. Your plan will be activated after PayFast confirms the payment.', sessionId: req.query.session_id || null });
});

app.get('/billing/cancel', (req, res) => {
  res.json({ ok: true, message: 'Checkout was cancelled.' });
});

app.listen(port, () => {
  console.log(`SaaS API listening on http://localhost:${port}`);
  console.log(`Database URL configured: ${connectionString ? 'yes' : 'no'}`);
});
