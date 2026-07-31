# Content Intelligence API

A monetization-ready SaaS API for content analysis that includes:

- user registration and login
- JWT-based authentication
- per-user API keys
- plan-based request quotas
- billing checkout hooks for subscriptions

## Features

- Starter, Growth, and Scale plans
- Monthly request caps
- JSON responses designed for app integrations
- A polished landing page and pricing UI for product launches
- Ready for Stripe checkout once credentials are configured

## Run locally

Create an environment file and set a JWT secret before starting the API:

```bash
cd money-api
cp .env.example .env
npm start
```

## Authentication

Register a user:

```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"founder@example.com","password":"supersecret","planId":"pro"}'
```

Login:

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"founder@example.com","password":"supersecret"}'
```

Analyze content using a JWT:

```bash
curl -X POST http://localhost:3000/v1/analyze \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"text":"This is a powerful article for a modern API company."}'
```

Or use an API key:

```bash
curl -X POST http://localhost:3000/v1/analyze \
  -H "X-API-Key: <api-key>" \
  -H "Content-Type: application/json" \
  -d '{"text":"This is a powerful article for a modern API company."}'
```

## Billing

To enable real Stripe checkout, set these environment variables:

```bash
PUBLIC_BASE_URL=https://your-domain.example.com
```

```bash
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_PRO=price_...
STRIPE_PRICE_BUSINESS=price_...
STRIPE_SUCCESS_URL=https://your-domain.example.com/billing/success
STRIPE_CANCEL_URL=https://your-domain.example.com/billing/cancel
```

If you only set `STRIPE_SECRET_KEY`, the API will create a checkout session using price data derived from the plan amount. If you also set `STRIPE_PRICE_PRO` and `STRIPE_PRICE_BUSINESS`, the API will use those real Stripe price IDs. Without Stripe credentials, the checkout endpoint returns a mock checkout payload so you can test the flow locally. The webhook endpoint also accepts a mock `checkout.session.completed` event when no Stripe secret is configured, which is useful for validating plan changes locally.

## Admin dashboard

The app now includes a simple admin dashboard at `/admin`.

To use it, set an `ADMIN_API_KEY` and visit:

```bash
https://your-domain/admin
```

Use the same key in the dashboard form to view users, subscription status, and update a customer plan.

## Database

The app now expects a PostgreSQL connection string via `DATABASE_URL`.

Example:

```bash
DATABASE_URL=postgresql://user:password@host:5432/database
```

Render can provide this automatically when you attach a managed PostgreSQL database.
