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
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
```

Without Stripe credentials, the checkout endpoint returns a mock checkout payload so you can test the flow locally. The webhook endpoint also accepts a mock `checkout.session.completed` event when no Stripe secret is configured, which is useful for validating plan changes locally.
