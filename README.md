# Closeway Content Intelligence API

A polished SaaS API for content analysis with secure access, plan-aware usage limits, and billing-ready checkout flows.

It includes:

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
- PayFast checkout flow ready once credentials are configured

## Run locally

Create an environment file and set your runtime values before starting the API:

```bash
cd money-api
cp .env.example .env  # if you keep a local example file
npm start
```

## Authentication

Register a user:

```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"your-email@company.com","password":"your-secure-password","planId":"pro"}'
```

Login:

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"your-email@company.com","password":"your-secure-password"}'
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

The app uses PayFast for checkout. Set your production values in the environment:

```bash
PUBLIC_BASE_URL=https://api.yourcompany.com
```

```bash
PAYFAST_MERCHANT_ID=your-payfast-merchant-id
PAYFAST_MERCHANT_KEY=your-payfast-merchant-key
PAYFAST_PASSPHRASE=your-payfast-passphrase
PAYFAST_MODE=sandbox
PAYFAST_RETURN_URL=https://api.yourcompany.com/billing/payfast/return
PAYFAST_CANCEL_URL=https://api.yourcompany.com/billing/cancel
PAYFAST_NOTIFY_URL=https://api.yourcompany.com/billing/payfast/notify
```

When PayFast credentials are configured, the checkout endpoint redirects customers to the PayFast payment page. Without those credentials, the app falls back to a mocked local checkout flow so you can test the experience.

## Admin dashboard

The app now includes a simple admin dashboard at `/admin`.

To use it, set an `ADMIN_API_KEY` and visit:

```bash
https://your-domain/admin
```

Use the same key in the dashboard form to view users, subscription status, and update a customer plan.

## Database

The app now expects a PostgreSQL connection string via `DATABASE_URL`.

Example connection string:

```bash
DATABASE_URL=postgresql://user:password@host:5432/database
```

Render can provide this automatically when you attach a managed PostgreSQL database.
