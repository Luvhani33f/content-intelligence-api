# Closeway Content Intelligence API

Closeway provides a polished content intelligence API for teams that want secure access, predictable usage limits, and billing-ready subscription workflows in one product.

## Overview

This project combines:

- secure user registration and login
- JWT-based authentication and API-key access
- plan-based request quotas
- subscription and checkout hooks for billing integration
- a polished public landing page and admin console

## Key features

- Starter, Growth, and Scale plans
- Monthly request caps with usage visibility
- JSON responses suitable for internal tools and external integrations
- PayFast-ready checkout flow for live billing environments
- Admin dashboard for viewing users and managing plans

## Quick start

### Prerequisites

- Node.js 18+
- PostgreSQL database
- A valid environment configuration

### Install dependencies

```bash
cd money-api
npm install
```

### Environment setup

Create a local environment file and set the required values:

```bash
cp .env.example .env
```

Example variables:

```bash
JWT_SECRET=your-secret-key
ADMIN_API_KEY=your-admin-key
DATABASE_URL=postgresql://user:password@host:5432/database
PORT=3000
```

### Start the server

```bash
npm start
```

The app will be available at:

```bash
http://localhost:3000
```

## Authentication

### Register a user

```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"your-email@company.com","password":"your-secure-password","planId":"pro"}'
```

### Login

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"your-email@company.com","password":"your-secure-password"}'
```

### Analyze content with a JWT

```bash
curl -X POST http://localhost:3000/v1/analyze \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"text":"This is a sample request for a modern content intelligence API."}'
```

### Analyze content with an API key

```bash
curl -X POST http://localhost:3000/v1/analyze \
  -H "X-API-Key: <api-key>" \
  -H "Content-Type: application/json" \
  -d '{"text":"This is a sample request for a modern content intelligence API."}'
```

## Billing

The application includes a billing flow that can be connected to PayFast. Configure these values in your environment when you are ready to go live:

```bash
PUBLIC_BASE_URL=https://api.yourcompany.com
PAYFAST_MERCHANT_ID=your-payfast-merchant-id
PAYFAST_MERCHANT_KEY=your-payfast-merchant-key
PAYFAST_PASSPHRASE=your-payfast-passphrase
PAYFAST_MODE=sandbox
PAYFAST_RETURN_URL=https://api.yourcompany.com/billing/payfast/return
PAYFAST_CANCEL_URL=https://api.yourcompany.com/billing/cancel
PAYFAST_NOTIFY_URL=https://api.yourcompany.com/billing/payfast/notify
```

Without PayFast credentials, the app falls back to local mock checkout behavior for testing.

## Admin dashboard

The admin portal is available at `/admin`.

Set an `ADMIN_API_KEY` and open:

```bash
https://your-domain/admin
```

Use the same key in the dashboard form to view users, check subscription state, and update customer plans.

## Deployment

This project is ready for deployment on platforms such as Render, Railway, or any Node.js-compatible host with PostgreSQL support.
