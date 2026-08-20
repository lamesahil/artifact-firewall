# GuardPost — Backend API

Stateless Express + TypeScript API for detecting and redacting sensitive credentials from text, JSON, and HAR files.

## Endpoints

- `GET  /api/health` — Health check
- `POST /api/sanitize` — Sanitize a file or raw text payload

## Supported Secret Types

- JSON Web Tokens (JWT)
- AWS Access & Secret Keys
- PostgreSQL / MongoDB URIs
- Generic API Keys (Stripe, Google, Slack, Bearer tokens)

## Running Locally

```bash
npm install
npm run dev   # tsx watch — listens on PORT or 3000
```

## Testing

```bash
npm test   # runs tests/engine.test.ts via tsx
```

