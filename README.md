# Redirect Service

A Node.js redirect service with bot detection, adaptive rate limiting, and short link creation.

## Features

- Create short links via `/shorten`
- Redirect via `/:code`
- Basic bot detection and challenge handling
- Rate limiting and request analytics
- In-memory storage for development

## Requirements

- Node.js 18+ or later
- npm

## Setup

1. Install dependencies:

```bash
npm install
```

2. Populate `.env` (already provided):

```env
PORT=10000
BASE_URL=http://localhost:10000
TARGET_URL=https://www.google.com
ALLOWED_DOMAINS=google.com,github.com
BOT_SCORE_THRESHOLD=45
GEO_API_URL=https://ipinfo.io/{ip}/country
LOG_FILE=clicks.log
```

## Run

```bash
node server.js
```

The server listens on `PORT` and responds on `http://localhost:10000` by default.

## Deploying on Render

Render will use the `start` script from `package.json` if you configure the service as a Node.js web service. The command is:

```bash
npm start
```

Once deployed, use your Render app URL as the base for API calls.

## Endpoints

- `GET /ping` - health check
- `GET /health` or `/healthz` - health check
- `POST /shorten` - create a short URL
- `GET /:code` - redirect to the stored target
- `GET /stats/:code` - view analytics for a code


## Create a Link

### Easy URL-based creation
You can create a short link by visiting `/shorten?url=...`.

```bash
curl "http://localhost:10000/shorten?url=https://github.com"
```

### Add a custom alias
```bash
curl "http://localhost:10000/shorten?url=https://github.com&alias=gh"
```

### JSON POST creation
```bash
curl -X POST http://localhost:10000/shorten \
  -H "Content-Type: application/json" \
  -d '{"url":"https://github.com"}'
```

### Example response
```json
{
  "success": true,
  "code": "a1B2c3",
  "short_url": "http://localhost:10000/a1B2c3",
  "original_url": "https://github.com",
  "expires_at": null
}
```

### Render deployment example
```bash
curl "https://outht.onrender.com/shorten?url=https://github.com"
```

## Notes

- This project uses in-memory storage and is not production-ready.
- For production, replace in-memory stores with Redis or another persistent database.
- `requirements.txt` lists the required Node package versions.
