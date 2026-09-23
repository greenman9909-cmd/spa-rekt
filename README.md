# SPA-REKT

> SPA security research framework — rip, mine, scan, report.

Pulls apart any React/Vue/Svelte SPA: extracts all assets, harvests API endpoints from minified JS bundles, finds hardcoded secrets, audits CORS misconfigurations, maps auth surface, checks security headers, and probes for common vulns.

**Use on targets you own or have written authorization for.**

---

## Features

| Module | What it does |
|---|---|
| **Ripper** | Downloads all JS/CSS chunks, lazy-loaded bundles, static assets |
| **Bundle Miner** | Regex-mines minified JS for API routes, auth endpoints, Vite chunk maps |
| **Secret Extractor** | Finds API keys, JWTs, AWS keys, Stripe keys, hardcoded tokens, internal IPs |
| **Endpoint Harvester** | Builds full API surface map from 10+ pattern classes |
| **CORS Scanner** | Tests origin reflection, null-origin bypass, wildcard + credentials combos |
| **Auth Scanner** | HTTP verb tampering, IDOR probing, JWT none-algorithm, unauthenticated access |
| **Header Auditor** | CSP, HSTS, X-Frame-Options, cookie flags, server disclosure |
| **Rate Limit Probe** | Fires 20 auth requests to detect missing rate limiting |

## Install

```bash
git clone https://github.com/YOUR_HANDLE/spa-rekt
cd spa-rekt
# zero dependencies — pure Node.js stdlib
node rekt.js --help
```

## Usage

```bash
# rip assets only
node rekt.js https://target.com

# full scan — all modules
node rekt.js https://target.com --all

# targeted modules
node rekt.js https://target.com --cors --secrets --deep

# with auth cookie + custom output
node rekt.js https://target.com --all --cookie="session=abc123" --out=./results

# with bearer token (JWT vuln testing)
node rekt.js https://target.com --auth --token="eyJ..."

# slow mode (delay between requests, ms)
node rekt.js https://target.com --all --delay=500 --threads=4
```

## Flags

| Flag | Description |
|---|---|
| `--all` | Enable all scan modules |
| `--deep` | Fetch all lazy chunks discovered in bundle maps |
| `--vuln` | Probe discovered endpoints (GET, status codes, JSON extraction) |
| `--secrets` | Secret extraction only |
| `--cors` | CORS misconfiguration scanner |
| `--auth` | Auth surface scanner (verb tampering, IDOR, JWT) |
| `--threads=N` | Parallel request workers (default: 8) |
| `--delay=N` | Ms between requests (default: 0) |
| `--cookie=` | Session cookie to include in all requests |
| `--token=` | Bearer token for auth endpoint testing |
| `--out=` | Output directory (default: `rekt-output/<hostname>`) |
| `--ua=` | Custom User-Agent |

## Output

```
rekt-output/
  target.com/
    index.html          ← SPA shell
    assets/             ← all JS/CSS chunks
    probe-*.json        ← raw API responses from accessible endpoints
    rekt-report.json    ← full machine-readable report
    rekt-report.md      ← human-readable summary
```

## Report Structure

```json
{
  "target": "https://target.com",
  "assets": [...],
  "endpoints": [{ "endpoint": "/api/user", "source": "index.js" }],
  "secrets": [{ "type": "JWT", "value": "eyJ...", "source": "vendor.js" }],
  "vulns": [{ "type": "CORS Reflect+Credentials", "severity": "CRITICAL", "exploit": "..." }],
  "cors": [...],
  "cookies": [...],
  "headers": { "server": "nginx/1.18", ... }
}
```

## Secret Patterns

Detects: Generic API keys · Bearer tokens · JWTs · AWS Access/Secret keys · Cloudflare tokens · Stripe keys · SendGrid API keys · Hardcoded passwords · Private keys · Firebase configs · GraphQL endpoints · Sentry DSNs · Webhook URLs · Internal IPs · URLs with embedded credentials

## CORS Tests

- Wildcard (`*`) with credentials
- Origin reflection (arbitrary origin echoed back)
- `null` origin bypass (sandboxed iframe attack)
- Subdomain takeover surface (`target.evil.com`)

## Requirements

- Node.js 18+
- No npm dependencies (stdlib only)

## License

MIT — research use.
