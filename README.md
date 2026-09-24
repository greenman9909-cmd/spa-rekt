# SPA-REKT v2

> Full-spectrum web security research framework — rip, mine, attack, harvest, report.

Zero npm dependencies. Pure Node.js stdlib.

---

## Modules

| Module | Flag | What it does |
|---|---|---|
| **Tech Fingerprint** | always | Detects CMS, framework, build tool, CDN, payment stack |
| **WAF Detect** | `--waf` | Identifies Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, F5, etc. |
| **Asset Ripper** | always | Downloads all JS/CSS/font/image assets |
| **Source Map Extractor** | `--sourcemap` | Recovers original source code from `.map` files, reconstructs file tree |
| **Bundle Miner** | always | Regex-mines minified JS for API endpoints, secrets, WS endpoints |
| **Secret Extractor** | `--secrets` | JWTs, API keys, AWS/Stripe/GH tokens, Firebase configs, passwords, SMTP creds |
| **Subdomain Enum** | `--subs` | DNS brute force + crt.sh certificate transparency lookup |
| **CORS Scanner** | `--cors` | Origin reflection, null-origin bypass, wildcard+credentials |
| **SQL Injection** | `--sqli` | Error-based + time-based SQLi across all discovered endpoints |
| **Path Traversal** | `--traversal` | LFI/directory traversal probing with 20+ payloads |
| **SSRF** | `--ssrf` | AWS/GCP/Azure metadata exfil, localhost port scanning, gopher |
| **XXE** | `--xxe` | XML external entity injection via POST to XML-accepting endpoints |
| **GraphQL Dump** | `--graphql` | Introspection schema dump, field suggestion leak detection |
| **Param Fuzzer** | `--fuzz` | SSTI, error triggering, unexpected-type injection |
| **Data Harvester** | `--harvest` | Pulls all accessible API responses, flags PII/sensitive data |
| **Auth Scanner** | `--auth` | HTTP verb tampering, IDOR, JWT none-algorithm, unauthenticated access |
| **Security Headers** | always | CSP, HSTS, X-Frame-Options, cookie flags, server disclosure |

---

## Install

```bash
git clone https://github.com/greenman9909-cmd/spa-rekt
cd spa-rekt
node rekt.js --help
# zero dependencies — pure Node.js 18+
```

## Usage

```bash
# full scan — all modules
node rekt.js https://target.com --all

# targeted: SQLi + SSRF + GraphQL
node rekt.js https://target.com --sqli --ssrf --graphql

# source code recovery
node rekt.js https://target.com --sourcemap --deep

# subdomain recon + CORS
node rekt.js https://target.com --subs --cors

# with auth cookie
node rekt.js https://target.com --all --cookie="session=abc123"

# with bearer token (enables JWT attack testing)
node rekt.js https://target.com --auth --token="eyJ..."

# slow/stealth mode
node rekt.js https://target.com --all --delay=800 --threads=3

# custom output dir
node rekt.js https://target.com --all --out=./results/mysite
```

## All Flags

| Flag | Description |
|---|---|
| `--all` | Enable all modules |
| `--deep` | Fetch lazy chunks discovered in bundle maps |
| `--waf` | WAF detection |
| `--sourcemap` | Source map extraction + source reconstruction |
| `--secrets` | Secret scanning only |
| `--subs` | Subdomain enumeration (DNS + crt.sh) |
| `--cors` | CORS misconfiguration scanner |
| `--auth` | Auth surface scanner |
| `--sqli` | SQL injection probing (error + time-based) |
| `--traversal` | Path traversal / LFI probing |
| `--ssrf` | SSRF with cloud metadata targets |
| `--xxe` | XXE injection via XML endpoints |
| `--graphql` | GraphQL introspection + field suggestion leak |
| `--fuzz` | Parameter fuzzing (SSTI, type confusion, 500 hunting) |
| `--harvest` | Harvest accessible API responses, flag PII |
| `--vuln` | Probe discovered endpoints |
| `--ws` | WebSocket endpoint detection |
| `--threads=N` | Parallel workers (default: 10) |
| `--delay=N` | Ms delay between requests (default: 0) |
| `--cookie=` | Session cookie |
| `--token=` | Bearer token |
| `--out=` | Output directory |
| `--ua=` | Custom User-Agent |
| `--wordlist=` | Custom wordlist for fuzzing (one entry per line) |

## Output

```
rekt-output/
  target.com/
    index.html              ← SPA shell
    assets/                 ← all JS/CSS/font chunks
    sourcemaps/             ← .map files + reconstructed source trees
      bundle.js.map
      bundle.js-sources/    ← original source files recovered
        src/
          components/
          pages/
    harvested/              ← raw API JSON responses
      api-user-profile.json
      api-admin-config.json
    graphql-schema.json     ← full GraphQL schema if introspection open
    rekt-report.json        ← machine-readable full report
    rekt-report.md          ← human-readable summary with exploits
```

## SSRF Cloud Targets

Tests extraction from:
- AWS EC2 Instance Metadata (`169.254.169.254`)
- GCP Metadata (`metadata.google.internal`)
- Alibaba Cloud (`100.100.100.200`)
- Azure IMDS (`169.254.169.254/metadata`)
- Localhost service ports (Redis 6379, MySQL 3306, MongoDB 27017)

## SQLi Payloads

Covers: MySQL, PostgreSQL, MSSQL, Oracle, SQLite, DB2  
Detection: error signatures + time-based blind (SLEEP/WAITFOR)

## Requirements

- Node.js 18+
- No npm dependencies

## License

MIT
