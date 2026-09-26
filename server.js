"use strict";

const http = require("node:http");
const dns = require("node:dns").promises;
const net = require("node:net");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");
const { URL } = require("node:url");

const PORT = Number(process.env.PORT || 8787);
const TOKEN = process.env.SPA_REKT_INTERNAL_TOKEN || "";
const ALLOWED = new Set(
  (process.env.SPA_REKT_ALLOWED_HOSTS || "")
    .split(",")
    .map(v => v.trim().toLowerCase())
    .filter(Boolean)
);
const MAX_BODY = 16 * 1024;
const TIMEOUT_MS = Math.min(Number(process.env.SPA_REKT_SCAN_TIMEOUT_MS || 90000), 120000);

function json(res, status, body) {
  const data = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": data.length,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  res.end(data);
}

function safeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

function isPrivateIp(ip) {
  if (net.isIP(ip) === 4) {
    const p = ip.split(".").map(Number);
    if (p[0] === 10 || p[0] === 127 || p[0] === 0) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] >= 224) return true;
    return false;
  }
  if (net.isIP(ip) === 6) {
    const v = ip.toLowerCase();
    return v === "::" || v === "::1" || v.startsWith("fc") || v.startsWith("fd") ||
      v.startsWith("fe8") || v.startsWith("fe9") || v.startsWith("fea") ||
      v.startsWith("feb") || v.startsWith("ff");
  }
  return true;
}

async function validateTarget(raw) {
  let parsed;
  try { parsed = new URL(raw); } catch { throw new Error("Invalid URL."); }
  if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Only HTTP(S) targets are allowed.");
  if (parsed.username || parsed.password) throw new Error("Credentials in URLs are not allowed.");
  const host = parsed.hostname.toLowerCase();
  if (!ALLOWED.size || !ALLOWED.has(host)) throw new Error("Target is not on the owner allowlist.");

  const answers = await dns.lookup(host, { all: true });
  if (!answers.length) throw new Error("Target could not be resolved.");
  for (const answer of answers) {
    if (isPrivateIp(answer.address)) throw new Error("Private and reserved network targets are blocked.");
  }
  return parsed.toString();
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", chunk => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new Error("Request body too large."));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

async function runPassiveScan(target) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "spa-rekt-"));
  const outDir = path.join(work, "output");
  const args = [
    path.join(__dirname, "rekt.js"),
    target,
    "--sourcemap",
    "--threads=4",
    "--delay=40",
    `--out=${outDir}`,
  ];

  let stdout = "";
  let stderr = "";
  let timedOut = false;

  await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, {
      cwd: __dirname,
      env: { ...process.env, NO_COLOR: "1" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const cap = value => value.length > 180000 ? value.slice(-180000) : value;
    child.stdout.on("data", d => { stdout = cap(stdout + d.toString()); });
    child.stderr.on("data", d => { stderr = cap(stderr + d.toString()); });
    child.on("error", reject);

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, TIMEOUT_MS);

    child.on("close", code => {
      clearTimeout(timer);
      if (timedOut) return reject(new Error("Passive audit timed out."));
      if (code !== 0) return reject(new Error((stderr || stdout || "Passive audit failed.").slice(-1200)));
      resolve();
    });
  });

  const reportPath = path.join(outDir, "rekt-report.json");
  if (!fs.existsSync(reportPath)) throw new Error("Audit finished without a report.");
  const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));

  const result = {
    target: report.target,
    timestamp: report.timestamp,
    tech: report.tech || {},
    http: report.http || {},
    hardening: report.hardening || [],
    asset_count: (report.assets || []).length,
    endpoints: [...new Set((report.endpoints || []).map(v => v.endpoint))].slice(0, 250),
    websocket_endpoints: report.wsEndpoints || [],
    source_maps: (report.sourcemaps || []).map(v => ({
      file: v.file || null,
      url: v.url || null,
      type: v.type || null,
    })),
    exposed_client_value_types: [...new Set((report.secrets || []).map(v => v.type))],
    exposed_client_value_count: (report.secrets || []).length,
  };

  fs.rmSync(work, { recursive: true, force: true });
  return result;
}

const server = http.createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/health") {
    return json(res, 200, { ok: true, service: "spa-rekt-private", mode: "passive" });
  }
  if (req.method !== "POST" || req.url !== "/scan") {
    return json(res, 404, { ok: false });
  }

  const auth = req.headers.authorization || "";
  const candidate = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!TOKEN || !candidate || !safeEqual(candidate, TOKEN)) {
    return json(res, 401, { ok: false, error: "Unauthorized." });
  }

  try {
    const raw = await readBody(req);
    const body = JSON.parse(raw || "{}");
    const target = await validateTarget(body.url || "");
    const result = await runPassiveScan(target);
    return json(res, 200, { ok: true, result });
  } catch (err) {
    return json(res, 400, { ok: false, error: err.message || "Audit failed." });
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`SPA-REKT private passive service listening on :${PORT}`);
});
