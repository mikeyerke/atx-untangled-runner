// SPDX-License-Identifier: BUSL-1.1
// Rebuilt after provenance hardening; runtime behavior is unchanged.
import { createHash, createPublicKey, diffieHellman, generateKeyPairSync, timingSafeEqual } from "node:crypto";
import http from "node:http";
import process from "node:process";
import httpProxy from "http-proxy";
import { chromium } from "playwright-core";
import { DstackClient } from "@phala/dstack-sdk";

const CASE_ID = String(process.env.ATX_CASE_ID || "");
const DESTROY_AFTER = new Date(process.env.ATX_DESTROY_AFTER || 0).getTime();
const MAX_RUNTIME_SECONDS = Math.min(3600, Math.max(300, Number(process.env.ATX_MAX_RUNTIME_SECONDS || 1800)));
const PORT = 8787;
const RESIDENT_ORIGIN = String(process.env.ATX_RESIDENT_ORIGIN || "https://atx-unlocked.mikeyerke.chatgpt.site");
const ALLOWED_KINDS = new Set(["austin_311", "public_record", "rebate", "permit"]);
const DANGEROUS = /emergency|active fire|gas leak|weapon|violence|suicid|medical emergency|immediate danger/i;
const PROTECTED = /captcha|verify you are human|two-factor|2fa|multi-factor|mfa|required payment|credit card|signature/i;
const MAX_AGENT_STEPS = 20;
const MAX_PAYLOAD_BYTES = 160_000;
const MAX_RECEIPT_BYTES = 900_000;
const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const publicJwk = publicKey.export({ format: "jwk" });
const proxy = httpProxy.createProxyServer({ target: "http://127.0.0.1:9990", ws: true, xfwd: false });
let job = null;
let takeoverHash = null;
let state = { status: "waiting_for_encrypted_job", updatedAt: new Date().toISOString() };
let browser = null;
let attestationReady = false;

if (!/^atx_[0-9a-f-]{36}$/i.test(CASE_ID)) throw new Error("Invalid ATX_CASE_ID");
const hardDeadline = Math.min(Number.isFinite(DESTROY_AFTER) ? DESTROY_AFTER : Infinity, Date.now() + MAX_RUNTIME_SECONDS * 1000);
const hardTimer = setTimeout(() => terminate("hard-timeout"), Math.max(1_000, hardDeadline - Date.now()));

function hash(value) { return createHash("sha256").update(value).digest(); }
function json(res, status, body, headers = {}) { const data = Buffer.from(JSON.stringify(body)); res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", "access-control-allow-origin": RESIDENT_ORIGIN, "access-control-allow-credentials": "true", "vary": "origin", "content-length": data.length, ...headers }); res.end(data); }
function readBody(req) { return new Promise((resolve, reject) => { const chunks = []; let size = 0; req.on("data", (chunk) => { size += chunk.length; if (size > MAX_PAYLOAD_BYTES) { reject(new Error("Payload too large")); req.destroy(); } else chunks.push(chunk); }); req.on("end", () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); } catch { reject(new Error("Invalid JSON")); } }); req.on("error", reject); }); }
function clean(value) { return String(value || "").trim(); }
function sameHash(value, expected) { const actual = hash(value); return expected?.length === actual.length && timingSafeEqual(expected, actual); }
function cookie(req, name) { return String(req.headers.cookie || "").split(";").map((v) => v.trim().split("=")).find(([key]) => key === name)?.[1] || ""; }
function authorizedTakeover(req) { return Boolean(takeoverHash && (sameHash(String(req.headers["x-atx-takeover"] || ""), takeoverHash) || sameHash(cookie(req, "atx_takeover"), takeoverHash))); }
function allowedUrl(url, domains) { try { const host = new URL(url).hostname.toLowerCase(); return domains.some((domain) => host === domain || host.endsWith(`.${domain}`)); } catch { return false; } }

async function attestation(nonce = "") {
  // The dstack socket exists only inside a confidential VM. Constructing this
  // client lazily keeps ordinary image boot/health checks meaningful while a
  // successful hardware quote remains mandatory before execution.
  const dstack = new DstackClient();
  const binding = hash(Buffer.from(`${CASE_ID}:${nonce}:${JSON.stringify(publicJwk)}`));
  const [quote, info] = await Promise.all([dstack.getQuote(binding), dstack.info()]);
  attestationReady = true;
  return { caseId: CASE_ID, publicJwk, nonce, quote: quote.quote, eventLog: quote.event_log, reportData: quote.report_data || binding.toString("hex"), composeHash: info.compose_hash, appId: info.app_id, instanceId: info.instance_id, osImageHash: info.tcb_info?.os_image_hash || info.os_image_hash || "", expiresAt: new Date(hardDeadline).toISOString() };
}

function decryptEnvelope(body) {
  if (body?.caseId !== CASE_ID) throw new Error("Case binding mismatch");
  const peer = createPublicKey({ key: body.ephemeralPublicJwk, format: "jwk" });
  const shared = diffieHellman({ privateKey, publicKey: peer });
  const key = shared;
  const iv = Buffer.from(body.iv, "base64"); const encrypted = Buffer.from(body.ciphertext, "base64");
  if (iv.length !== 12 || encrypted.length < 17) throw new Error("Invalid encrypted envelope");
  const tag = encrypted.subarray(encrypted.length - 16); const ciphertext = encrypted.subarray(0, -16);
  return import("node:crypto").then(({ createDecipheriv }) => { const decipher = createDecipheriv("aes-256-gcm", key, iv); decipher.setAAD(Buffer.from(CASE_ID)); decipher.setAuthTag(tag); return JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8")); });
}

async function firstVisible(page, candidates) { for (const candidate of candidates) { const locator = typeof candidate === "string" ? page.getByText(candidate, { exact: false }).first() : candidate(page); if (await locator.isVisible().catch(() => false)) return locator; } return null; }
async function clickFirst(page, labels) { const item = await firstVisible(page, labels.flatMap((label) => [(p) => p.getByRole("button", { name: new RegExp(label, "i") }).first(), (p) => p.getByRole("link", { name: new RegExp(label, "i") }).first()])); if (!item) return false; await item.click(); await page.waitForTimeout(700); return true; }
async function fillFirst(page, labels, value) { if (!clean(value)) return false; for (const label of labels) for (const locator of [page.getByLabel(new RegExp(label, "i")).first(), page.getByPlaceholder(new RegExp(label, "i")).first(), page.locator(`input[name*="${label}" i], textarea[name*="${label}" i]`).first()]) if (await locator.isVisible().catch(() => false)) { await locator.fill(clean(value)); return true; } return false; }
async function snapshot(page) { return page.locator("body").evaluate(() => ({ text: document.body.innerText.slice(0, 12_000), url: location.href })); }
async function protectedGate(page) { const snap = await snapshot(page); const controls = await page.locator('input[type="password"],input[autocomplete="one-time-code"],input[autocomplete="cc-number"],iframe[src*="captcha" i],[class*="captcha" i],[id*="captcha" i],canvas[aria-label*="signature" i]').count().catch(() => 0); return { blocked: controls > 0 || PROTECTED.test(snap.text), snap }; }
function confirmation(text) { for (const pattern of [/#?\b\d{2}-\d{6,}\b/, /(?:confirmation|request|reference|tracking|case)\s*(?:number|no\.?|#|id)?\s*[:#-]?\s*([A-Z0-9-]{6,})/i]) { const found = text.match(pattern); if (found) return clean(found[1] || found[0]).replace(/^#/, ""); } return ""; }

async function run(localJob) {
  if (!ALLOWED_KINDS.has(localJob.kind) || localJob.caseId !== CASE_ID || !localJob.authorizedAt) throw new Error("Invalid or unauthorized job");
  if (DANGEROUS.test(`${localJob.intent} ${JSON.stringify(localJob.facts)}`)) return { status: "needs_human", blocker: "Possible emergency or public-safety issue. Use 911 or 311 by phone as appropriate." };
  browser = await chromium.launch({ headless: false, executablePath: process.env.CHROMIUM_PATH || chromium.executablePath(), args: ["--no-sandbox", "--disable-dev-shm-usage", "--disable-sync", "--no-first-run"] });
  const context = await browser.newContext({ viewport: { width: 1440, height: 960 }, acceptDownloads: true }); const page = await context.newPage();
  state = { status: "running", updatedAt: new Date().toISOString() };
  try {
    await page.goto(localJob.startUrl, { waitUntil: "domcontentloaded", timeout: 45_000 });
    page.on("framenavigated", (frame) => { if (frame === page.mainFrame() && !allowedUrl(frame.url(), localJob.allowedDomains)) page.evaluate(() => window.stop()).catch(() => {}); });
    if (localJob.kind === "austin_311") await clickFirst(page, ["Service Request Submittal", "Start Reporting", "Submit a service request", "New request", "Report an issue"]); else await clickFirst(page, ["Submit a request", "Get started", "Apply now", "Start application", "Request records"]);
    await fillFirst(page, ["address", "location", "street"], localJob.facts.address); await fillFirst(page, ["zip", "postal"], localJob.facts.zip);
    await fillFirst(page, ["description", "details", "request", "what happened", "records"], localJob.facts.issueDescription || localJob.facts.requestText || localJob.facts.projectDescription || localJob.intent);
    await fillFirst(page, ["email", "e-mail"], localJob.facts.contactEmail || localJob.facts.replyEmail); await fillFirst(page, ["account number", "account"], localJob.facts.accountNumber);
    await fillFirst(page, ["equipment", "model", "serial"], localJob.facts.equipment); await fillFirst(page, ["purchase date", "installation date"], localJob.facts.purchaseDate);
    for (let step = 0; step < MAX_AGENT_STEPS; step += 1) {
      const gate = await protectedGate(page);
      if (gate.blocked) { state = { status: "needs_human", blocker: "Complete the protected step in the private browser. ATX will resume automatically.", takeoverPath: "/takeover", updatedAt: new Date().toISOString() }; while ((await protectedGate(page)).blocked && Date.now() < hardDeadline) await new Promise((r) => setTimeout(r, 2000)); state = { status: "running", updatedAt: new Date().toISOString() }; }
      const snap = await snapshot(page); const code = confirmation(snap.text);
      if (code && /(thank you|submitted|received|success|service request)/i.test(snap.text)) { const proof = await page.screenshot({ type: "jpeg", quality: 68, fullPage: true }); if (proof.length > MAX_RECEIPT_BYTES) throw new Error("Receipt proof exceeded size cap"); return { status: "submitted", officialConfirmation: code, officialStatusUrl: page.url(), proofBase64: proof.toString("base64"), proofSha256: hash(proof).toString("hex"), summary: "Submitted through the official channel; confirmation and proof were captured." }; }
      if (await clickFirst(page, ["Continue", "Next", "Review"])) continue;
      const submit = await firstVisible(page, [(p) => p.getByRole("button", { name: /submit|send request|finish/i }).first(), (p) => p.locator('button[type="submit"],input[type="submit"]').first()]);
      if (submit) { await submit.click(); await page.waitForTimeout(1500); continue; }
      return { status: "needs_human", blocker: "The official page requires one fact or choice that was not supplied.", takeoverPath: "/takeover", summary: "Use the private browser to answer the exact question. ATX will continue." };
    }
    return { status: "failed", summary: "The official site did not reach a confirmation within the action cap." };
  } finally { await context.close().catch(() => {}); await browser?.close().catch(() => {}); browser = null; }
}

async function terminate(reason) { clearTimeout(hardTimer); state = { status: "destroyed", reason, updatedAt: new Date().toISOString() }; job = null; takeoverHash = null; await browser?.close().catch(() => {}); setTimeout(() => process.exit(0), 100).unref(); }

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://runner.local");
    if (req.method === "OPTIONS") { res.writeHead(204, { "access-control-allow-origin": RESIDENT_ORIGIN, "access-control-allow-credentials": "true", "access-control-allow-methods": "GET,POST,OPTIONS", "access-control-allow-headers": "content-type,x-atx-takeover", "access-control-max-age": "600", "vary": "origin" }); return res.end(); }
    if (req.method === "GET" && url.pathname === "/health") return json(res, 200, { ok: true, caseId: CASE_ID, expiresAt: new Date(hardDeadline).toISOString() });
    if (req.method === "GET" && url.pathname === "/attestation") return json(res, 200, await attestation(url.searchParams.get("nonce") || ""));
    if (req.method === "POST" && url.pathname === "/execute") {
      if (!attestationReady) return json(res, 428, { error: "Verified confidential attestation required before execution" });
      if (job) return json(res, 409, { error: "This room already has a job" }); const body = await readBody(req); const plaintext = await decryptEnvelope(body);
      takeoverHash = Buffer.from(String(plaintext.takeoverHash || ""), "hex"); if (takeoverHash.length !== 32) throw new Error("Invalid takeover binding"); job = plaintext.job;
      run(job).then((result) => { state = { ...result, updatedAt: new Date().toISOString() }; }).catch((error) => { state = { status: "failed", summary: error.message, updatedAt: new Date().toISOString() }; });
      return json(res, 202, { accepted: true });
    }
    if (req.method === "GET" && url.pathname === "/status") { if (!authorizedTakeover(req)) return json(res, 401, { error: "Resident session required" }); return json(res, 200, state); }
    if (req.method === "GET" && url.pathname === "/takeover") { const html = `<!doctype html><meta name="viewport" content="width=device-width"><title>ATX private takeover</title><body><p>Opening your private execution room…</p><script>const t=location.hash.slice(1);fetch('/redeem',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({token:t})}).then(r=>{if(!r.ok)throw 0;location.replace('/vnc')}).catch(()=>document.body.textContent='This private takeover link is invalid or expired.')</script>`; res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'; frame-ancestors 'none'" }); return res.end(html); }
    if (req.method === "POST" && url.pathname === "/redeem") { const body = await readBody(req); if (!takeoverHash || !sameHash(String(body.token || ""), takeoverHash)) return json(res, 403, { error: "Invalid takeover token" }); return json(res, 200, { accepted: true }, { "set-cookie": `atx_takeover=${body.token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=1800` }); }
    if ((url.pathname.startsWith("/vnc") || url.pathname.startsWith("/websockify")) && authorizedTakeover(req)) return proxy.web(req, res);
    return json(res, 404, { error: "Not found" });
  } catch (error) { return json(res, 400, { error: error.message }); }
});
server.on("upgrade", (req, socket, head) => { if (authorizedTakeover(req)) proxy.ws(req, socket, head); else socket.destroy(); });
server.listen(PORT, "0.0.0.0");
