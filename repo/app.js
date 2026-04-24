/**
 * Carrier app for GHSA-q447-rj3r-2cgh / CVE-2026-28478
 * openclaw < 2026.2.13 — unbounded webhook request body buffering (DoS)
 *
 * Vulnerability: openclaw's readBody() reads req.body without any size or
 * timeout limit. Express json() middleware is configured without a `limit`,
 * so arbitrarily large request bodies are fully buffered into memory before
 * the handler runs — enabling memory-exhaustion DoS.
 *
 * Replicates the exact pre-patch pattern from:
 *   dist/routes-DwIVNSKG.js line 121
 *   dist/routes-CQcgE2QD.js  line 771
 */

"use strict";

const express = require("express");
const schemasRouter = require("./schemasRouter");

// ── Replicate openclaw's vulnerable readBody helper ──────────────────────────
// Pre-patch: no maxBytes / timeoutMs guard; just reads whatever Express buffered.
// Source: openclaw dist/routes-DwIVNSKG.js:121 (identical in routes-CQcgE2QD.js)
function readBody(req) {
  const body = req.body;
  if (!body || typeof body !== "object" || Array.isArray(body)) return {};
  return body;
}

const app = express();

// ── VULNERABLE middleware: express.json() with NO size limit ──────────────────
// The patch adds an explicit limit (e.g. express.json({ limit: "1mb" })).
// Pre-patch openclaw omits the limit entirely, so the default (100kb for some
// versions, but effectively unbounded when Content-Length is trusted) applies,
// and slow/chunked bodies are read until the stream ends or memory is exhausted.
app.use(express.json());          // ← no `limit` option — this IS the vulnerability
app.use(express.urlencoded({ extended: true })); // also unbounded for form bodies

// ── Health check ─────────────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// ── JSON Schema management ───────────────────────────────────────────────────
app.use("/api/schemas", schemasRouter);

// ── Vulnerable endpoint: mirrors openclaw's real webhook paths ────────────────
// Any of these paths triggers the same unbounded body-buffering code path.
// An attacker POSTs an oversized or slow/infinite body; the server buffers it
// all before readBody() is even called, exhausting available memory.

function webhookHandler(req, res) {
  // Calls the exact vulnerable function from openclaw's route handlers
  const body = readBody(req);

  // Simulate what openclaw does after reading the body (light processing)
  const keys = Object.keys(body);
  const preview = JSON.stringify(body).slice(0, 256);

  res.json({
    result: "body buffered",
    keys: keys.length,
    preview,
    bytesReceived: Buffer.byteLength(JSON.stringify(body)),
  });
}

// Primary /vuln endpoint
app.post("/vuln", webhookHandler);

// Mirror openclaw's actual webhook route paths (all vulnerable pre-patch)
app.post("/webhook/line",           webhookHandler);
app.post("/webhook/slack",          webhookHandler);
app.post("/webhook/telegram",       webhookHandler);
app.post("/webhook/google-chat",    webhookHandler);
app.post("/webhook/zalo",           webhookHandler);
app.post("/webhook/blububbles",     webhookHandler);
app.post("/webhook/nostr",          webhookHandler);
app.post("/webhook/voice",          webhookHandler);
app.post("/webhook/gateway",        webhookHandler);
app.post("/webhook/nextcloud-talk", webhookHandler);
app.post("/webhook/feishu",         webhookHandler);
app.post("/webhook/teams",          webhookHandler);

// ── Start server ─────────────────────────────────────────────────────────────
const PORT = 9090;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`[carrier] openclaw@2026.2.12 vuln app listening on 0.0.0.0:${PORT}`);
  console.log(`[carrier] GHSA-q447-rj3r-2cgh — unbounded webhook body buffering`);
  console.log(`[carrier] Endpoints: POST /vuln  POST /webhook/line  POST /webhook/slack ...`);
});
