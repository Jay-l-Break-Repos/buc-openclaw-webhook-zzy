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
const crypto = require("crypto");

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
app.get("/", function(req, res) {
  res.json({ status: "ok" });
});

app.get("/health", function(req, res) {
  res.json({ status: "ok" });
});

// ── JSON Schema management ───────────────────────────────────────────────────
var _schemas = new Map();
var _validTypes = ["object","array","string","number","integer","boolean","null"];

function _validateSchemaDef(s) {
  if (!s || typeof s !== "object" || Array.isArray(s)) return ["schema must be an object"];
  var errs = [];
  if (s.type !== undefined) {
    if (typeof s.type === "string") {
      if (_validTypes.indexOf(s.type) === -1) errs.push("invalid type: " + s.type);
    } else if (Array.isArray(s.type)) {
      for (var i = 0; i < s.type.length; i++) {
        if (_validTypes.indexOf(s.type[i]) === -1) errs.push("invalid type: " + s.type[i]);
      }
    } else {
      errs.push("type must be string or array");
    }
  }
  if (s.properties && typeof s.properties === "object" && !Array.isArray(s.properties)) {
    var keys = Object.keys(s.properties);
    for (var j = 0; j < keys.length; j++) {
      var sub = _validateSchemaDef(s.properties[keys[j]]);
      for (var k = 0; k < sub.length; k++) errs.push(keys[j] + ": " + sub[k]);
    }
  }
  return errs;
}

function _checkType(val, type) {
  if (type === "object") return val !== null && typeof val === "object" && !Array.isArray(val);
  if (type === "array") return Array.isArray(val);
  if (type === "string") return typeof val === "string";
  if (type === "number") return typeof val === "number";
  if (type === "integer") return typeof val === "number" && Number.isInteger(val);
  if (type === "boolean") return typeof val === "boolean";
  if (type === "null") return val === null;
  return true;
}

function _validateData(schema, data) {
  var errors = [];
  if (schema.type && !_checkType(data, schema.type)) {
    errors.push({message: "expected type " + schema.type});
    return errors;
  }
  if (schema.required && Array.isArray(schema.required) && data && typeof data === "object") {
    for (var i = 0; i < schema.required.length; i++) {
      if (!(schema.required[i] in data)) errors.push({message: "missing required: " + schema.required[i]});
    }
  }
  if (schema.properties && data && typeof data === "object" && !Array.isArray(data)) {
    var keys = Object.keys(schema.properties);
    for (var j = 0; j < keys.length; j++) {
      if (keys[j] in data) {
        var sub = _validateData(schema.properties[keys[j]], data[keys[j]]);
        for (var k = 0; k < sub.length; k++) errors.push({message: keys[j] + ": " + sub[k].message});
      }
    }
  }
  return errors;
}

app.post("/api/schemas", function(req, res) {
  var b = req.body;
  if (!b || typeof b !== "object" || Array.isArray(b)) return res.status(400).json({error: "bad request"});
  if (!b.name || typeof b.name !== "string") return res.status(400).json({error: "name required"});
  if (!b.version || typeof b.version !== "string") return res.status(400).json({error: "version required"});
  if (!b.schema || typeof b.schema !== "object" || Array.isArray(b.schema)) return res.status(400).json({error: "schema required"});
  var errs = _validateSchemaDef(b.schema);
  if (errs.length > 0) return res.status(400).json({error: "Invalid JSON Schema", details: errs});
  var id = crypto.randomUUID();
  _schemas.set(id, {id: id, name: b.name, version: b.version, schema: b.schema, createdAt: new Date().toISOString()});
  res.status(201).json({id: id, name: b.name});
});

app.get("/api/schemas", function(req, res) {
  res.json(Array.from(_schemas.values()));
});

app.get("/api/schemas/:id", function(req, res) {
  var e = _schemas.get(req.params.id);
  if (!e) return res.status(404).json({error: "not found"});
  res.json(e);
});

app.post("/api/schemas/:id/validate", function(req, res) {
  var e = _schemas.get(req.params.id);
  if (!e) return res.status(404).json({error: "not found"});
  var errors = _validateData(e.schema, req.body);
  var valid = errors.length === 0;
  res.json({valid: valid, errors: valid ? null : errors});
});

app.delete("/api/schemas/:id", function(req, res) {
  if (!_schemas.delete(req.params.id)) return res.status(404).json({error: "not found"});
  res.status(204).send();
});

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
