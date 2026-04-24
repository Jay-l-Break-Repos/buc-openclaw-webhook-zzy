/**
 * Carrier app for GHSA-q447-rj3r-2cgh / CVE-2026-28478
 * openclaw < 2026.2.13 -- unbounded webhook request body buffering (DoS)
 */

"use strict";

const express = require("express");
const crypto = require("crypto");

// ── In-memory schema store ───────────────────────────────────────────────────
const schemas = new Map();

// Valid JSON Schema types
const VALID_SCHEMA_TYPES = ["object", "array", "string", "number", "integer", "boolean", "null"];

/**
 * Validate that a schema definition is a valid JSON Schema.
 * Returns an array of error strings, or empty array if valid.
 */
function validateJsonSchema(schema, path) {
  path = path || "";
  const errors = [];

  if (!schema || typeof schema !== "object" || Array.isArray(schema)) {
    errors.push((path || "schema") + " must be an object");
    return errors;
  }

  // Validate "type" keyword
  if ("type" in schema) {
    if (typeof schema.type === "string") {
      if (!VALID_SCHEMA_TYPES.includes(schema.type)) {
        errors.push((path ? path + "." : "") + "type: invalid type value '" + schema.type + "'");
      }
    } else if (Array.isArray(schema.type)) {
      for (const t of schema.type) {
        if (!VALID_SCHEMA_TYPES.includes(t)) {
          errors.push((path ? path + "." : "") + "type: invalid type value '" + t + "'");
        }
      }
    } else {
      errors.push((path ? path + "." : "") + "type must be a string or array");
    }
  }

  // Validate "required" keyword
  if ("required" in schema) {
    if (!Array.isArray(schema.required)) {
      errors.push((path ? path + "." : "") + "required must be an array");
    } else {
      for (const r of schema.required) {
        if (typeof r !== "string") {
          errors.push((path ? path + "." : "") + "required items must be strings");
          break;
        }
      }
    }
  }

  // Validate "properties" keyword (recurse)
  if ("properties" in schema && schema.properties) {
    if (typeof schema.properties !== "object" || Array.isArray(schema.properties)) {
      errors.push((path ? path + "." : "") + "properties must be an object");
    } else {
      for (const [key, propSchema] of Object.entries(schema.properties)) {
        const propErrors = validateJsonSchema(propSchema, (path ? path + "." : "") + "properties." + key);
        errors.push(...propErrors);
      }
    }
  }

  // Validate "items" keyword (recurse)
  if ("items" in schema && schema.items) {
    if (typeof schema.items === "object" && !Array.isArray(schema.items)) {
      const itemErrors = validateJsonSchema(schema.items, (path ? path + "." : "") + "items");
      errors.push(...itemErrors);
    }
  }

  return errors;
}

// ── Replicate openclaw's vulnerable readBody helper ──────────────────────────
function readBody(req) {
  const body = req.body;
  if (!body || typeof body !== "object" || Array.isArray(body)) return {};
  return body;
}

const app = express();

// ── Body parsing middleware ──────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Health check ─────────────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// ── JSON Schema management endpoints ─────────────────────────────────────────

// POST /api/schemas - Register a new schema
app.post("/api/schemas", (req, res) => {
  const body = req.body;

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return res.status(400).json({ error: "Request body must be a JSON object" });
  }

  const { name, version, schema } = body;

  if (!name || typeof name !== "string") {
    return res.status(400).json({ error: "Missing or invalid 'name' field" });
  }
  if (!version || typeof version !== "string") {
    return res.status(400).json({ error: "Missing or invalid 'version' field" });
  }
  if (!schema || typeof schema !== "object" || Array.isArray(schema)) {
    return res.status(400).json({ error: "Missing or invalid 'schema' field" });
  }

  // Validate the schema definition itself
  const schemaErrors = validateJsonSchema(schema);
  if (schemaErrors.length > 0) {
    return res.status(400).json({ error: "Invalid JSON Schema", details: schemaErrors });
  }

  const id = crypto.randomUUID();
  schemas.set(id, { id, name, version, schema, createdAt: new Date().toISOString() });

  return res.status(201).json({ id, name });
});

// GET /api/schemas - List all schemas
app.get("/api/schemas", (req, res) => {
  return res.json(Array.from(schemas.values()));
});

// GET /api/schemas/:id - Get a single schema
app.get("/api/schemas/:id", (req, res) => {
  const entry = schemas.get(req.params.id);
  if (!entry) {
    return res.status(404).json({ error: "Schema not found" });
  }
  return res.json(entry);
});

// POST /api/schemas/:id/validate - Validate payload against schema
app.post("/api/schemas/:id/validate", (req, res) => {
  const entry = schemas.get(req.params.id);
  if (!entry) {
    return res.status(404).json({ error: "Schema not found" });
  }

  const schema = entry.schema;
  const data = req.body;
  const errors = [];

  // Basic type check
  if (schema.type) {
    let typeValid = true;
    switch (schema.type) {
      case "object":
        typeValid = data !== null && typeof data === "object" && !Array.isArray(data);
        break;
      case "array":
        typeValid = Array.isArray(data);
        break;
      case "string":
        typeValid = typeof data === "string";
        break;
      case "number":
        typeValid = typeof data === "number";
        break;
      case "integer":
        typeValid = typeof data === "number" && Number.isInteger(data);
        break;
      case "boolean":
        typeValid = typeof data === "boolean";
        break;
    }
    if (!typeValid) {
      errors.push({ message: "Type mismatch: expected " + schema.type });
    }
  }

  // Required fields check
  if (schema.required && Array.isArray(schema.required) && typeof data === "object" && data !== null) {
    for (const field of schema.required) {
      if (!(field in data)) {
        errors.push({ message: "Missing required field: " + field });
      }
    }
  }

  // Property type checks
  if (schema.properties && typeof data === "object" && data !== null && !Array.isArray(data)) {
    for (const [key, propSchema] of Object.entries(schema.properties)) {
      if (key in data && propSchema.type) {
        const val = data[key];
        let propValid = true;
        switch (propSchema.type) {
          case "string": propValid = typeof val === "string"; break;
          case "number": propValid = typeof val === "number"; break;
          case "integer": propValid = typeof val === "number" && Number.isInteger(val); break;
          case "boolean": propValid = typeof val === "boolean"; break;
          case "object": propValid = val !== null && typeof val === "object" && !Array.isArray(val); break;
          case "array": propValid = Array.isArray(val); break;
        }
        if (!propValid) {
          errors.push({ message: "Property '" + key + "': expected " + propSchema.type });
        }
      }
    }
  }

  const valid = errors.length === 0;
  return res.json({ valid, errors: valid ? null : errors });
});

// DELETE /api/schemas/:id - Delete a schema
app.delete("/api/schemas/:id", (req, res) => {
  const deleted = schemas.delete(req.params.id);
  if (!deleted) {
    return res.status(404).json({ error: "Schema not found" });
  }
  return res.status(204).send();
});

// ── Vulnerable webhook endpoints ─────────────────────────────────────────────
function webhookHandler(req, res) {
  const body = readBody(req);
  const keys = Object.keys(body);
  const preview = JSON.stringify(body).slice(0, 256);
  res.json({
    result: "body buffered",
    keys: keys.length,
    preview,
    bytesReceived: Buffer.byteLength(JSON.stringify(body)),
  });
}

app.post("/vuln", webhookHandler);
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
  console.log("[carrier] openclaw@2026.2.12 vuln app listening on 0.0.0.0:" + PORT);
  console.log("[carrier] GHSA-q447-rj3r-2cgh -- unbounded webhook body buffering");
  console.log("[carrier] Endpoints: POST /vuln  POST /webhook/line  POST /webhook/slack ...");
  console.log("[carrier] Schema API: POST/GET /api/schemas  POST /api/schemas/:id/validate  DELETE /api/schemas/:id");
});
