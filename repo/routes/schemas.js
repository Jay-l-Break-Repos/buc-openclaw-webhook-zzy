"use strict";

console.log("[carrier] routes/schemas.js loading...");

/**
 * Schema Registry Routes
 *
 * POST   /api/schemas              — Register a new JSON Schema definition.
 * GET    /api/schemas              — List all registered schemas (returns array directly).
 * GET    /api/schemas/:id          — Retrieve a single schema by ID (404 if not found).
 * POST   /api/schemas/:id/validate — Validate a JSON payload against a stored schema.
 * DELETE /api/schemas/:id          — Remove a registered schema.
 *
 * Schemas are validated with ajv (draft-07 / JSON Schema) before being stored
 * in an in-memory registry keyed by a unique id.
 */

const express = require("express");
const Ajv = require("ajv");
const { randomUUID } = require("crypto");

console.log("[carrier] schemas deps loaded: express OK, Ajv type=" + typeof Ajv + ", randomUUID type=" + typeof randomUUID);

const router = express.Router();

// ── In-memory schema registry ─────────────────────────────────────────────────
// Map<id, { id, name, version, schema, registeredAt }>
const schemaRegistry = new Map();

// ── ajv instance used to validate that submitted schemas are themselves valid ──
const ajv = new Ajv({ strict: false, allErrors: true });
console.log("[carrier] ajv instance created OK");

// ── Compiled-validator cache: Map<id, ValidateFunction> ──────────────────────
const validatorCache = new Map();

// ── POST /api/schemas ─────────────────────────────────────────────────────────
// Body (JSON):
//   name    {string}  required – human-readable identifier for this schema
//   schema  {object}  required – the JSON Schema definition
//   version {string}  optional – defaults to "1.0.0"
//
// Responses:
//   201  { id, name, version, registeredAt }  – schema registered successfully
//   400  { error, details? }                  – missing/invalid fields or invalid schema
//   409  { error }                            – a schema with that name already exists
router.post("/", (req, res) => {
  const { name, schema, version = "1.0.0" } = req.body || {};

  // ── Input validation ────────────────────────────────────────────────────────
  if (!name || typeof name !== "string" || name.trim() === "") {
    return res.status(400).json({
      error: "Missing or invalid field: 'name' must be a non-empty string.",
    });
  }

  if (!schema || typeof schema !== "object" || Array.isArray(schema)) {
    return res.status(400).json({
      error: "Missing or invalid field: 'schema' must be a JSON Schema object.",
    });
  }

  if (typeof version !== "string" || version.trim() === "") {
    return res.status(400).json({
      error: "Invalid field: 'version' must be a non-empty string.",
    });
  }

  const trimmedName = name.trim();

  // ── Duplicate check (by name) ───────────────────────────────────────────────
  for (const entry of schemaRegistry.values()) {
    if (entry.name === trimmedName) {
      return res.status(409).json({
        error: `A schema named '${trimmedName}' is already registered.`,
      });
    }
  }

  // ── Validate that the submitted schema is itself a valid JSON Schema ─────────
  const isValidSchema = ajv.validateSchema(schema);
  if (!isValidSchema) {
    return res.status(400).json({
      error: "The provided 'schema' is not a valid JSON Schema.",
      details: ajv.errors,
    });
  }

  // ── Store in registry ───────────────────────────────────────────────────────
  const id = randomUUID();
  const registeredAt = new Date().toISOString();

  schemaRegistry.set(id, {
    id,
    name: trimmedName,
    version: version.trim(),
    schema,
    registeredAt,
  });

  return res.status(201).json({
    id,
    name: trimmedName,
    version: version.trim(),
    registeredAt,
  });
});

// ── GET /api/schemas ──────────────────────────────────────────────────────────
// Returns an array of all registered schemas directly (not wrapped in an object).
//
// Response 200: [ { id, name, version, registeredAt }, ... ]
router.get("/", (req, res) => {
  const schemas = Array.from(schemaRegistry.values()).map(
    ({ id, name, version, registeredAt }) => ({ id, name, version, registeredAt })
  );

  return res.status(200).json(schemas);
});

// ── GET /api/schemas/:id ──────────────────────────────────────────────────────
// Returns a single registered schema by its ID.
//
// Responses:
//   200  { id, name, version, schema, registeredAt }  – schema found
//   404  { error }                                     – schema not found
router.get("/:id", (req, res) => {
  const { id } = req.params;

  const entry = schemaRegistry.get(id);
  if (!entry) {
    return res.status(404).json({
      error: `Schema with id '${id}' not found.`,
    });
  }

  return res.status(200).json(entry);
});

// ── POST /api/schemas/:id/validate ────────────────────────────────────────────
// Validates a JSON payload against the stored schema identified by :id.
//
// Body (JSON): the data object to validate
//
// Responses:
//   200  { valid: true }                       – payload is valid
//   200  { valid: false, errors: [...] }       – payload is invalid (ajv errors)
//   404  { error }                             – schema not found
router.post("/:id/validate", (req, res) => {
  const { id } = req.params;

  const entry = schemaRegistry.get(id);
  if (!entry) {
    return res.status(404).json({
      error: `Schema with id '${id}' not found.`,
    });
  }

  // Retrieve or compile the validator for this schema
  let validate = validatorCache.get(id);
  if (!validate) {
    try {
      validate = ajv.compile(entry.schema);
      validatorCache.set(id, validate);
    } catch (err) {
      return res.status(500).json({
        error: "Failed to compile schema for validation.",
        details: err.message,
      });
    }
  }

  const data = req.body;
  const valid = validate(data);

  if (valid) {
    return res.status(200).json({ valid: true });
  }

  return res.status(200).json({
    valid: false,
    errors: validate.errors,
  });
});

// ── DELETE /api/schemas/:id ───────────────────────────────────────────────────
// Removes a registered schema from the registry.
//
// Responses:
//   200  { message }  – schema deleted successfully
//   404  { error }    – schema not found
router.delete("/:id", (req, res) => {
  const { id } = req.params;

  if (!schemaRegistry.has(id)) {
    return res.status(404).json({
      error: `Schema with id '${id}' not found.`,
    });
  }

  const entry = schemaRegistry.get(id);
  schemaRegistry.delete(id);
  validatorCache.delete(id);

  return res.status(200).json({
    message: `Schema '${entry.name}' (id: ${id}) deleted successfully.`,
  });
});

// ── Export registry accessors for use by other route modules ─────────────────
function getSchema(id) {
  const entry = schemaRegistry.get(id);
  return entry ? entry.schema : null;
}

function getSchemaEntry(id) {
  return schemaRegistry.get(id) || null;
}

console.log("[carrier] routes/schemas.js loaded OK, exporting router");
module.exports = { router, getSchema, getSchemaEntry };
