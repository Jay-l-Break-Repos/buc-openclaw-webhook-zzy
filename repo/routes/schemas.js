"use strict";

/**
 * Schema Registry Routes
 *
 * POST /api/schemas  — Register a new JSON Schema definition.
 * GET  /api/schemas  — List all registered schemas (name + version).
 *
 * Schemas are validated with ajv (draft-07 / JSON Schema) before being stored
 * in an in-memory registry keyed by schema name.
 */

const express = require("express");
const Ajv = require("ajv");

const router = express.Router();

// ── In-memory schema registry ─────────────────────────────────────────────────
// Map<name, { name, version, schema, registeredAt }>
const schemaRegistry = new Map();

// ── ajv instance used to validate that submitted schemas are themselves valid ──
const ajv = new Ajv({ strict: false, allErrors: true });

// ── POST /api/schemas ─────────────────────────────────────────────────────────
// Body (JSON):
//   name    {string}  required – unique identifier for this schema
//   schema  {object}  required – the JSON Schema definition
//   version {string}  optional – defaults to "1.0.0"
//
// Responses:
//   201  { message, name, version }   – schema registered successfully
//   400  { error, details? }          – missing/invalid fields or invalid schema
//   409  { error }                    – a schema with that name already exists
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

  // ── Duplicate check ─────────────────────────────────────────────────────────
  if (schemaRegistry.has(trimmedName)) {
    return res.status(409).json({
      error: `A schema named '${trimmedName}' is already registered.`,
    });
  }

  // ── Validate that the submitted schema is itself a valid JSON Schema ─────────
  // ajv.validateSchema() checks meta-schema compliance without compiling against data.
  const isValidSchema = ajv.validateSchema(schema);
  if (!isValidSchema) {
    return res.status(400).json({
      error: "The provided 'schema' is not a valid JSON Schema.",
      details: ajv.errors,
    });
  }

  // ── Store in registry ───────────────────────────────────────────────────────
  schemaRegistry.set(trimmedName, {
    name: trimmedName,
    version: version.trim(),
    schema,
    registeredAt: new Date().toISOString(),
  });

  return res.status(201).json({
    message: `Schema '${trimmedName}' registered successfully.`,
    name: trimmedName,
    version: version.trim(),
  });
});

// ── GET /api/schemas ──────────────────────────────────────────────────────────
// Returns an array of all registered schemas with their name and version.
//
// Response 200:
//   { schemas: [{ name, version, registeredAt }, ...] }
router.get("/", (req, res) => {
  const schemas = Array.from(schemaRegistry.values()).map(
    ({ name, version, registeredAt }) => ({ name, version, registeredAt })
  );

  return res.status(200).json({ schemas });
});

// ── Export registry accessor for use by other route modules ──────────────────
// (e.g. the upcoming validation endpoint will need to look up stored schemas)
function getSchema(name) {
  const entry = schemaRegistry.get(name);
  return entry ? entry.schema : null;
}

function getSchemaEntry(name) {
  return schemaRegistry.get(name) || null;
}

module.exports = { router, getSchema, getSchemaEntry };
