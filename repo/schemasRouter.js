/**
 * Express router for JSON Schema management endpoints.
 *
 * POST   /api/schemas              — Register a new JSON Schema
 * GET    /api/schemas              — List all registered schemas
 * GET    /api/schemas/:id          — Get a single schema by ID
 * POST   /api/schemas/:id/validate — Validate a payload against a schema
 * DELETE /api/schemas/:id          — Delete a schema by ID
 */

"use strict";

const express = require("express");
const {
  registerSchema,
  getSchema,
  listSchemas,
  validatePayload,
  deleteSchema,
} = require("./schemaStore");

const router = express.Router();

/**
 * POST /api/schemas
 *
 * Accepts a schema entry with { name, version, schema } in the request body.
 * Validates the embedded JSON Schema using ajv, stores the full entry in
 * memory with a generated ID, and returns { id, name }.
 *
 * Success response (201):
 *   { "id": "<uuid>", "name": "webhook-event" }
 *
 * Error responses:
 *   400 — Request body is missing, malformed, or contains an invalid JSON Schema
 */
router.post("/", (req, res) => {
  const body = req.body;

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return res.status(400).json({
      error: "Request body must be a JSON object with name, version, and schema fields",
    });
  }

  try {
    const { id, name } = registerSchema(body);
    return res.status(201).json({ id, name });
  } catch (err) {
    return res.status(400).json({
      error: err.message,
      details: err.validationErrors || [],
    });
  }
});

/**
 * GET /api/schemas
 *
 * Returns an array of all registered schema entries.
 * Each entry includes: id, name, version, schema, createdAt.
 *
 * Success response (200):
 *   [ { "id": "...", "name": "webhook-event", "version": "1.0", "schema": {...}, "createdAt": "..." }, ... ]
 */
router.get("/", (req, res) => {
  const schemas = listSchemas();
  return res.status(200).json(schemas);
});

/**
 * GET /api/schemas/:id
 *
 * Returns a single schema entry by ID.
 *
 * Success response (200):
 *   { "id": "...", "name": "webhook-event", "version": "1.0", "schema": {...}, "createdAt": "..." }
 *
 * Error responses:
 *   404 — Schema not found
 */
router.get("/:id", (req, res) => {
  const entry = getSchema(req.params.id);
  if (!entry) {
    return res.status(404).json({ error: "Schema not found" });
  }
  return res.status(200).json(entry);
});

/**
 * POST /api/schemas/:id/validate
 *
 * Validates a payload against the stored schema identified by :id.
 * The request body IS the payload to validate.
 *
 * Success response (200):
 *   { "valid": true }
 *   or
 *   { "valid": false, "errors": [...] }
 *
 * Error responses:
 *   404 — Schema not found
 */
router.post("/:id/validate", (req, res) => {
  try {
    const result = validatePayload(req.params.id, req.body);
    return res.status(200).json(result);
  } catch (err) {
    if (err.statusCode === 404) {
      return res.status(404).json({ error: err.message });
    }
    return res.status(500).json({ error: err.message });
  }
});

/**
 * DELETE /api/schemas/:id
 *
 * Deletes a schema entry by ID.
 *
 * Success response (204): No content
 *
 * Error responses:
 *   404 — Schema not found
 */
router.delete("/:id", (req, res) => {
  const deleted = deleteSchema(req.params.id);
  if (!deleted) {
    return res.status(404).json({ error: "Schema not found" });
  }
  return res.status(204).send();
});

module.exports = router;
