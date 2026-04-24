/**
 * Express router for JSON Schema management endpoints.
 *
 * POST /api/schemas  — Register a new JSON Schema
 */

"use strict";

const express = require("express");
const { registerSchema } = require("./schemaStore");

const router = express.Router();

/**
 * POST /api/schemas
 *
 * Accepts a schema entry with { name, version, schema } in the request body.
 * Validates the embedded JSON Schema using ajv, stores the full entry in
 * memory with a generated ID, and returns { id, name }.
 *
 * Request body:
 *   {
 *     "name": "webhook-event",
 *     "version": "1.0",
 *     "schema": { "type": "object", "properties": { ... } }
 *   }
 *
 * Success response (201):
 *   { "id": "<uuid>", "name": "webhook-event" }
 *
 * Error responses:
 *   400 — Request body is missing, malformed, or contains an invalid JSON Schema
 */
router.post("/", (req, res) => {
  const body = req.body;

  // Basic sanity check: body must be a non-null, non-array object
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

module.exports = router;
