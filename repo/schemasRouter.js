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
 * Accepts a JSON Schema definition in the request body, validates it using
 * ajv, stores it in memory with a generated ID, and returns the ID.
 *
 * Request body: a valid JSON Schema object (e.g. { "type": "object", ... })
 *
 * Success response (201):
 *   { "id": "<uuid>", "message": "Schema registered successfully" }
 *
 * Error responses:
 *   400 — Request body is missing or not a valid JSON Schema
 */
router.post("/", (req, res) => {
  const schema = req.body;

  // Basic sanity check: body must be a non-null, non-array object
  if (!schema || typeof schema !== "object" || Array.isArray(schema)) {
    return res.status(400).json({
      error: "Request body must be a JSON Schema object",
    });
  }

  try {
    const { id } = registerSchema(schema);
    return res.status(201).json({
      id,
      message: "Schema registered successfully",
    });
  } catch (err) {
    return res.status(400).json({
      error: err.message,
      details: err.validationErrors || [],
    });
  }
});

module.exports = router;
