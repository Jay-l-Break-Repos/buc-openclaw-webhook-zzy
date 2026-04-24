/**
 * In-memory JSON Schema store with ajv validation.
 *
 * Provides helpers to register (and validate) JSON Schema definitions,
 * storing them keyed by an auto-generated ID.
 */

"use strict";

const Ajv = require("ajv");
const crypto = require("crypto");

// Single ajv instance shared across the application
const ajv = new Ajv({ allErrors: true });

/**
 * In-memory map of schemaId → { id, name, version, schema, createdAt }
 * @type {Map<string, { id: string, name: string, version: string, schema: object, createdAt: string }>}
 */
const schemas = new Map();

/**
 * Generate a short unique identifier for a schema.
 * Uses a random UUID v4 string.
 *
 * @returns {string} A unique schema ID
 */
function generateId() {
  return crypto.randomUUID();
}

/**
 * Register a named schema entry. Validates the embedded JSON Schema using ajv,
 * then stores the full entry (name, version, schema) in memory.
 *
 * @param {object} entry - The schema entry to register
 * @param {string} entry.name - Human-readable name for the schema
 * @param {string} entry.version - Version string (e.g. "1.0")
 * @param {object} entry.schema - The JSON Schema definition to validate and store
 * @returns {{ id: string, name: string }} The generated schema ID and name on success
 * @throws {Error} When required fields are missing or the schema is invalid
 */
function registerSchema({ name, version, schema }) {
  // Validate required fields
  if (!name || typeof name !== "string") {
    const error = new Error("Missing or invalid 'name' field");
    error.validationErrors = [{ message: "'name' is required and must be a string" }];
    throw error;
  }

  if (!version || typeof version !== "string") {
    const error = new Error("Missing or invalid 'version' field");
    error.validationErrors = [{ message: "'version' is required and must be a string" }];
    throw error;
  }

  if (!schema || typeof schema !== "object" || Array.isArray(schema)) {
    const error = new Error("Missing or invalid 'schema' field");
    error.validationErrors = [{ message: "'schema' is required and must be a JSON Schema object" }];
    throw error;
  }

  // Attempt to compile — ajv throws if the schema itself is invalid
  try {
    ajv.compile(schema);
  } catch (err) {
    const error = new Error("Invalid JSON Schema");
    error.validationErrors = err.errors || [{ message: err.message }];
    throw error;
  }

  const id = generateId();
  schemas.set(id, {
    id,
    name,
    version,
    schema,
    createdAt: new Date().toISOString(),
  });

  return { id, name };
}

/**
 * Retrieve a stored schema entry by ID.
 *
 * @param {string} id
 * @returns {{ id: string, name: string, version: string, schema: object, createdAt: string } | undefined}
 */
function getSchema(id) {
  return schemas.get(id);
}

/**
 * Return all stored schemas as an array.
 *
 * @returns {Array<{ id: string, name: string, version: string, schema: object, createdAt: string }>}
 */
function listSchemas() {
  return Array.from(schemas.values());
}

module.exports = {
  registerSchema,
  getSchema,
  listSchemas,
  // Exposed for testing convenience
  _schemas: schemas,
  _ajv: ajv,
};
