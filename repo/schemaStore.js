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
 * In-memory map of schemaId → { id, schema, createdAt }
 * @type {Map<string, { id: string, schema: object, createdAt: string }>}
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
 * Validate that a given object is a valid JSON Schema (draft-07 / 2020-12
 * depending on ajv defaults) and store it in memory.
 *
 * @param {object} schema - The JSON Schema definition to register
 * @returns {{ id: string }} The generated schema ID on success
 * @throws {{ message: string, errors: object[] }} When the schema is invalid
 */
function registerSchema(schema) {
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
    schema,
    createdAt: new Date().toISOString(),
  });

  return { id };
}

/**
 * Retrieve a stored schema entry by ID.
 *
 * @param {string} id
 * @returns {{ id: string, schema: object, createdAt: string } | undefined}
 */
function getSchema(id) {
  return schemas.get(id);
}

/**
 * Return all stored schemas as an array.
 *
 * @returns {Array<{ id: string, schema: object, createdAt: string }>}
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
