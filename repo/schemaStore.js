/**
 * In-memory JSON Schema store with basic validation.
 *
 * Provides helpers to register, retrieve, list, validate against,
 * and delete JSON Schema definitions, storing them keyed by an
 * auto-generated ID.
 */

"use strict";

const crypto = require("crypto");

/**
 * In-memory map of schemaId -> { id, name, version, schema, createdAt }
 * @type {Map<string, object>}
 */
const schemas = new Map();

/**
 * Generate a unique identifier for a schema.
 * @returns {string}
 */
function generateId() {
  return crypto.randomUUID();
}

/**
 * Basic JSON Schema validation: check that a value matches a schema.
 * Supports type, required, properties (shallow), and items.
 *
 * @param {object} schema - JSON Schema object
 * @param {*} data - The data to validate
 * @returns {{ valid: boolean, errors: Array<{message: string}> }}
 */
function validateAgainstSchema(schema, data) {
  const errors = [];

  // Type check
  if (schema.type) {
    const jsType = typeof data;
    let valid = true;

    switch (schema.type) {
      case "object":
        valid = data !== null && jsType === "object" && !Array.isArray(data);
        break;
      case "array":
        valid = Array.isArray(data);
        break;
      case "string":
        valid = jsType === "string";
        break;
      case "number":
        valid = jsType === "number" && !isNaN(data);
        break;
      case "integer":
        valid = jsType === "number" && Number.isInteger(data);
        break;
      case "boolean":
        valid = jsType === "boolean";
        break;
      case "null":
        valid = data === null;
        break;
    }

    if (!valid) {
      errors.push({ message: `Expected type '${schema.type}' but got '${Array.isArray(data) ? "array" : jsType}'` });
      return { valid: false, errors };
    }
  }

  // Required fields check (for objects)
  if (schema.required && Array.isArray(schema.required) && typeof data === "object" && data !== null) {
    for (const field of schema.required) {
      if (!(field in data)) {
        errors.push({ message: `Missing required field '${field}'` });
      }
    }
  }

  // Properties check (shallow type validation for object properties)
  if (schema.properties && typeof data === "object" && data !== null && !Array.isArray(data)) {
    for (const [key, propSchema] of Object.entries(schema.properties)) {
      if (key in data && propSchema.type) {
        const propResult = validateAgainstSchema(propSchema, data[key]);
        if (!propResult.valid) {
          for (const err of propResult.errors) {
            errors.push({ message: `Property '${key}': ${err.message}` });
          }
        }
      }
    }
  }

  return { valid: errors.length === 0, errors: errors.length > 0 ? errors : null };
}

/**
 * Basic check that an object looks like a valid JSON Schema.
 * @param {object} schema
 * @returns {boolean}
 */
function isValidJsonSchema(schema) {
  if (!schema || typeof schema !== "object" || Array.isArray(schema)) {
    return false;
  }
  // Accept any object as a schema — even an empty object {} is a valid JSON Schema
  return true;
}

/**
 * Register a named schema entry.
 *
 * @param {object} entry
 * @param {string} entry.name
 * @param {string} entry.version
 * @param {object} entry.schema
 * @returns {{ id: string, name: string }}
 * @throws {Error}
 */
function registerSchema({ name, version, schema }) {
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

  if (!isValidJsonSchema(schema)) {
    const error = new Error("Missing or invalid 'schema' field");
    error.validationErrors = [{ message: "'schema' is required and must be a JSON Schema object" }];
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
 * @param {string} id
 * @returns {object|undefined}
 */
function getSchema(id) {
  return schemas.get(id);
}

/**
 * Return all stored schemas as an array.
 * @returns {Array<object>}
 */
function listSchemas() {
  return Array.from(schemas.values());
}

/**
 * Validate a payload against a stored schema.
 *
 * @param {string} id
 * @param {*} payload
 * @returns {{ valid: boolean, errors: Array|null }}
 * @throws {Error} When schema not found
 */
function validatePayload(id, payload) {
  const entry = schemas.get(id);
  if (!entry) {
    const error = new Error("Schema not found");
    error.statusCode = 404;
    throw error;
  }

  return validateAgainstSchema(entry.schema, payload);
}

/**
 * Delete a stored schema by ID.
 * @param {string} id
 * @returns {boolean}
 */
function deleteSchema(id) {
  return schemas.delete(id);
}

module.exports = {
  registerSchema,
  getSchema,
  listSchemas,
  validatePayload,
  deleteSchema,
  _schemas: schemas,
};
