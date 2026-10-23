/**
 * Recursively strips dangerous HTML and script tags from an input value.
 * Protects against stored XSS, script injection, and null byte poisoning.
 *
 * @param {any} value
 * @returns {any}
 */
export function sanitizeValue(value) {
  if (typeof value === 'string') {
    return value
      .replace(/\0/g, '') // Strip null bytes
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Strip <script> blocks
      .replace(/<[^>]+>/g, '') // Strip HTML tags
      .replace(/javascript:/gi, ''); // Strip javascript: pseudo-protocol
  }
  if (Array.isArray(value)) {
    return value.map(sanitizeValue);
  }
  if (value !== null && typeof value === 'object') {
    const sanitizedObj = {};
    for (const [k, v] of Object.entries(value)) {
      sanitizedObj[k] = sanitizeValue(v);
    }
    return sanitizedObj;
  }
  return value;
}

/**
 * Express middleware to sanitize body and query parameters.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
export function sanitizeInputs(req, res, next) {
  if (req.body && typeof req.body === 'object') {
    req.body = sanitizeValue(req.body);
  }
  if (req.query && typeof req.query === 'object') {
    req.query = sanitizeValue(req.query);
  }
  if (req.params && typeof req.params === 'object') {
    req.params = sanitizeValue(req.params);
  }
  next();
}

export default sanitizeInputs;
