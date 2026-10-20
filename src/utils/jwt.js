import jwt from 'jsonwebtoken';
import env from '../config/env.js';

/**
 * Permitted user roles within TrustVault.
 */
export const VALID_ROLES = Object.freeze(['ADMIN', 'OWNER', 'VIEWER']);

/**
 * Custom structured error for JWT verification failures.
 */
export class AuthTokenError extends Error {
  /**
   * @param {string} message - Descriptive error message.
   * @param {string} code - Machine-readable code ('TOKEN_EXPIRED', 'TOKEN_INVALID', etc.).
   * @param {number} [statusCode=401] - HTTP status code.
   */
  constructor(message, code, statusCode = 401) {
    super(message);
    this.name = 'AuthTokenError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

/**
 * Generates a signed JSON Web Token for an authenticated user session.
 *
 * @param {Object} payload - User session details.
 * @param {string} payload.id - Unique user UUID.
 * @param {string} payload.email - User email address.
 * @param {'ADMIN'|'OWNER'|'VIEWER'} payload.role - Assigned platform role.
 * @param {string} [expiresIn] - Optional custom expiration override (defaults to JWT_EXPIRES_IN).
 * @returns {string} The signed JWT string.
 * @throws {Error} If payload is missing required claims or contains invalid role.
 */
export function generateToken(payload, expiresIn = env.JWT_EXPIRES_IN) {
  if (!payload || typeof payload !== 'object') {
    throw new Error('Payload must be a valid object.');
  }

  const { id, email, role } = payload;

  if (!id || typeof id !== 'string') {
    throw new Error('JWT payload requires a valid user "id".');
  }

  if (!email || typeof email !== 'string') {
    throw new Error('JWT payload requires a valid user "email".');
  }

  if (!role || !VALID_ROLES.includes(role)) {
    throw new Error(
      `JWT payload requires a valid "role". Permitted roles: ${VALID_ROLES.join(', ')}.`
    );
  }

  return jwt.sign(
    {
      id,
      email,
      role
    },
    env.JWT_SECRET,
    { expiresIn }
  );
}

/**
 * Verifies and decodes a signed JSON Web Token safely.
 *
 * @param {string} token - The JWT string extracted from Authorization header.
 * @returns {Object} The decoded payload containing id, email, role, and standard claims.
 * @throws {AuthTokenError} If token is missing, expired, or tampered.
 */
export function verifyToken(token) {
  if (!token || typeof token !== 'string') {
    throw new AuthTokenError('Authentication token must be provided.', 'TOKEN_MISSING', 401);
  }

  try {
    return jwt.verify(token, env.JWT_SECRET);
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      throw new AuthTokenError(
        'Authentication token has expired. Please re-authenticate.',
        'TOKEN_EXPIRED',
        401
      );
    }

    if (err.name === 'JsonWebTokenError') {
      throw new AuthTokenError(
        'Invalid authentication token signature or malformed token.',
        'TOKEN_INVALID',
        401
      );
    }

    throw new AuthTokenError(
      `Token verification failed: ${err.message}`,
      'TOKEN_VERIFICATION_FAILED',
      401
    );
  }
}
