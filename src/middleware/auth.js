import { verifyToken, AuthTokenError } from '../utils/jwt.js';
import { logAuditEvent } from '../utils/auditLogger.js';

/**
 * Authentication Policy Enforcement Point (PEP) Middleware.
 * Intercepts requests, validates Bearer JWT signatures, logs access attempts,
 * and attaches verified user identity claims to `req.user`.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
export async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;
  const ipAddress = req.ip || req.socket?.remoteAddress || 'unknown';

  if (!token) {
    await logAuditEvent({
      userId: null,
      action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
      resource: req.originalUrl,
      details: {
        method: req.method,
        path: req.originalUrl,
        reason: 'MISSING_AUTHORIZATION_HEADER'
      },
      ipAddress,
      status: 'DENIED'
    });

    return res.status(401).json({ error: 'Access token required.' });
  }

  try {
    const decoded = verifyToken(token);
    req.user = {
      id: decoded.id,
      email: decoded.email,
      role: decoded.role
    };
    return next();
  } catch (err) {
    const errorCode = err instanceof AuthTokenError ? err.code : 'TOKEN_INVALID';

    await logAuditEvent({
      userId: null,
      action: 'INVALID_TOKEN_ATTEMPT',
      resource: req.originalUrl,
      details: {
        method: req.method,
        path: req.originalUrl,
        errorCode,
        errorMessage: err.message
      },
      ipAddress,
      status: 'DENIED'
    });

    return res.status(401).json({
      error: err.message || 'Invalid or expired token.',
      code: errorCode
    });
  }
}

export default authenticateToken;
