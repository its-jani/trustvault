import { logAuditEvent } from '../utils/auditLogger.js';

/**
 * Role-Based Access Control (RBAC) Policy Enforcement Point Middleware Factory.
 * Verifies that the authenticated user possesses one of the allowed roles.
 * Denials are synchronously logged to `audit_logs`.
 *
 * @param {string|string[]} allowedRoles - Single role or array of authorized roles (e.g., ['ADMIN', 'OWNER'])
 * @returns {import('express').RequestHandler}
 */
export function requireRole(allowedRoles) {
  const roles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];

  return async function rbacMiddleware(req, res, next) {
    const user = req.user;
    const ipAddress = req.ip || req.socket?.remoteAddress || 'unknown';

    if (!user || !roles.includes(user.role)) {
      await logAuditEvent({
        userId: user?.id || null,
        action: 'FORBIDDEN_ROLE_ATTEMPT',
        resource: req.originalUrl,
        details: {
          attemptedRole: user?.role || 'ANONYMOUS',
          requiredRoles: roles,
          ip: ipAddress,
          method: req.method,
          path: req.originalUrl
        },
        ipAddress,
        status: 'DENIED'
      });

      return res.status(403).json({
        error: 'Access denied: Insufficient privileges.'
      });
    }

    return next();
  };
}

export default requireRole;
