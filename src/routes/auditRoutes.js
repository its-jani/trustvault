import { Router } from 'express';
import { authenticateToken } from '../middleware/auth.js';
import { requireRole } from '../middleware/rbac.js';
import { getAuditLogsHandler } from '../controllers/auditController.js';

const router = Router();

// Apply authentication and strict admin RBAC
router.use(authenticateToken);
router.use(requireRole(['ADMIN']));

/**
 * @route   GET /api/audit-logs
 * @desc    Query, filter, and inspect immutable forensic audit events
 * @access  Protected (ADMIN only)
 */
router.get('/', getAuditLogsHandler);

export default router;
