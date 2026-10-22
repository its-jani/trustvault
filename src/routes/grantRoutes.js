import { Router } from 'express';
import { authenticateToken } from '../middleware/auth.js';
import {
  createGrantHandler,
  revokeGrantHandler,
  listGrantsHandler
} from '../controllers/grantController.js';

const router = Router();

// Apply authentication enforcement to all grant endpoints
router.use(authenticateToken);

/**
 * @route   POST /api/grants
 * @desc    Delegate document view access to another registered user
 * @access  Protected (Owner or ADMIN)
 */
router.post('/', createGrantHandler);

/**
 * @route   DELETE /api/grants/:id
 * @desc    Revoke document access grant immediately
 * @access  Protected (Owner, Grant Creator, or ADMIN)
 */
router.delete('/:id', revokeGrantHandler);

/**
 * @route   GET /api/grants/document/:documentId
 * @desc    List all active access grants for a document
 * @access  Protected (Owner or ADMIN)
 */
router.get('/document/:documentId', listGrantsHandler);

export default router;
