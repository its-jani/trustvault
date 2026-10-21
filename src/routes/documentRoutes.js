import { Router } from 'express';
import { authenticateToken } from '../middleware/auth.js';
import { uploadSingleDocument } from '../middleware/upload.js';
import {
  uploadDocument,
  downloadDocument,
  listDocuments,
  deleteDocument
} from '../controllers/documentController.js';

const router = Router();

// Apply authentication policy enforcement across all document endpoints
router.use(authenticateToken);

/**
 * @route   POST /api/documents/upload
 * @desc    Upload and encrypt document buffer via AES-256-GCM into private storage
 * @access  Protected
 */
router.post('/upload', uploadSingleDocument, uploadDocument);

/**
 * @route   GET /api/documents
 * @desc    List all documents owned by or granted to authenticated user (all if ADMIN)
 * @access  Protected
 */
router.get('/', listDocuments);

/**
 * @route   GET /api/documents/:id/download
 * @desc    Download, decrypt, and stream document buffer with live PEP authorization check
 * @access  Protected
 */
router.get('/:id/download', downloadDocument);

/**
 * @route   DELETE /api/documents/:id
 * @desc    Delete document from storage and metadata catalog (Owner or ADMIN only)
 * @access  Protected
 */
router.delete('/:id', deleteDocument);

export default router;
