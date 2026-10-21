import supabase from '../config/supabase.js';
import { encryptBuffer, decryptBuffer } from '../utils/crypto.js';
import {
  uploadEncryptedDocument,
  downloadEncryptedDocument,
  deleteDocumentFromStorage
} from '../services/storageService.js';
import { logAuditEvent } from '../utils/auditLogger.js';

/**
 * Extracts pure storage path, IV, and auth tag from storage_path composite string.
 *
 * @param {string} compositePath
 * @returns {{ pureStoragePath: string, iv: string, authTag: string }}
 */
function parseStorageEnvelope(compositePath) {
  if (!compositePath) return { pureStoragePath: '', iv: '', authTag: '' };
  const [pureStoragePath, envelope] = compositePath.split('#');
  const [iv, authTag] = (envelope || '').split(':');
  return { pureStoragePath, iv: iv || '', authTag: authTag || '' };
}

/**
 * Ingests, encrypts with AES-256-GCM, and uploads a document to private cloud storage.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
export async function uploadDocument(req, res, next) {
  try {
    if (!req.file || !req.file.buffer) {
      return res.status(400).json({ error: 'No document file provided.' });
    }

    const userId = req.user.id;
    const originalName = req.file.originalname || 'document.bin';
    const title = (req.body.title && req.body.title.trim()) || originalName;
    const category = (req.body.category && req.body.category.trim()) || 'General';
    const mimeType = req.file.mimetype || 'application/octet-stream';
    const ipAddress = req.ip || req.socket?.remoteAddress || 'unknown';

    // 1. In-memory AES-256-GCM encryption with fresh IV
    const { encryptedBuffer, iv, authTag } = encryptBuffer(req.file.buffer);

    // 2. Virtualize storage path
    const sanitizedFilename = originalName.replace(/[^a-zA-Z0-9._-]/g, '_');
    const pureStoragePath = `documents/${userId}/${Date.now()}_${sanitizedFilename}.enc`;

    // 3. Upload ciphertext to private Supabase storage
    await uploadEncryptedDocument({
      storagePath: pureStoragePath,
      encryptedBuffer,
      mimeType: 'application/octet-stream'
    });

    // 4. Record document metadata in database
    const compositePath = `${pureStoragePath}#${iv}:${authTag}`;
    const { data: newDoc, error: insertError } = await supabase
      .from('documents')
      .insert([
        {
          title,
          category,
          storage_path: compositePath,
          file_size_bytes: req.file.size,
          mime_type: mimeType,
          owner_id: userId
        }
      ])
      .select('id, title, category, file_size_bytes, mime_type, owner_id, created_at')
      .single();

    if (insertError) {
      // Rollback orphaned storage object
      await deleteDocumentFromStorage(pureStoragePath).catch(() => {});
      return next(insertError);
    }

    // 5. Audit log
    await logAuditEvent({
      userId,
      action: 'DOCUMENT_UPLOAD_SUCCESS',
      resource: newDoc.id,
      details: {
        title: newDoc.title,
        category: newDoc.category,
        fileSizeBytes: newDoc.file_size_bytes,
        mimeType: newDoc.mime_type
      },
      ipAddress,
      status: 'SUCCESS'
    });

    return res.status(201).json({
      message: 'Document uploaded and encrypted successfully.',
      document: {
        id: newDoc.id,
        title: newDoc.title,
        file_name: newDoc.title,
        category: newDoc.category,
        file_size: newDoc.file_size_bytes,
        mime_type: newDoc.mime_type,
        owner_id: newDoc.owner_id,
        created_at: newDoc.created_at
      }
    });
  } catch (err) {
    return next(err);
  }
}

/**
 * Enforces live PEP authorization, downloads encrypted buffer, decrypts in RAM, and streams to client.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
export async function downloadDocument(req, res, next) {
  try {
    const documentId = req.params.id;
    const user = req.user;
    const ipAddress = req.ip || req.socket?.remoteAddress || 'unknown';

    // 1. Fetch Document Record
    const { data: document, error: fetchError } = await supabase
      .from('documents')
      .select('id, title, category, storage_path, file_size_bytes, mime_type, owner_id')
      .eq('id', documentId)
      .maybeSingle();

    if (fetchError) {
      return next(fetchError);
    }

    if (!document) {
      return res.status(404).json({ error: 'Document not found.' });
    }

    // 2. Policy Enforcement Point (PEP) Authorization Check
    const isOwner = user.id === document.owner_id;
    const isAdmin = user.role === 'ADMIN';

    let hasGrant = false;
    if (!isOwner && !isAdmin) {
      const { data: grant } = await supabase
        .from('document_grants')
        .select('id, permission')
        .eq('document_id', document.id)
        .eq('grantee_id', user.id)
        .maybeSingle();

      hasGrant = !!grant;
    }

    if (!isOwner && !isAdmin && !hasGrant) {
      await logAuditEvent({
        userId: user.id,
        action: 'UNAUTHORIZED_DOCUMENT_DOWNLOAD_ATTEMPT',
        resource: document.id,
        details: {
          documentTitle: document.title,
          ownerId: document.owner_id,
          userRole: user.role
        },
        ipAddress,
        status: 'DENIED'
      });

      return res.status(403).json({
        error: 'Access denied: Insufficient document permissions.'
      });
    }

    // 3. Retrieve ciphertext from private storage
    const { pureStoragePath, iv, authTag } = parseStorageEnvelope(document.storage_path);
    const encryptedBuffer = await downloadEncryptedDocument(pureStoragePath);

    // 4. Decrypt in-memory buffer
    const decryptedBuffer = decryptBuffer(encryptedBuffer, iv, authTag);

    // 5. Successful download audit log
    await logAuditEvent({
      userId: user.id,
      action: 'DOCUMENT_DOWNLOAD_SUCCESS',
      resource: document.id,
      details: {
        title: document.title,
        mimeType: document.mime_type
      },
      ipAddress,
      status: 'SUCCESS'
    });

    // 6. Send decrypted buffer with sanitized headers
    res.setHeader('Content-Type', document.mime_type || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(document.title)}"`);
    res.setHeader('Content-Length', decryptedBuffer.length);

    return res.status(200).send(decryptedBuffer);
  } catch (err) {
    return next(err);
  }
}

/**
 * Lists documents accessible to the authenticated user (Owned, Granted, or All if Admin).
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
export async function listDocuments(req, res, next) {
  try {
    const user = req.user;

    let query = supabase
      .from('documents')
      .select('id, title, category, file_size_bytes, mime_type, owner_id, created_at');

    if (user.role !== 'ADMIN') {
      // Find IDs granted to user
      const { data: grants } = await supabase
        .from('document_grants')
        .select('document_id')
        .eq('grantee_id', user.id);

      const grantedDocIds = (grants || []).map((g) => g.document_id);

      if (grantedDocIds.length > 0) {
        query = query.or(`owner_id.eq.${user.id},id.in.(${grantedDocIds.join(',')})`);
      } else {
        query = query.eq('owner_id', user.id);
      }
    }

    const { data: documents, error } = await query.order('created_at', { ascending: false });

    if (error) {
      return next(error);
    }

    const sanitizedList = (documents || []).map((doc) => ({
      id: doc.id,
      title: doc.title,
      file_name: doc.title,
      category: doc.category,
      file_size: doc.file_size_bytes,
      mime_type: doc.mime_type,
      owner_id: doc.owner_id,
      created_at: doc.created_at
    }));

    return res.status(200).json({ documents: sanitizedList });
  } catch (err) {
    return next(err);
  }
}

/**
 * Deletes document object from cloud storage and metadata record from database.
 * Only document owners or administrators may delete documents.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
export async function deleteDocument(req, res, next) {
  try {
    const documentId = req.params.id;
    const user = req.user;
    const ipAddress = req.ip || req.socket?.remoteAddress || 'unknown';

    const { data: document, error: fetchError } = await supabase
      .from('documents')
      .select('id, title, storage_path, owner_id')
      .eq('id', documentId)
      .maybeSingle();

    if (fetchError) {
      return next(fetchError);
    }

    if (!document) {
      return res.status(404).json({ error: 'Document not found.' });
    }

    // PEP Authorization Check: Owner or Admin only
    if (user.id !== document.owner_id && user.role !== 'ADMIN') {
      await logAuditEvent({
        userId: user.id,
        action: 'UNAUTHORIZED_DOCUMENT_DELETE_ATTEMPT',
        resource: document.id,
        details: {
          documentTitle: document.title,
          ownerId: document.owner_id,
          userRole: user.role
        },
        ipAddress,
        status: 'DENIED'
      });

      return res.status(403).json({
        error: 'Access denied: Only document owners or administrators may delete documents.'
      });
    }

    // 1. Remove blob from cloud storage
    const { pureStoragePath } = parseStorageEnvelope(document.storage_path);
    await deleteDocumentFromStorage(pureStoragePath).catch((err) => {
      console.warn('[TrustVault Storage Cleanup Warning]:', err.message);
    });

    // 2. Remove row from database (cascades to document_grants)
    const { error: deleteError } = await supabase
      .from('documents')
      .delete()
      .eq('id', document.id);

    if (deleteError) {
      return next(deleteError);
    }

    // 3. Audit log
    await logAuditEvent({
      userId: user.id,
      action: 'DOCUMENT_DELETED',
      resource: document.id,
      details: { title: document.title, ownerId: document.owner_id },
      ipAddress,
      status: 'SUCCESS'
    });

    return res.status(200).json({
      message: 'Document deleted successfully.',
      id: document.id
    });
  } catch (err) {
    return next(err);
  }
}

export default {
  uploadDocument,
  downloadDocument,
  listDocuments,
  deleteDocument
};
