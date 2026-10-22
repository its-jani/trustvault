import {
  createGrant,
  revokeGrant,
  listDocumentGrants
} from '../services/grantService.js';

/**
 * Handles creation of document access grants.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
export async function createGrantHandler(req, res, next) {
  try {
    const { documentId, granteeEmail, granteeId, expiresAt, permission } = req.body;
    const grantedByUserId = req.user.id;
    const grantedByUserRole = req.user.role;
    const ipAddress = req.ip || req.socket?.remoteAddress || 'unknown';

    const grant = await createGrant({
      documentId,
      grantedByUserId,
      grantedByUserRole,
      granteeEmail,
      granteeId,
      expiresAt,
      permission,
      ipAddress
    });

    return res.status(201).json({
      message: 'Access grant created successfully.',
      grant
    });
  } catch (err) {
    return next(err);
  }
}

/**
 * Handles revocation of document access grants.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
export async function revokeGrantHandler(req, res, next) {
  try {
    const grantId = req.params.id;
    const revokedByUserId = req.user.id;
    const revokedByUserRole = req.user.role;
    const ipAddress = req.ip || req.socket?.remoteAddress || 'unknown';

    const result = await revokeGrant({
      grantId,
      revokedByUserId,
      revokedByUserRole,
      ipAddress
    });

    return res.status(200).json(result);
  } catch (err) {
    return next(err);
  }
}

/**
 * Handles listing grants for a document.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
export async function listGrantsHandler(req, res, next) {
  try {
    const { documentId } = req.params;
    const requestingUserId = req.user.id;
    const requestingUserRole = req.user.role;

    const grants = await listDocumentGrants(documentId, requestingUserId, requestingUserRole);

    return res.status(200).json({ grants });
  } catch (err) {
    return next(err);
  }
}
