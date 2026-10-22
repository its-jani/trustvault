import { queryAuditLogs } from '../services/auditService.js';

/**
 * Handles administrative query and inspection of audit logs.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
export async function getAuditLogsHandler(req, res, next) {
  try {
    const { action, actorId, actor_id, documentId, document_id, startDate, endDate, limit, page } = req.query;
    const ipAddress = req.ip || req.socket?.remoteAddress || 'unknown';

    const result = await queryAuditLogs({
      requesterUser: req.user,
      action,
      actorId: actorId || actor_id,
      documentId: documentId || document_id,
      startDate,
      endDate,
      limit,
      page,
      ipAddress
    });

    return res.status(200).json(result);
  } catch (err) {
    return next(err);
  }
}
