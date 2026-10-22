import supabase from '../config/supabase.js';
import { logAuditEvent } from '../utils/auditLogger.js';
import { AppError } from '../middleware/errorHandler.js';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Queries and filters immutable audit logs with admin-only enforcement and pagination.
 *
 * @param {Object} params
 * @param {Object} params.requesterUser - Authenticated user object from req.user
 * @param {string} [params.action] - Filter by specific audit action
 * @param {string} [params.actorId] - Filter by initiating actor UUID
 * @param {string} [params.documentId] - Filter by target document UUID
 * @param {string} [params.startDate] - ISO 8601 start date
 * @param {string} [params.endDate] - ISO 8601 end date
 * @param {number|string} [params.limit=50] - Number of records per page (max 100)
 * @param {number|string} [params.page=1] - Page number (1-indexed)
 * @param {string} [params.ipAddress] - Request IP for audit logging
 */
export async function queryAuditLogs({
  requesterUser,
  action,
  actorId,
  documentId,
  startDate,
  endDate,
  limit = 50,
  page = 1,
  ipAddress
}) {
  // 1. Defense-in-depth RBAC verification
  if (!requesterUser || requesterUser.role !== 'ADMIN') {
    await logAuditEvent({
      userId: requesterUser?.id || null,
      action: 'UNAUTHORIZED_AUDIT_QUERY_ATTEMPT',
      resource: '/api/audit-logs',
      details: { attemptedRole: requesterUser?.role || 'ANONYMOUS' },
      ipAddress,
      status: 'DENIED'
    });
    throw new AppError('Access denied: Admin privileges required.', 403);
  }

  // 2. Pagination parameter sanitization
  const parsedLimit = Math.min(100, Math.max(1, parseInt(limit, 10) || 50));
  const parsedPage = Math.max(1, parseInt(page, 10) || 1);
  const offset = (parsedPage - 1) * parsedLimit;

  // 3. Query construction with count
  let query = supabase
    .from('audit_logs')
    .select('id, timestamp, actor_id, action, document_id, details, previous_hash, current_hash', { count: 'exact' });

  if (action && typeof action === 'string' && action.trim()) {
    query = query.eq('action', action.trim());
  }

  if (actorId) {
    if (!UUID_REGEX.test(actorId)) throw new AppError('Invalid actorId format. Must be a valid UUID.', 400);
    query = query.eq('actor_id', actorId);
  }

  if (documentId) {
    if (!UUID_REGEX.test(documentId)) throw new AppError('Invalid documentId format. Must be a valid UUID.', 400);
    query = query.or(`document_id.eq.${documentId},details->>documentId.eq.${documentId}`);
  }

  if (startDate) {
    const parsedStart = new Date(startDate);
    if (isNaN(parsedStart.getTime())) throw new AppError('Invalid startDate format. Must be an ISO 8601 date string.', 400);
    query = query.gte('timestamp', parsedStart.toISOString());
  }

  if (endDate) {
    const parsedEnd = new Date(endDate);
    if (isNaN(parsedEnd.getTime())) throw new AppError('Invalid endDate format. Must be an ISO 8601 date string.', 400);
    query = query.lte('timestamp', parsedEnd.toISOString());
  }

  const { data: logs, count, error } = await query
    .order('timestamp', { ascending: false })
    .range(offset, offset + parsedLimit - 1);

  if (error) throw error;

  const totalRecords = count || 0;
  const totalPages = Math.ceil(totalRecords / parsedLimit);

  // Map timestamp to created_at alias for downstream compatibility
  const normalizedLogs = (logs || []).map((log) => ({
    ...log,
    created_at: log.timestamp
  }));

  return {
    data: normalizedLogs,
    count: totalRecords,
    page: parsedPage,
    totalPages
  };
}
