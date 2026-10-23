import apiClient from './client';

/**
 * Queries immutable audit logs (Admin privilege required).
 *
 * @param {Object} [params={}]
 * @param {string} [params.action] - Action filter (e.g. 'UNAUTHORIZED_ACCESS_ATTEMPT')
 * @param {string} [params.actorId] - User UUID filter
 * @param {string} [params.documentId] - Document UUID filter
 * @param {string} [params.startDate] - Start date (ISO 8601)
 * @param {string} [params.endDate] - End date (ISO 8601)
 * @param {number} [params.page=1] - Page number (1-indexed)
 * @param {number} [params.limit=25] - Records per page (max 100)
 * @returns {Promise<{ data: Array, count: number, page: number, totalPages: number }>}
 */
export async function fetchAuditLogs(params = {}) {
  const query = new URLSearchParams();
  if (params.action) query.set('action', params.action);
  if (params.actorId) query.set('actorId', params.actorId);
  if (params.documentId) query.set('documentId', params.documentId);
  if (params.startDate) query.set('startDate', params.startDate);
  if (params.endDate) query.set('endDate', params.endDate);
  if (params.page) query.set('page', String(params.page));
  if (params.limit) query.set('limit', String(params.limit));

  const queryString = query.toString();
  const endpoint = `/audit-logs${queryString ? `?${queryString}` : ''}`;

  const response = await apiClient(endpoint);

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.error || errorData.message || 'Failed to fetch audit logs.');
  }

  return await response.json();
}
