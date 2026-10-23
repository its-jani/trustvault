import apiClient from './client';

/**
 * Lists all active access grants for a document.
 *
 * @param {string} documentId - Document UUID
 * @returns {Promise<Array>} List of grant objects
 */
export async function fetchDocumentGrants(documentId) {
  const response = await apiClient(`/grants/document/${documentId}`);
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.error || errorData.message || 'Failed to fetch document grants.');
  }
  const data = await response.json();
  return data.grants || [];
}

/**
 * Delegates view access on a document to another registered user.
 *
 * @param {Object} params
 * @param {string} params.documentId - Document UUID
 * @param {string} [params.granteeEmail] - Recipient user email
 * @param {string} [params.granteeId] - Recipient user ID (if email not provided)
 * @param {string} [params.permission='VIEW'] - Permission level
 * @param {string} [params.expiresAt] - Optional ISO expiration date
 * @returns {Promise<Object>} Created grant object
 */
export async function createGrant({ documentId, granteeEmail, granteeId, permission = 'VIEW', expiresAt }) {
  const response = await apiClient('/grants', {
    method: 'POST',
    body: JSON.stringify({
      documentId,
      granteeEmail,
      granteeId,
      permission,
      expiresAt: expiresAt || null
    })
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.error || errorData.message || 'Failed to delegate access grant.');
  }

  const data = await response.json();
  return data.grant;
}

/**
 * Revokes a document access grant immediately.
 *
 * @param {string} grantId - Grant UUID
 * @returns {Promise<Object>}
 */
export async function revokeGrant(grantId) {
  const response = await apiClient(`/grants/${grantId}`, {
    method: 'DELETE'
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.error || errorData.message || 'Failed to revoke access grant.');
  }

  return await response.json();
}
