import supabase from '../config/supabase.js';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Writes an immutable audit event to Supabase audit_logs via PEP service client.
 * Catches all errors gracefully to prevent crashing core HTTP request flows.
 *
 * @param {Object} params
 * @param {string|null} [params.userId=null] - The actor UUID initiating the action
 * @param {string} params.action - Machine-readable action descriptor
 * @param {string|Object|null} [params.resource=null] - Targeted resource or document ID
 * @param {Object} [params.details={}] - Contextual details (method, path, headers, error reasons)
 * @param {string|null} [params.ipAddress=null] - Originating IP address
 * @param {string} [params.status='SUCCESS'] - Status ('SUCCESS'|'DENIED'|'FAILED')
 * @returns {Promise<Object|null>} The inserted row or null on error
 */
export async function logAuditEvent({
  userId = null,
  action,
  resource = null,
  details = {},
  ipAddress = null,
  status = 'SUCCESS'
}) {
  try {
    const validUserId = typeof userId === 'string' && UUID_REGEX.test(userId) ? userId : null;
    const documentId = typeof resource === 'string' && UUID_REGEX.test(resource) ? resource : null;

    const payload = {
      actor_id: validUserId,
      action: action || 'UNKNOWN_ACTION',
      document_id: documentId,
      details: {
        ...details,
        ...(resource && !documentId ? { resource } : {}),
        ...(userId && !validUserId ? { rawUserId: userId } : {}),
        ipAddress: ipAddress || 'unknown',
        status
      }
    };

    const { data, error } = await supabase.from('audit_logs').insert([payload]).select();

    if (error) {
      console.error('[TrustVault Audit Log Error] Failed to persist audit event:', error.message);
      return null;
    }

    return data ? data[0] : null;
  } catch (err) {
    console.error('[TrustVault Audit Log Exception] Unexpected error logging audit event:', err.message);
    return null;
  }
}

export default logAuditEvent;
