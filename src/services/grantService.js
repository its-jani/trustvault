import supabase from '../config/supabase.js';
import { logAuditEvent } from '../utils/auditLogger.js';
import { AppError } from '../middleware/errorHandler.js';

/**
 * Creates a new document access grant for a registered user.
 *
 * @param {Object} params
 * @param {string} params.documentId
 * @param {string} params.grantedByUserId
 * @param {string} [params.grantedByUserRole]
 * @param {string} [params.granteeEmail]
 * @param {string} [params.granteeId]
 * @param {string} [params.expiresAt]
 * @param {string} [params.permission='READ']
 * @param {string} [params.ipAddress]
 */
export async function createGrant({
  documentId,
  grantedByUserId,
  grantedByUserRole,
  granteeEmail,
  granteeId,
  expiresAt,
  permission = 'READ',
  ipAddress
}) {
  if (!documentId) throw new AppError('Document ID is required.', 400);
  if (!granteeEmail && !granteeId) throw new AppError('Grantee email or user ID is required.', 400);

  // 1. Verify Document Existence & Ownership / Admin Authority
  const { data: document, error: docError } = await supabase
    .from('documents')
    .select('id, owner_id, title')
    .eq('id', documentId)
    .maybeSingle();

  if (docError) throw docError;
  if (!document) throw new AppError('Document not found.', 404);

  const isOwner = document.owner_id === grantedByUserId;
  let isAdmin = grantedByUserRole === 'ADMIN';
  if (!isAdmin && !grantedByUserRole) {
    const { data: user } = await supabase.from('users').select('role').eq('id', grantedByUserId).maybeSingle();
    isAdmin = user?.role === 'ADMIN';
  }

  if (!isOwner && !isAdmin) {
    await logAuditEvent({
      userId: grantedByUserId,
      action: 'UNAUTHORIZED_GRANT_CREATION_ATTEMPT',
      resource: documentId,
      details: { reason: 'NON_OWNER_NON_ADMIN' },
      ipAddress,
      status: 'DENIED'
    });
    throw new AppError('Forbidden: Only the document owner or an administrator can grant access.', 403);
  }

  // 2. Lookup Grantee User
  let query = supabase.from('users').select('id, email, full_name, role');
  if (granteeEmail) {
    query = query.eq('email', granteeEmail.trim().toLowerCase());
  } else {
    query = query.eq('id', granteeId);
  }
  const { data: grantee, error: granteeError } = await query.maybeSingle();

  if (granteeError) throw granteeError;
  if (!grantee) {
    throw new AppError('Grantee user not found.', 404);
  }

  // 3. Prevent Self-Granting
  if (grantee.id === grantedByUserId) {
    throw new AppError('Cannot grant document access to yourself.', 400);
  }

  // 4. Check for Existing Active Grant
  const { data: existingGrant } = await supabase
    .from('document_grants')
    .select('id')
    .eq('document_id', documentId)
    .eq('grantee_id', grantee.id)
    .maybeSingle();

  if (existingGrant) {
    throw new AppError('Access grant already exists for this user.', 409);
  }

  // 5. Insert Record into document_grants
  const grantRecord = {
    document_id: documentId,
    grantee_id: grantee.id,
    granted_by: grantedByUserId,
    permission
  };

  const { data: newGrant, error: insertError } = await supabase
    .from('document_grants')
    .insert([grantRecord])
    .select()
    .single();

  if (insertError) throw insertError;

  // 6. Log GRANT_CREATED to audit_logs
  await logAuditEvent({
    userId: grantedByUserId,
    action: 'GRANT_CREATED',
    resource: documentId,
    details: {
      grantId: newGrant.id,
      granteeId: grantee.id,
      granteeEmail: grantee.email,
      permission,
      expiresAt: expiresAt || null
    },
    ipAddress,
    status: 'SUCCESS'
  });

  return {
    id: newGrant.id,
    document_id: newGrant.document_id,
    grantee_id: newGrant.grantee_id,
    granted_to: grantee.email,
    granted_by: newGrant.granted_by,
    permission: newGrant.permission,
    expires_at: expiresAt || null,
    created_at: newGrant.created_at
  };
}

/**
 * Revokes a document access grant.
 *
 * @param {Object} params
 * @param {string} params.grantId
 * @param {string} params.revokedByUserId
 * @param {string} [params.revokedByUserRole]
 * @param {string} [params.ipAddress]
 */
export async function revokeGrant({ grantId, revokedByUserId, revokedByUserRole, ipAddress }) {
  if (!grantId) throw new AppError('Grant ID is required.', 400);

  // 1. Fetch Existing Grant
  const { data: grant, error: fetchError } = await supabase
    .from('document_grants')
    .select('id, document_id, grantee_id, granted_by')
    .eq('id', grantId)
    .maybeSingle();

  if (fetchError) throw fetchError;
  if (!grant) throw new AppError('Grant not found.', 404);

  // 2. Fetch Document to Check Owner
  const { data: document } = await supabase
    .from('documents')
    .select('id, owner_id')
    .eq('id', grant.document_id)
    .maybeSingle();

  const isOwner = document && document.owner_id === revokedByUserId;
  const isGrantCreator = grant.granted_by === revokedByUserId;
  let isAdmin = revokedByUserRole === 'ADMIN';
  if (!isAdmin && !revokedByUserRole) {
    const { data: user } = await supabase.from('users').select('role').eq('id', revokedByUserId).maybeSingle();
    isAdmin = user?.role === 'ADMIN';
  }

  if (!isOwner && !isGrantCreator && !isAdmin) {
    await logAuditEvent({
      userId: revokedByUserId,
      action: 'UNAUTHORIZED_GRANT_REVOCATION_ATTEMPT',
      resource: grant.document_id,
      details: { grantId, reason: 'NOT_OWNER_CREATOR_OR_ADMIN' },
      ipAddress,
      status: 'DENIED'
    });
    throw new AppError('Forbidden: Insufficient permissions to revoke this grant.', 403);
  }

  // 3. Delete Grant from document_grants
  const { error: deleteError } = await supabase
    .from('document_grants')
    .delete()
    .eq('id', grantId);

  if (deleteError) throw deleteError;

  // 4. Log GRANT_REVOKED to audit_logs
  await logAuditEvent({
    userId: revokedByUserId,
    action: 'GRANT_REVOKED',
    resource: grant.document_id,
    details: {
      grantId,
      granteeId: grant.grantee_id,
      revokedBy: revokedByUserId
    },
    ipAddress,
    status: 'SUCCESS'
  });

  return { message: 'Grant revoked successfully.', grantId };
}

/**
 * Lists all active grants for a given document.
 *
 * @param {string} documentId
 * @param {string} requestingUserId
 * @param {string} [requestingUserRole]
 */
export async function listDocumentGrants(documentId, requestingUserId, requestingUserRole) {
  if (!documentId) throw new AppError('Document ID is required.', 400);

  // 1. Verify Document and Access Authority
  const { data: document, error: docError } = await supabase
    .from('documents')
    .select('id, owner_id')
    .eq('id', documentId)
    .maybeSingle();

  if (docError) throw docError;
  if (!document) throw new AppError('Document not found.', 404);

  const isOwner = document.owner_id === requestingUserId;
  let isAdmin = requestingUserRole === 'ADMIN';
  if (!isAdmin && !requestingUserRole) {
    const { data: user } = await supabase.from('users').select('role').eq('id', requestingUserId).maybeSingle();
    isAdmin = user?.role === 'ADMIN';
  }

  if (!isOwner && !isAdmin) {
    throw new AppError('Forbidden: Only the document owner or an administrator can view grants.', 403);
  }

  // 2. Fetch Active Grants
  const { data: grants, error: grantsError } = await supabase
    .from('document_grants')
    .select('id, document_id, grantee_id, granted_by, permission, created_at')
    .eq('document_id', documentId);

  if (grantsError) throw grantsError;
  if (!grants || grants.length === 0) return [];

  // 3. Join Grantee User Metadata (email, name)
  const granteeIds = grants.map((g) => g.grantee_id);
  const { data: users, error: usersError } = await supabase
    .from('users')
    .select('id, email, full_name')
    .in('id', granteeIds);

  if (usersError) throw usersError;

  const userMap = (users || []).reduce((acc, u) => {
    acc[u.id] = u;
    return acc;
  }, {});

  return grants.map((g) => ({
    id: g.id,
    document_id: g.document_id,
    grantee_id: g.grantee_id,
    grantee_email: userMap[g.grantee_id]?.email || null,
    grantee_name: userMap[g.grantee_id]?.full_name || null,
    granted_by: g.granted_by,
    permission: g.permission,
    created_at: g.created_at
  }));
}
