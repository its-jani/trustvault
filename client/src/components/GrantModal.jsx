import React, { useState, useEffect, useCallback } from 'react';
import { UserCheck, Trash2, Mail, ShieldAlert, Loader2, Clock, CheckCircle2, AlertCircle } from 'lucide-react';
import { Modal } from './ui/Modal';
import { Button } from './ui/Button';
import { Input } from './ui/Input';
import { Label } from './ui/Label';
import { Badge } from './ui/Badge';
import { Alert, AlertDescription } from './ui/Alert';
import { fetchDocumentGrants, createGrant, revokeGrant } from '../api/grants';

export function GrantModal({ isOpen, onClose, document: doc }) {
  const [grants, setGrants] = useState([]);
  const [granteeEmail, setGranteeEmail] = useState('');
  const [permission, setPermission] = useState('READ');
  const [isLoading, setIsLoading] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [revokingId, setRevokingId] = useState(null);
  const [error, setError] = useState(null);
  const [successMessage, setSuccessMessage] = useState(null);

  const loadGrants = useCallback(async () => {
    if (!doc?.id) return;
    try {
      setIsLoading(true);
      setError(null);
      const data = await fetchDocumentGrants(doc.id);
      setGrants(data);
    } catch (err) {
      setError(err.message || 'Failed to load existing document grants.');
    } finally {
      setIsLoading(false);
    }
  }, [doc?.id]);

  useEffect(() => {
    if (isOpen && doc?.id) {
      setGranteeEmail('');
      setError(null);
      setSuccessMessage(null);
      loadGrants();
    }
  }, [isOpen, doc?.id, loadGrants]);

  const handleCreateGrant = async (e) => {
    e.preventDefault();
    if (!granteeEmail.trim()) {
      setError('Please provide the recipient user email.');
      return;
    }

    try {
      setIsSubmitting(true);
      setError(null);
      setSuccessMessage(null);

      const newGrant = await createGrant({
        documentId: doc.id,
        granteeEmail: granteeEmail.trim(),
        permission
      });

      setSuccessMessage(`Access granted to ${granteeEmail.trim()}.`);
      setGranteeEmail('');
      // Optimistically append or reload
      setGrants((prev) => [newGrant, ...prev]);
    } catch (err) {
      setError(err.message || 'Failed to delegate access.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRevokeGrant = async (grantId, granteeDisplay) => {
    try {
      setRevokingId(grantId);
      setError(null);
      setSuccessMessage(null);

      await revokeGrant(grantId);
      setGrants((prev) => prev.filter((g) => g.id !== grantId));
      setSuccessMessage(`Revoked access for ${granteeDisplay || 'grantee'}.`);
    } catch (err) {
      setError(err.message || 'Failed to revoke access.');
    } finally {
      setRevokingId(null);
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Delegate Access Permissions"
      description={`Manage fine-grained PEP access grants for "${doc?.title || 'Document'}".`}
      maxWidth="max-w-xl"
    >
      <div className="space-y-5">
        {error && (
          <Alert variant="destructive">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {successMessage && (
          <Alert variant="success">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <AlertDescription>{successMessage}</AlertDescription>
          </Alert>
        )}

        {/* Delegate New Grant Form */}
        <form onSubmit={handleCreateGrant} className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-3">
          <div className="flex items-center gap-2 text-xs font-bold text-slate-300 uppercase tracking-wider">
            <UserCheck className="w-4 h-4 text-indigo-400" />
            Add New Grantee
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="sm:col-span-2">
              <Label htmlFor="grantee-email">User Email</Label>
              <div className="relative">
                <Mail className="absolute left-3 top-3 w-4 h-4 text-slate-500" />
                <Input
                  id="grantee-email"
                  type="email"
                  value={granteeEmail}
                  onChange={(e) => setGranteeEmail(e.target.value)}
                  placeholder="colleague@domain.com"
                  className="pl-9"
                  disabled={isSubmitting}
                />
              </div>
            </div>

            <div>
              <Label htmlFor="grant-permission">Permission</Label>
              <select
                id="grant-permission"
                value={permission}
                onChange={(e) => setPermission(e.target.value)}
                disabled={isSubmitting}
                className="w-full h-10 px-3 rounded-lg bg-slate-900 border border-slate-800 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
              >
                <option value="READ">VIEW (Read-only)</option>
              </select>
            </div>
          </div>

          <div className="flex justify-end pt-1">
            <Button
              type="submit"
              size="sm"
              disabled={isSubmitting || !granteeEmail.trim()}
              isLoading={isSubmitting}
              className="gap-1.5"
            >
              Grant Access
            </Button>
          </div>
        </form>

        {/* Active Grants List */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
              Active Access Grants ({grants.length})
            </span>
          </div>

          {isLoading ? (
            <div className="py-8 flex flex-col items-center justify-center text-slate-500 gap-2">
              <Loader2 className="w-5 h-5 animate-spin text-indigo-400" />
              <span className="text-xs">Loading active grants...</span>
            </div>
          ) : grants.length === 0 ? (
            <div className="p-6 rounded-xl border border-dashed border-slate-800 text-center">
              <p className="text-xs text-slate-400">
                No active delegate grants. Only the document owner and administrators can access this document.
              </p>
            </div>
          ) : (
            <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
              {grants.map((grant) => {
                const granteeDisplay =
                  grant.grantee?.email || grant.grantee?.full_name || grant.grantee_id;
                const isRevoking = revokingId === grant.id;

                return (
                  <div
                    key={grant.id}
                    className="p-3 rounded-lg bg-slate-950/40 border border-slate-800/80 flex items-center justify-between gap-3 hover:border-slate-700/80 transition-colors"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-slate-200 truncate">
                          {granteeDisplay}
                        </span>
                        <Badge variant="outline" className="text-[10px] py-0">
                          {grant.permission || 'READ'}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-2 text-[10px] text-slate-500 mt-0.5">
                        <Clock className="w-3 h-3" />
                        <span>
                          Granted on {grant.created_at ? new Date(grant.created_at).toLocaleDateString() : 'Active'}
                        </span>
                      </div>
                    </div>

                    <Button
                      type="button"
                      variant="destructive"
                      size="sm"
                      onClick={() => handleRevokeGrant(grant.id, granteeDisplay)}
                      disabled={isRevoking}
                      isLoading={isRevoking}
                      className="h-8 px-2.5 text-xs gap-1"
                      title="Revoke access immediately"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      <span className="hidden sm:inline">Revoke</span>
                    </Button>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex justify-end pt-3 border-t border-slate-800/60">
          <Button variant="outline" size="sm" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </Modal>
  );
}

export default GrantModal;
