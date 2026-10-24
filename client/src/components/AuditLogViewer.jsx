import React, { useState, useEffect, useCallback } from 'react';
import {
  History,
  Filter,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  CheckCircle,
  XCircle,
  FileText,
  Clock,
  User,
  Search,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from './ui/Card';
import { Button } from './ui/Button';
import { Input } from './ui/Input';
import { Label } from './ui/Label';
import { Badge } from './ui/Badge';
import { Alert, AlertDescription } from './ui/Alert';
import { fetchAuditLogs } from '../api/audit';

const COMMON_ACTIONS = [
  { value: '', label: 'All Security Actions' },
  { value: 'DOCUMENT_UPLOAD_SUCCESS', label: 'DOCUMENT_UPLOAD_SUCCESS' },
  { value: 'DOCUMENT_DOWNLOAD_SUCCESS', label: 'DOCUMENT_DOWNLOAD_SUCCESS' },
  { value: 'UNAUTHORIZED_DOCUMENT_DOWNLOAD_ATTEMPT', label: 'UNAUTHORIZED_DOCUMENT_DOWNLOAD_ATTEMPT' },
  { value: 'DOCUMENT_DELETE_SUCCESS', label: 'DOCUMENT_DELETE_SUCCESS' },
  { value: 'UNAUTHORIZED_DOCUMENT_DELETE_ATTEMPT', label: 'UNAUTHORIZED_DOCUMENT_DELETE_ATTEMPT' },
  { value: 'GRANT_CREATED', label: 'GRANT_CREATED' },
  { value: 'GRANT_REVOKED', label: 'GRANT_REVOKED' },
  { value: 'USER_LOGIN_SUCCESS', label: 'USER_LOGIN_SUCCESS' },
  { value: 'USER_LOGIN_FAILED', label: 'USER_LOGIN_FAILED' },
  { value: 'USER_REGISTERED', label: 'USER_REGISTERED' }
];

export function AuditLogViewer() {
  const [logs, setLogs] = useState([]);
  const [count, setCount] = useState(0);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [limit, setLimit] = useState(15);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  // Filters
  const [actionFilter, setActionFilter] = useState('');
  const [actorIdFilter, setActorIdFilter] = useState('');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [expandedLogId, setExpandedLogId] = useState(null);

  const loadAuditLogs = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);
      const res = await fetchAuditLogs({
        action: actionFilter || undefined,
        actorId: actorIdFilter.trim() || undefined,
        startDate: startDate ? new Date(startDate).toISOString() : undefined,
        endDate: endDate ? new Date(endDate).toISOString() : undefined,
        page,
        limit
      });

      setLogs(res.data || []);
      setCount(res.count || 0);
      setTotalPages(res.totalPages || 1);
    } catch (err) {
      setError(err.message || 'Failed to query forensic audit logs.');
    } finally {
      setIsLoading(false);
    }
  }, [actionFilter, actorIdFilter, startDate, endDate, page, limit]);

  useEffect(() => {
    loadAuditLogs();
  }, [loadAuditLogs]);

  const handleFilterSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    loadAuditLogs();
  };

  const resetFilters = () => {
    setActionFilter('');
    setActorIdFilter('');
    setStartDate('');
    setEndDate('');
    setPage(1);
  };

  const toggleExpand = (id) => {
    setExpandedLogId((prev) => (prev === id ? null : id));
  };

  const getStatusBadge = (status) => {
    switch (status?.toUpperCase()) {
      case 'SUCCESS':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-950/60 text-emerald-400 border border-emerald-800/40">
            <CheckCircle className="w-3 h-3 text-emerald-400" />
            SUCCESS
          </span>
        );
      case 'DENIED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-rose-950/60 text-rose-400 border border-rose-800/40">
            <ShieldAlert className="w-3 h-3 text-rose-400" />
            DENIED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-amber-950/60 text-amber-400 border border-amber-800/40">
            <XCircle className="w-3 h-3 text-amber-400" />
            {status || 'UNKNOWN'}
          </span>
        );
    }
  };

  return (
    <Card className="border-slate-800 bg-slate-900/60 backdrop-blur-xl">
      <CardHeader className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-emerald-950 border border-emerald-700/50 flex items-center justify-center text-emerald-400">
              <History className="w-4 h-4" />
            </div>
            <CardTitle className="text-xl">Forensic Audit Trail</CardTitle>
          </div>
          <CardDescription className="mt-1">
            Immutable, append-only security logs guarded by database trigger enforcement ({count} records).
          </CardDescription>
        </div>

        <Button
          variant="outline"
          size="sm"
          onClick={loadAuditLogs}
          disabled={isLoading}
          className="gap-2 shrink-0"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </CardHeader>

      <CardContent className="pt-5 space-y-4">
        {error && (
          <Alert variant="destructive">
            <ShieldAlert className="w-4 h-4 shrink-0" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* Filter Controls */}
        <form onSubmit={handleFilterSubmit} className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-3">
          <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-400">
            <Filter className="w-3.5 h-3.5 text-indigo-400" />
            Filter & Search Parameters
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <div>
              <Label htmlFor="filter-action">Action Type</Label>
              <select
                id="filter-action"
                value={actionFilter}
                onChange={(e) => setActionFilter(e.target.value)}
                className="w-full h-9 px-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
              >
                {COMMON_ACTIONS.map((item) => (
                  <option key={item.value} value={item.value} className="bg-slate-900 text-slate-200">
                    {item.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <Label htmlFor="filter-actor">Actor User UUID</Label>
              <Input
                id="filter-actor"
                value={actorIdFilter}
                onChange={(e) => setActorIdFilter(e.target.value)}
                placeholder="RFC 4122 UUID..."
                className="h-9 text-xs"
              />
            </div>

            <div>
              <Label htmlFor="filter-start">From Date</Label>
              <input
                id="filter-start"
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                className="w-full h-9 px-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
              />
            </div>

            <div>
              <Label htmlFor="filter-end">To Date</Label>
              <input
                id="filter-end"
                type="date"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
                className="w-full h-9 px-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
              />
            </div>
          </div>

          <div className="flex items-center justify-end gap-2 pt-1">
            <Button type="button" variant="ghost" size="sm" onClick={resetFilters} className="text-xs">
              Clear Filters
            </Button>
            <Button type="submit" size="sm" className="text-xs gap-1.5">
              <Search className="w-3.5 h-3.5" />
              Apply Filter
            </Button>
          </div>
        </form>

        {/* Audit Log Table */}
        <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-950/40">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider text-[10px]">
                <tr>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Action</th>
                  <th className="py-3 px-4">Actor</th>
                  <th className="py-3 px-4">Resource ID</th>
                  <th className="py-3 px-4">Client IP</th>
                  <th className="py-3 px-4 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {isLoading ? (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-slate-500">
                      <RefreshCw className="w-5 h-5 animate-spin mx-auto text-indigo-400 mb-2" />
                      Loading audit records...
                    </td>
                  </tr>
                ) : logs.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-slate-500 font-sans">
                      No security audit events match the specified query filters.
                    </td>
                  </tr>
                ) : (
                  logs.map((log) => {
                    const isExpanded = expandedLogId === log.id;
                    const dateFormatted = log.created_at || log.timestamp
                      ? new Date(log.created_at || log.timestamp).toLocaleString()
                      : '-';

                    // Map values checking top-level columns and JSONB details fallback
                    const status = log.status || log.details?.status || 'SUCCESS';
                    const actor = log.actor_id || log.user_id || log.details?.actor_id || 'System';
                    const ip = log.ip_address || log.details?.ipAddress || '-';
                    const resource = log.document_id || log.details?.resource || log.details?.documentId || '-';

                    return (
                      <React.Fragment key={log.id}>
                        <tr className="hover:bg-slate-900/50 transition-colors">
                          <td className="py-3 px-4 text-slate-300 whitespace-nowrap text-[11px]">
                            {dateFormatted}
                          </td>
                          <td className="py-3 px-4 whitespace-nowrap">
                            {getStatusBadge(status)}
                          </td>
                          <td className="py-3 px-4 text-indigo-300 font-sans font-semibold whitespace-nowrap">
                            {log.action}
                          </td>
                          <td className="py-3 px-4 text-slate-400 whitespace-nowrap text-[11px]" title={actor}>
                            {actor !== 'System' ? `${actor.slice(0, 8)}...` : 'System'}
                          </td>
                          <td className="py-3 px-4 text-slate-400 whitespace-nowrap text-[11px]" title={resource}>
                            {resource !== '-' ? `${resource.slice(0, 8)}...` : '-'}
                          </td>
                          <td className="py-3 px-4 text-slate-500 whitespace-nowrap text-[11px]">
                            {ip}
                          </td>
                          <td className="py-3 px-4 text-right whitespace-nowrap">
                            <button
                              type="button"
                              onClick={() => toggleExpand(log.id)}
                              className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200 transition-colors font-sans cursor-pointer"
                            >
                              {isExpanded ? (
                                <>
                                  Hide <ChevronUp className="w-3 h-3" />
                                </>
                              ) : (
                                <>
                                  Inspect <ChevronDown className="w-3 h-3" />
                                </>
                              )}
                            </button>
                          </td>
                        </tr>

                        {isExpanded && (
                          <tr className="bg-slate-950/80">
                            <td colSpan={7} className="p-4 border-t border-slate-800/80">
                              <div className="space-y-2">
                                <div className="text-[10px] font-sans font-bold uppercase tracking-wider text-slate-400">
                                  Forensic Payload Metadata ({log.id})
                                </div>
                                <pre className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-emerald-300 overflow-x-auto max-h-48 font-mono">
                                  {JSON.stringify(
                                    {
                                      id: log.id,
                                      action: log.action,
                                      status: log.status,
                                      user_id: log.user_id,
                                      resource: log.resource,
                                      ip_address: log.ip_address,
                                      timestamp: log.timestamp || log.created_at,
                                      details: log.details
                                    },
                                    null,
                                    2
                                  )}
                                </pre>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Toolbar */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 px-4 py-3 bg-slate-900/60 border-t border-slate-800 text-xs">
            <div className="text-slate-400">
              Showing page <span className="font-semibold text-slate-200">{page}</span> of{' '}
              <span className="font-semibold text-slate-200">{totalPages}</span> ({count} total records)
            </div>

            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1 || isLoading}
                className="h-8 px-2.5 text-xs gap-1"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
                Prev
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages || isLoading}
                className="h-8 px-2.5 text-xs gap-1"
              >
                Next
                <ChevronRight className="w-3.5 h-3.5" />
              </Button>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export default AuditLogViewer;
