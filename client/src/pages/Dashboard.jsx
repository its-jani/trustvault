import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../context/AuthContext';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../components/ui/Card';
import { Input } from '../components/ui/Input';
import { Alert, AlertDescription } from '../components/ui/Alert';
import { UploadModal } from '../components/UploadModal';
import { GrantModal } from '../components/GrantModal';
import { AuditLogViewer } from '../components/AuditLogViewer';
import { fetchDocuments, downloadDocument, deleteDocument } from '../api/documents';
import {
  ShieldCheck,
  LogOut,
  FileText,
  Share2,
  History,
  Lock,
  Upload,
  Download,
  Trash2,
  RefreshCw,
  Search,
  Filter,
  CheckCircle2,
  AlertCircle,
  Clock,
  HardDrive
} from 'lucide-react';

export const Dashboard = () => {
  const { user, logout } = useAuth();
  const [activeTab, setActiveTab] = useState('documents'); // 'documents' | 'audit'

  // Documents state
  const [documents, setDocuments] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [downloadingId, setDownloadingId] = useState(null);
  const [deletingId, setDeletingId] = useState(null);
  const [feedback, setFeedback] = useState(null); // { type: 'success' | 'error', message: '' }

  // Modals state
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [selectedGrantDoc, setSelectedGrantDoc] = useState(null);

  const loadDocuments = useCallback(async () => {
    try {
      setIsLoading(true);
      const data = await fetchDocuments();
      setDocuments(data);
    } catch (err) {
      setFeedback({
        type: 'error',
        message: err.message || 'Failed to retrieve vault documents.'
      });
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDocuments();
  }, [loadDocuments]);

  const handleDownload = async (doc) => {
    try {
      setDownloadingId(doc.id);
      setFeedback(null);
      await downloadDocument(doc.id, doc.file_name || doc.title);
      setFeedback({
        type: 'success',
        message: `Decrypted and downloaded "${doc.title}" successfully.`
      });
    } catch (err) {
      setFeedback({
        type: 'error',
        message: err.message || 'Failed to download document.'
      });
    } finally {
      setDownloadingId(null);
    }
  };

  const handleDelete = async (doc) => {
    if (!window.confirm(`Are you sure you want to permanently delete "${doc.title}" from the encrypted vault?`)) {
      return;
    }

    try {
      setDeletingId(doc.id);
      setFeedback(null);
      await deleteDocument(doc.id);
      setDocuments((prev) => prev.filter((d) => d.id !== doc.id));
      setFeedback({
        type: 'success',
        message: `Document "${doc.title}" deleted from storage and metadata catalog.`
      });
    } catch (err) {
      setFeedback({
        type: 'error',
        message: err.message || 'Failed to delete document.'
      });
    } finally {
      setDeletingId(null);
    }
  };

  const formatFileSize = (bytes) => {
    if (!bytes || bytes === 0) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  // Filter documents
  const filteredDocuments = documents.filter((doc) => {
    const matchesSearch =
      doc.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (doc.file_name && doc.file_name.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesCategory =
      selectedCategory === 'ALL' || doc.category?.toUpperCase() === selectedCategory.toUpperCase();
    return matchesSearch && matchesCategory;
  });

  const canManageDoc = (doc) => {
    return user?.role === 'ADMIN' || doc.owner_id === user?.id;
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Top Navigation */}
      <header className="border-b border-slate-800/80 bg-slate-900/60 backdrop-blur-xl sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-indigo-600 to-violet-600 flex items-center justify-center shadow-lg shadow-indigo-600/30">
              <ShieldCheck className="w-5 h-5 text-white" />
            </div>
            <div>
              <span className="font-bold text-lg tracking-tight text-white">Trust<span className="text-indigo-400">Vault</span></span>
              <span className="hidden sm:inline-block ml-2 text-[10px] font-semibold tracking-wider uppercase px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700/60">
                Zero-Trust Core
              </span>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="text-right hidden sm:block">
              <p className="text-xs font-semibold text-slate-200">{user?.full_name || user?.email}</p>
              <p className="text-[10px] text-slate-400 font-mono">{user?.email}</p>
            </div>
            <Badge variant={user?.role}>{user?.role}</Badge>
            <Button variant="outline" size="sm" onClick={logout} className="gap-1.5 cursor-pointer">
              <LogOut className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Sign Out</span>
            </Button>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
        {/* Navigation Tabs (Document Vault vs Admin Audit Trail) */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setActiveTab('documents')}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
                activeTab === 'documents'
                  ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/25'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <FileText className="w-4 h-4" />
              Encrypted Vault ({documents.length})
            </button>

            {user?.role === 'ADMIN' && (
              <button
                type="button"
                onClick={() => setActiveTab('audit')}
                className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
                  activeTab === 'audit'
                    ? 'bg-emerald-600 text-white shadow-lg shadow-emerald-600/25'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                }`}
              >
                <History className="w-4 h-4" />
                Forensic Audit Inspector
              </button>
            )}
          </div>

          {activeTab === 'documents' && (
            <Button
              variant="emerald"
              size="sm"
              onClick={() => setIsUploadOpen(true)}
              className="gap-2 cursor-pointer shadow-lg shadow-emerald-600/20"
            >
              <Upload className="w-4 h-4" />
              Upload Document
            </Button>
          )}
        </div>

        {/* Global Feedback Banner */}
        {feedback && (
          <Alert variant={feedback.type === 'error' ? 'destructive' : 'success'}>
            {feedback.type === 'error' ? (
              <AlertCircle className="w-4 h-4 shrink-0" />
            ) : (
              <CheckCircle2 className="w-4 h-4 shrink-0" />
            )}
            <AlertDescription className="flex items-center justify-between w-full">
              <span>{feedback.message}</span>
              <button
                type="button"
                onClick={() => setFeedback(null)}
                className="text-xs underline hover:no-underline ml-4"
              >
                Dismiss
              </button>
            </AlertDescription>
          </Alert>
        )}

        {/* TAB 1: Document Vault */}
        {activeTab === 'documents' && (
          <div className="space-y-6">
            {/* Search and Filter Toolbar */}
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-3 rounded-2xl bg-slate-900/40 border border-slate-800">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
                <Input
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search encrypted documents by title or file name..."
                  className="pl-9 h-9 text-xs"
                />
              </div>

              <div className="flex items-center gap-2">
                <select
                  value={selectedCategory}
                  onChange={(e) => setSelectedCategory(e.target.value)}
                  className="h-9 px-3 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
                >
                  <option value="ALL">All Categories</option>
                  <option value="GENERAL">General</option>
                  <option value="FINANCIAL">Financial</option>
                  <option value="LEGAL">Legal</option>
                  <option value="IDENTITY">Identity</option>
                  <option value="HEALTHCARE">Healthcare</option>
                  <option value="CONFIDENTIAL">Confidential</option>
                </select>

                <Button
                  variant="outline"
                  size="sm"
                  onClick={loadDocuments}
                  disabled={isLoading}
                  className="h-9 px-2.5 cursor-pointer"
                  title="Reload document list"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
                </Button>
              </div>
            </div>

            {/* Document Cards Grid / Table */}
            {isLoading ? (
              <div className="p-16 rounded-2xl border border-slate-800 text-center flex flex-col items-center justify-center gap-3">
                <RefreshCw className="w-8 h-8 text-indigo-400 animate-spin" />
                <p className="text-sm text-slate-400 font-medium">
                  Validating cryptographic permissions and querying vault records...
                </p>
              </div>
            ) : filteredDocuments.length === 0 ? (
              <div className="p-16 rounded-2xl border border-dashed border-slate-800 text-center space-y-4">
                <div className="w-12 h-12 rounded-xl bg-slate-800/60 border border-slate-700/60 text-slate-400 flex items-center justify-center mx-auto">
                  <FileText className="w-6 h-6" />
                </div>
                <div>
                  <h3 className="text-base font-semibold text-slate-200">No documents found</h3>
                  <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
                    {searchQuery || selectedCategory !== 'ALL'
                      ? 'No documents match your active search or category filters.'
                      : 'Your vault is currently empty. Upload your first encrypted document to secure it with AES-256-GCM.'}
                  </p>
                </div>
                {!searchQuery && selectedCategory === 'ALL' && (
                  <Button
                    variant="emerald"
                    size="sm"
                    onClick={() => setIsUploadOpen(true)}
                    className="gap-2"
                  >
                    <Upload className="w-3.5 h-3.5" />
                    Upload Now
                  </Button>
                )}
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filteredDocuments.map((doc) => {
                  const isOwner = doc.owner_id === user?.id;
                  const isDownloading = downloadingId === doc.id;
                  const isDeleting = deletingId === doc.id;

                  return (
                    <Card
                      key={doc.id}
                      className="border-slate-800/90 bg-slate-900/60 backdrop-blur-md hover:border-slate-700 transition-all flex flex-col justify-between"
                    >
                      <CardHeader className="pb-3">
                        <div className="flex items-start justify-between gap-2">
                          <div className="w-9 h-9 rounded-lg bg-indigo-950/80 border border-indigo-700/40 text-indigo-400 flex items-center justify-center shrink-0">
                            <FileText className="w-4 h-4" />
                          </div>
                          <div className="flex items-center gap-1.5 flex-wrap justify-end">
                            <Badge variant="outline" className="text-[10px] uppercase">
                              {doc.category || 'General'}
                            </Badge>
                            {isOwner ? (
                              <Badge variant="OWNER" className="text-[10px]">Owner</Badge>
                            ) : user?.role === 'ADMIN' ? (
                              <Badge variant="ADMIN" className="text-[10px]">Admin View</Badge>
                            ) : (
                              <Badge variant="VIEWER" className="text-[10px]">Granted</Badge>
                            )}
                          </div>
                        </div>

                        <CardTitle className="text-base font-semibold text-slate-100 truncate mt-2" title={doc.title}>
                          {doc.title}
                        </CardTitle>
                        <CardDescription className="text-xs text-slate-400 truncate font-mono">
                          {doc.file_name || doc.title}
                        </CardDescription>
                      </CardHeader>

                      <CardContent className="space-y-4 pt-0">
                        {/* Metadata stats */}
                        <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/60 grid grid-cols-2 gap-2 text-[11px] text-slate-400">
                          <div className="flex items-center gap-1.5">
                            <HardDrive className="w-3.5 h-3.5 text-slate-500" />
                            <span>{formatFileSize(doc.file_size)}</span>
                          </div>
                          <div className="flex items-center gap-1.5 justify-end">
                            <Clock className="w-3.5 h-3.5 text-slate-500" />
                            <span>
                              {doc.created_at ? new Date(doc.created_at).toLocaleDateString() : 'Stored'}
                            </span>
                          </div>
                        </div>

                        {/* Action buttons */}
                        <div className="flex items-center justify-between gap-2 pt-1 border-t border-slate-800/60">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleDownload(doc)}
                            disabled={isDownloading}
                            isLoading={isDownloading}
                            className="flex-1 gap-1.5 text-xs h-8 cursor-pointer"
                            title="Decrypt stream and download"
                          >
                            <Download className="w-3.5 h-3.5" />
                            Download
                          </Button>

                          {canManageDoc(doc) && (
                            <>
                              <Button
                                variant="secondary"
                                size="sm"
                                onClick={() => setSelectedGrantDoc(doc)}
                                className="h-8 px-2.5 text-xs gap-1 cursor-pointer"
                                title="Manage access grants"
                              >
                                <Share2 className="w-3.5 h-3.5" />
                                <span className="hidden sm:inline">Grants</span>
                              </Button>

                              <Button
                                variant="destructive"
                                size="sm"
                                onClick={() => handleDelete(doc)}
                                disabled={isDeleting}
                                isLoading={isDeleting}
                                className="h-8 px-2.5 text-xs cursor-pointer"
                                title="Permanently delete document"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </Button>
                            </>
                          )}
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* TAB 2: Admin Forensic Audit Inspector */}
        {activeTab === 'audit' && user?.role === 'ADMIN' && (
          <AuditLogViewer />
        )}
      </main>

      {/* Upload Modal */}
      <UploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onUploadSuccess={(newDoc) => {
          setDocuments((prev) => [newDoc, ...prev]);
          setFeedback({
            type: 'success',
            message: `Document "${newDoc.title}" encrypted with AES-256-GCM and stored successfully.`
          });
        }}
      />

      {/* Grant Delegation Modal */}
      <GrantModal
        isOpen={!!selectedGrantDoc}
        onClose={() => setSelectedGrantDoc(null)}
        document={selectedGrantDoc}
      />
    </div>
  );
};

export default Dashboard;
