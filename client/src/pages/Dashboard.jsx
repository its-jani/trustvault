import React from 'react';
import { useAuth } from '../context/AuthContext';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../components/ui/Card';
import { ShieldCheck, LogOut, FileText, Share2, History, Lock } from 'lucide-react';

export const Dashboard = () => {
  const { user, logout } = useAuth();

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Top Navigation */}
      <header className="border-b border-slate-800/80 bg-slate-900/60 backdrop-blur-xl sticky top-0 z-50">
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
            <Button variant="outline" size="sm" onClick={logout} className="gap-1.5">
              <LogOut className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Sign Out</span>
            </Button>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 sm:py-12">
        <div className="mb-8">
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Security Control Center
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Authenticated as <span className="text-indigo-400 font-semibold">{user?.email}</span> with Policy Enforcement Point credentials.
          </p>
        </div>

        {/* Feature Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Card className="hover:border-slate-700/80 transition-all">
            <CardHeader>
              <div className="w-10 h-10 rounded-xl bg-indigo-950/80 border border-indigo-700/40 text-indigo-400 flex items-center justify-center mb-2">
                <FileText className="w-5 h-5" />
              </div>
              <CardTitle className="text-lg">Encrypted Vault</CardTitle>
              <CardDescription>
                AES-256-GCM envelope-encrypted files stored with ephemeral in-memory processing.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-xs text-slate-400 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                Live PEP Active (Owner / Admin / Grant)
              </div>
            </CardContent>
          </Card>

          <Card className="hover:border-slate-700/80 transition-all">
            <CardHeader>
              <div className="w-10 h-10 rounded-xl bg-violet-950/80 border border-violet-700/40 text-violet-400 flex items-center justify-center mb-2">
                <Share2 className="w-5 h-5" />
              </div>
              <CardTitle className="text-lg">Delegation Subsystem</CardTitle>
              <CardDescription>
                Grant and revoke time-bound or role-based viewing permissions with zero cache lag.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-xs text-slate-400 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-indigo-400" />
                Immediate Invalidation Engine
              </div>
            </CardContent>
          </Card>

          <Card className="hover:border-slate-700/80 transition-all">
            <CardHeader>
              <div className="w-10 h-10 rounded-xl bg-emerald-950/80 border border-emerald-700/40 text-emerald-400 flex items-center justify-center mb-2">
                <History className="w-5 h-5" />
              </div>
              <CardTitle className="text-lg">Forensic Audit Trail</CardTitle>
              <CardDescription>
                Append-only forensic logging protected by PostgreSQL database triggers.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-xs text-slate-400 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-400" />
                Trigger Enforcement: Immuntable
              </div>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;
