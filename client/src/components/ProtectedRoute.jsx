import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { ShieldCheck } from 'lucide-react';

export const ProtectedRoute = ({ children, requiredRole }) => {
  const { user, isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center p-4">
        <div className="relative flex items-center justify-center">
          <div className="absolute w-20 h-20 bg-indigo-500/20 rounded-full blur-xl animate-pulse" />
          <div className="relative p-4 rounded-2xl bg-slate-900 border border-slate-800 shadow-xl">
            <ShieldCheck className="w-10 h-10 text-indigo-400 animate-pulse" />
          </div>
        </div>
        <div className="mt-6 flex flex-col items-center space-y-2">
          <div className="h-2 w-32 bg-slate-800 rounded-full overflow-hidden">
            <div className="h-full bg-indigo-500 rounded-full animate-[progress_1.5s_ease-in-out_infinite]" />
          </div>
          <p className="text-xs text-slate-500 font-medium tracking-wider uppercase">
            Verifying PEP Credentials...
          </p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (requiredRole && user?.role !== requiredRole && user?.role !== 'ADMIN') {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
        <div className="max-w-md w-full p-8 rounded-2xl bg-slate-900 border border-rose-900/50 text-center shadow-2xl">
          <div className="w-12 h-12 rounded-xl bg-rose-950/60 border border-rose-700/50 text-rose-400 flex items-center justify-center mx-auto mb-4">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <h2 className="text-xl font-bold text-white mb-2">Access Denied</h2>
          <p className="text-sm text-slate-400 mb-6">
            Your authenticated role (<span className="text-rose-300 font-semibold">{user?.role}</span>) does not possess permission to access this resource.
          </p>
          <a
            href="/"
            className="inline-flex items-center justify-center px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-750 text-slate-200 text-sm font-medium transition-all"
          >
            Return to Vault
          </a>
        </div>
      </div>
    );
  }

  return children;
};

export default ProtectedRoute;
