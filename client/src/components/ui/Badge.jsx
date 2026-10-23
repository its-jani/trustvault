import React from 'react';
import { cn } from '../../lib/utils';

export const Badge = ({ className, variant = 'default', children, ...props }) => {
  const baseStyles =
    'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold tracking-wide transition-colors border select-none';

  const variants = {
    default:
      'bg-slate-800 text-slate-200 border-slate-700/80',
    ADMIN:
      'bg-violet-950/70 text-violet-300 border-violet-700/50 shadow-sm shadow-violet-900/30',
    OWNER:
      'bg-indigo-950/70 text-indigo-300 border-indigo-700/50 shadow-sm shadow-indigo-900/30',
    VIEWER:
      'bg-emerald-950/70 text-emerald-300 border-emerald-700/50 shadow-sm shadow-emerald-900/30',
    destructive:
      'bg-rose-950/70 text-rose-300 border-rose-700/50 shadow-sm shadow-rose-900/30',
    outline:
      'bg-transparent text-slate-300 border-slate-800'
  };

  return (
    <span className={cn(baseStyles, variants[variant] || variants.default, className)} {...props}>
      {children}
    </span>
  );
};

export default Badge;
