import React from 'react';
import { cn } from '../../lib/utils';
import { AlertCircle, CheckCircle2, Info, AlertTriangle } from 'lucide-react';

export const Alert = ({ className, variant = 'default', children, ...props }) => {
  const variants = {
    default: 'bg-slate-900 border-slate-800 text-slate-200',
    destructive: 'bg-rose-950/40 border-rose-800/60 text-rose-200',
    success: 'bg-emerald-950/40 border-emerald-800/60 text-emerald-200',
    warning: 'bg-amber-950/40 border-amber-800/60 text-amber-200'
  };

  const icons = {
    default: <Info className="w-5 h-5 text-indigo-400 shrink-0 mt-0.5" />,
    destructive: <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />,
    success: <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />,
    warning: <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
  };

  return (
    <div
      role="alert"
      className={cn(
        'relative w-full rounded-xl border p-4 flex gap-3 text-sm shadow-lg',
        variants[variant],
        className
      )}
      {...props}
    >
      {icons[variant]}
      <div className="flex-1">{children}</div>
    </div>
  );
};

export const AlertTitle = ({ className, children, ...props }) => (
  <h5 className={cn('font-semibold leading-tight tracking-tight mb-1 text-white', className)} {...props}>
    {children}
  </h5>
);

export const AlertDescription = ({ className, children, ...props }) => (
  <div className={cn('text-xs opacity-90 leading-relaxed', className)} {...props}>
    {children}
  </div>
);

export default Alert;
