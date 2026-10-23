import React from 'react';
import { cn } from '../../lib/utils';

export const Input = React.forwardRef(({ className, type = 'text', error, ...props }, ref) => {
  return (
    <div className="w-full relative">
      <input
        type={type}
        ref={ref}
        className={cn(
          'flex h-11 w-full rounded-xl border bg-slate-900/80 px-4 py-2.5 text-sm text-slate-100 placeholder:text-slate-500 shadow-inner',
          'border-slate-800 transition-all duration-200 ease-in-out',
          'focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 focus:bg-slate-900',
          'disabled:cursor-not-allowed disabled:opacity-50',
          error && 'border-rose-500/80 focus:border-rose-500 focus:ring-rose-500/20',
          className
        )}
        {...props}
      />
      {error && (
        <p className="mt-1.5 text-xs text-rose-400 font-medium flex items-center gap-1">
          <span>•</span> {error}
        </p>
      )}
    </div>
  );
});

Input.displayName = 'Input';
export default Input;
