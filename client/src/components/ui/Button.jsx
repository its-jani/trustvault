import React from 'react';
import { cn } from '../../lib/utils';
import { Loader2 } from 'lucide-react';

export const Button = React.forwardRef(
  (
    {
      className,
      variant = 'default',
      size = 'default',
      isLoading = false,
      children,
      disabled,
      ...props
    },
    ref
  ) => {
    const baseStyles =
      'inline-flex items-center justify-center font-medium transition-all duration-200 ease-in-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500/50 disabled:opacity-50 disabled:pointer-events-none active:scale-[0.98] select-none cursor-pointer';

    const variants = {
      default:
        'bg-gradient-to-r from-indigo-600 to-violet-600 text-white shadow-lg shadow-indigo-600/25 hover:from-indigo-500 hover:to-violet-500 hover:shadow-indigo-500/35 border border-indigo-400/20',
      destructive:
        'bg-rose-600 text-white shadow-lg shadow-rose-600/25 hover:bg-rose-500 border border-rose-500/20',
      outline:
        'border border-slate-800 bg-slate-900/60 text-slate-200 hover:bg-slate-800/80 hover:text-white hover:border-slate-700',
      secondary:
        'bg-slate-800 text-slate-100 hover:bg-slate-750 border border-slate-700/60',
      ghost:
        'text-slate-400 hover:text-slate-100 hover:bg-slate-800/60',
      emerald:
        'bg-gradient-to-r from-emerald-600 to-teal-600 text-white shadow-lg shadow-emerald-600/25 hover:from-emerald-500 hover:to-teal-500 border border-emerald-400/20'
    };

    const sizes = {
      default: 'h-11 px-5 py-2.5 rounded-xl text-sm',
      sm: 'h-9 px-3.5 py-1.5 rounded-lg text-xs',
      lg: 'h-13 px-7 py-3 rounded-xl text-base font-semibold',
      icon: 'h-10 w-10 rounded-xl'
    };

    return (
      <button
        ref={ref}
        disabled={disabled || isLoading}
        className={cn(baseStyles, variants[variant], sizes[size], className)}
        {...props}
      >
        {isLoading && <Loader2 className="w-4 h-4 mr-2 animate-spin text-current" />}
        {children}
      </button>
    );
  }
);

Button.displayName = 'Button';
export default Button;
