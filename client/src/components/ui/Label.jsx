import React from 'react';
import { cn } from '../../lib/utils';

export const Label = React.forwardRef(({ className, children, ...props }, ref) => (
  <label
    ref={ref}
    className={cn(
      'block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5 select-none',
      className
    )}
    {...props}
  >
    {children}
  </label>
));

Label.displayName = 'Label';
export default Label;
