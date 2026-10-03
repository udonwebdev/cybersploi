import React from "react";
import clsx from "clsx";

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  helperText?: string;
}

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, helperText, className, id, ...props }, ref) => {
    const inputId = id || (label ? label.toLowerCase().replace(/\s+/g, "-") : undefined);

    return (
      <div className="w-full">
        {label && (
          <label htmlFor={inputId} className="block text-xs font-medium text-slate-300 mb-1.5 uppercase tracking-wider font-mono">
            {label}
          </label>
        )}
        <div className="relative">
          <input
            id={inputId}
            ref={ref}
            className={clsx(
              "w-full px-3.5 py-2 bg-background-subtle border rounded-md text-sm text-slate-100 placeholder-slate-500 transition-colors focus:outline-none focus:ring-1",
              error
                ? "border-severity-critical focus:ring-severity-critical"
                : "border-border focus:border-cyber-teal focus:ring-cyber-teal",
              className
            )}
            {...props}
          />
        </div>
        {error && <p className="mt-1 text-xs text-severity-critical">{error}</p>}
        {helperText && !error && <p className="mt-1 text-xs text-slate-400">{helperText}</p>}
      </div>
    );
  }
);
Input.displayName = "Input";
