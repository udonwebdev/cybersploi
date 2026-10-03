import React from "react";
import clsx from "clsx";

export interface SelectOption {
  value: string;
  label: string;
}

export interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  options: SelectOption[];
  error?: string;
}

export const Select = React.forwardRef<HTMLSelectElement, SelectProps>(
  ({ label, options, error, className, id, ...props }, ref) => {
    const selectId = id || (label ? label.toLowerCase().replace(/\s+/g, "-") : undefined);

    return (
      <div className="w-full">
        {label && (
          <label htmlFor={selectId} className="block text-xs font-medium text-slate-300 mb-1.5 uppercase tracking-wider font-mono">
            {label}
          </label>
        )}
        <select
          id={selectId}
          ref={ref}
          className={clsx(
            "w-full px-3.5 py-2 bg-background-subtle border rounded-md text-sm text-slate-100 transition-colors focus:outline-none focus:ring-1",
            error
              ? "border-severity-critical focus:ring-severity-critical"
              : "border-border focus:border-cyber-teal focus:ring-cyber-teal",
            className
          )}
          {...props}
        >
          {options.map((opt) => (
            <option key={opt.value} value={opt.value} className="bg-background-card text-slate-100">
              {opt.label}
            </option>
          ))}
        </select>
        {error && <p className="mt-1 text-xs text-severity-critical">{error}</p>}
      </div>
    );
  }
);
Select.displayName = "Select";
