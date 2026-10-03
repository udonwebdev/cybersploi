import React from "react";
import clsx from "clsx";

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "danger" | "outline" | "ghost" | "cyan";
  size?: "sm" | "md" | "lg";
  isLoading?: boolean;
}

export const Button: React.FC<ButtonProps> = ({
  children,
  className,
  variant = "primary",
  size = "md",
  isLoading = false,
  disabled,
  ...props
}) => {
  const baseStyles =
    "inline-flex items-center justify-center font-mono text-xs font-bold uppercase tracking-wider rounded-xl transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-background disabled:opacity-50 disabled:cursor-not-allowed select-none active:scale-[0.98]";

  const sizeStyles = {
    sm: "px-3 py-1.5 text-[11px]",
    md: "px-4 py-2 text-xs",
    lg: "px-6 py-3 text-sm",
  };

  const variantStyles = {
    primary:
      "bg-gradient-to-r from-cyber-blue to-cyber-cyan text-slate-950 hover:brightness-110 focus:ring-cyber-cyan font-black shadow-glow hover:shadow-glow-lg border border-cyan-300/30",
    cyan:
      "bg-cyber-cyan text-slate-950 hover:bg-cyan-300 focus:ring-cyber-cyan font-black shadow-glow hover:shadow-glow-lg",
    secondary:
      "bg-background-card/90 text-slate-200 hover:bg-background-elevated hover:text-white border border-[#1e293b] hover:border-slate-600 focus:ring-slate-400 shadow-sm",
    danger:
      "bg-gradient-to-r from-red-600 to-rose-500 text-white hover:brightness-110 focus:ring-red-500 shadow-glow-danger border border-red-400/30",
    outline:
      "bg-transparent text-cyber-cyan border border-cyber-cyan/60 hover:bg-cyber-cyan/10 hover:border-cyber-cyan focus:ring-cyber-cyan shadow-glow",
    ghost:
      "bg-transparent text-slate-400 hover:text-slate-100 hover:bg-white/5 focus:ring-slate-500",
  };

  return (
    <button
      className={clsx(baseStyles, sizeStyles[size], variantStyles[variant], className)}
      disabled={disabled || isLoading}
      {...props}
    >
      {isLoading && (
        <svg
          className="animate-spin -ml-1 mr-2 h-3.5 w-3.5 text-current"
          xmlns="http://www.w3.org/2000/svg"
          fill="none"
          viewBox="0 0 24 24"
        >
          <circle
            className="opacity-25"
            cx="12"
            cy="12"
            r="10"
            stroke="currentColor"
            strokeWidth="4"
          />
          <path
            className="opacity-75"
            fill="currentColor"
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
          />
        </svg>
      )}
      {children}
    </button>
  );
};
