import React from "react";
import clsx from "clsx";

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: "critical" | "high" | "medium" | "low" | "info" | "success" | "outline" | "warning" | "destructive" | "default";
  size?: "sm" | "md";
  pulse?: boolean;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  className,
  variant = "info",
  size = "sm",
  pulse = false,
  ...props
}) => {
  const sizeStyles = {
    sm: "px-2 py-0.5 text-xs gap-1.5",
    md: "px-2.5 py-1 text-xs gap-1.5",
  };

  const variantStyles = {
    critical: "bg-red-950/80 text-red-400 border border-red-800/60 font-semibold shadow-sm",
    destructive: "bg-red-950/80 text-red-400 border border-red-800/60 font-semibold shadow-sm",
    high: "bg-amber-950/80 text-amber-400 border border-amber-800/60 font-semibold",
    warning: "bg-amber-950/80 text-amber-400 border border-amber-800/60 font-semibold",
    medium: "bg-yellow-950/80 text-yellow-400 border border-yellow-800/60",
    low: "bg-blue-950/80 text-blue-400 border border-blue-800/60",
    info: "bg-slate-800 text-slate-300 border border-slate-700",
    default: "bg-slate-800 text-slate-300 border border-slate-700",
    success: "bg-emerald-950/80 text-emerald-400 border border-emerald-800/60 font-semibold",
    outline: "bg-transparent text-slate-300 border border-border",
  };

  const dotColors: Record<string, string> = {
    critical: "bg-red-400",
    destructive: "bg-red-400",
    high: "bg-amber-400",
    warning: "bg-amber-400",
    medium: "bg-yellow-400",
    low: "bg-blue-400",
    success: "bg-emerald-400",
    info: "bg-slate-400",
    default: "bg-slate-400",
    outline: "bg-slate-400",
  };

  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-full font-mono uppercase tracking-wider transition-all",
        sizeStyles[size],
        variantStyles[variant],
        (pulse || variant === "critical" || variant === "destructive") && "animate-pulse",
        className
      )}
      {...props}
    >
      {pulse && (
        <span className={clsx("w-1.5 h-1.5 rounded-full inline-block", dotColors[variant] || "bg-current")} />
      )}
      {children}
    </span>
  );
};
