"use client";

import React from "react";
import clsx from "clsx";

interface ProgressBarProps {
  value: number; // 0 to 100
  max?: number;
  height?: "xs" | "sm" | "md" | "lg";
  variant?: "teal" | "emerald" | "amber" | "danger" | "dynamic";
  animated?: boolean;
  showValue?: boolean;
  label?: string;
  className?: string;
}

const heightMap = {
  xs: "h-1",
  sm: "h-1.5",
  md: "h-2.5",
  lg: "h-4",
};

export const ProgressBar: React.FC<ProgressBarProps> = ({
  value,
  max = 100,
  height = "sm",
  variant = "teal",
  animated = false,
  showValue = false,
  label,
  className = "",
}) => {
  const percentage = Math.min(Math.max(Math.round((value / max) * 100), 0), 100);

  let barColor = "bg-cyber-teal";
  if (variant === "emerald") barColor = "bg-cyber-emerald";
  else if (variant === "amber") barColor = "bg-amber-400";
  else if (variant === "danger") barColor = "bg-severity-critical";
  else if (variant === "dynamic") {
    if (percentage > 80) barColor = "bg-severity-critical";
    else if (percentage > 50) barColor = "bg-amber-400";
    else barColor = "bg-cyber-emerald";
  }

  return (
    <div className={clsx("w-full space-y-1.5", className)}>
      {(label || showValue) && (
        <div className="flex justify-between items-center text-xs font-mono">
          {label && <span className="text-slate-400 truncate">{label}</span>}
          {showValue && <span className="text-slate-200 font-semibold">{percentage}%</span>}
        </div>
      )}
      <div
        className={clsx(
          "w-full bg-background-subtle rounded-full overflow-hidden border border-border/60",
          heightMap[height]
        )}
      >
        <div
          className={clsx(
            "h-full rounded-full transition-all duration-500 ease-out",
            barColor,
            animated && "animate-pulse"
          )}
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  );
};
