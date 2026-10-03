"use client";

import React from "react";
import clsx from "clsx";

export type StatusType = "online" | "offline" | "degraded" | "warning" | "running" | "critical";

interface StatusPulseProps {
  status: StatusType;
  label?: string;
  size?: "sm" | "md" | "lg";
  className?: string;
  showText?: boolean;
}

const statusConfig: Record<StatusType, { color: string; bgPing: string; defaultLabel: string }> = {
  online: {
    color: "bg-cyber-emerald",
    bgPing: "bg-cyber-emerald",
    defaultLabel: "ONLINE",
  },
  offline: {
    color: "bg-slate-500",
    bgPing: "bg-slate-500",
    defaultLabel: "OFFLINE",
  },
  degraded: {
    color: "bg-amber-400",
    bgPing: "bg-amber-400",
    defaultLabel: "DEGRADED",
  },
  warning: {
    color: "bg-amber-500",
    bgPing: "bg-amber-500",
    defaultLabel: "WARNING",
  },
  running: {
    color: "bg-cyber-teal",
    bgPing: "bg-cyber-teal",
    defaultLabel: "RUNNING",
  },
  critical: {
    color: "bg-severity-critical",
    bgPing: "bg-severity-critical",
    defaultLabel: "CRITICAL",
  },
};

const sizeMap = {
  sm: { dot: "w-2 h-2", ping: "w-2 h-2", text: "text-[10px]" },
  md: { dot: "w-2.5 h-2.5", ping: "w-2.5 h-2.5", text: "text-xs" },
  lg: { dot: "w-3 h-3", ping: "w-3 h-3", text: "text-sm" },
};

export const StatusPulse: React.FC<StatusPulseProps> = ({
  status,
  label,
  size = "md",
  className = "",
  showText = true,
}) => {
  const config = statusConfig[status] || statusConfig.online;
  const sizes = sizeMap[size];

  return (
    <span className={clsx("inline-flex items-center gap-2 font-mono font-medium", className)}>
      <span className={clsx("relative flex", sizes.dot)}>
        {status !== "offline" && (
          <span
            className={clsx(
              "animate-ping absolute inline-flex h-full w-full rounded-full opacity-75",
              config.bgPing
            )}
          />
        )}
        <span className={clsx("relative inline-flex rounded-full", sizes.dot, config.color)} />
      </span>
      {showText && (
        <span className={clsx(sizes.text, "tracking-wider uppercase text-slate-300")}>
          {label || config.defaultLabel}
        </span>
      )}
    </span>
  );
};
