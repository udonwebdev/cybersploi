"use client";

import React from "react";
import clsx from "clsx";
import { AnimatedCounter } from "./animated-counter";

export type MetricAccent = "teal" | "cyan" | "emerald" | "amber" | "danger" | "neutral" | "purple";

interface MetricCardProps {
  title: string;
  value: number;
  suffix?: string;
  description?: string;
  icon?: React.ComponentType<{ className?: string }>;
  accent?: MetricAccent;
  trend?: {
    value: number;
    label: string;
    direction: "up" | "down" | "neutral";
  };
  className?: string;
}

const accentMap: Record<MetricAccent, { border: string; text: string; glow: string; bg: string; iconBg: string }> = {
  cyan: {
    border: "border-l-cyber-cyan",
    text: "text-cyber-cyan",
    glow: "hover:border-cyber-cyan/60 hover:shadow-glow",
    bg: "from-cyber-cyan/10 via-cyber-blue/5 to-transparent",
    iconBg: "bg-cyber-cyan/15 text-cyber-cyan border-cyber-cyan/30",
  },
  teal: {
    border: "border-l-cyber-cyan",
    text: "text-cyber-cyan",
    glow: "hover:border-cyber-cyan/60 hover:shadow-glow",
    bg: "from-cyber-cyan/10 via-cyber-blue/5 to-transparent",
    iconBg: "bg-cyber-cyan/15 text-cyber-cyan border-cyber-cyan/30",
  },
  emerald: {
    border: "border-l-cyber-emerald",
    text: "text-emerald-400",
    glow: "hover:border-emerald-500/60 hover:shadow-glow-emerald",
    bg: "from-emerald-950/30 to-transparent",
    iconBg: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  },
  amber: {
    border: "border-l-amber-500",
    text: "text-amber-400",
    glow: "hover:border-amber-500/60 hover:shadow-glow-warning",
    bg: "from-amber-950/30 to-transparent",
    iconBg: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  },
  danger: {
    border: "border-l-severity-critical",
    text: "text-rose-400",
    glow: "hover:border-rose-500/60 hover:shadow-glow-danger",
    bg: "from-rose-950/30 to-transparent",
    iconBg: "bg-rose-500/15 text-rose-400 border-rose-500/30",
  },
  purple: {
    border: "border-l-cyber-purple",
    text: "text-purple-400",
    glow: "hover:border-purple-500/60",
    bg: "from-purple-950/30 to-transparent",
    iconBg: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  },
  neutral: {
    border: "border-l-slate-600",
    text: "text-slate-200",
    glow: "hover:border-slate-500",
    bg: "from-white/[0.02] to-transparent",
    iconBg: "bg-slate-800 text-slate-300 border-slate-700",
  },
};

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  suffix = "",
  description,
  icon: Icon,
  accent = "cyan",
  trend,
  className = "",
}) => {
  const styling = accentMap[accent] || accentMap.cyan;

  return (
    <div
      className={clsx(
        "relative rounded-2xl border border-[#1e293b] bg-background-card/90 backdrop-blur-xl p-5",
        "border-l-4 transition-all duration-300 shadow-glass",
        styling.border,
        styling.glow,
        "bg-gradient-to-br",
        styling.bg,
        className
      )}
    >
      <div className="flex items-start justify-between">
        <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-bold">
          {title}
        </span>
        {Icon && (
          <div className={clsx("p-2 rounded-xl border shadow-sm", styling.iconBg)}>
            <Icon className="w-4 h-4" />
          </div>
        )}
      </div>

      <div className="mt-3 flex items-baseline gap-1">
        <h3 className={clsx("text-3xl font-mono font-black tracking-tight", styling.text)}>
          <AnimatedCounter value={value} />
        </h3>
        {suffix && <span className="text-sm font-mono text-slate-400 font-bold">{suffix}</span>}
      </div>

      {(description || trend) && (
        <div className="mt-2.5 flex items-center justify-between gap-2 text-xs font-mono border-t border-[#1e293b]/60 pt-2.5">
          {description && <p className="text-[11px] text-slate-400 leading-snug truncate">{description}</p>}
          {trend && (
            <span
              className={clsx(
                "text-[10px] px-2 py-0.5 rounded-full font-black shrink-0 tracking-wider",
                trend.direction === "up" && "bg-rose-950/80 text-rose-400 border border-rose-800/60 shadow-glow-danger",
                trend.direction === "down" && "bg-emerald-950/80 text-emerald-400 border border-emerald-800/60 shadow-glow-emerald",
                trend.direction === "neutral" && "bg-slate-800 text-slate-400 border border-slate-700"
              )}
            >
              {trend.direction === "up" ? "▲" : trend.direction === "down" ? "▼" : "•"} {trend.value}% {trend.label}
            </span>
          )}
        </div>
      )}
    </div>
  );
};
