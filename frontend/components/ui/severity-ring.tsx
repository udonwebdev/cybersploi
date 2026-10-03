"use client";

import React from "react";

interface SeverityBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info?: number;
}

interface SeverityRingProps {
  breakdown: SeverityBreakdown;
  size?: number;
  strokeWidth?: number;
  className?: string;
  showCenterText?: boolean;
}

export const SeverityRing: React.FC<SeverityRingProps> = ({
  breakdown,
  size = 140,
  strokeWidth = 14,
  className = "",
  showCenterText = true,
}) => {
  const { critical, high, medium, low, info = 0 } = breakdown;
  const total = critical + high + medium + low + info;

  const center = size / 2;
  const radius = center - strokeWidth;
  const circumference = 2 * Math.PI * radius;

  if (total === 0) {
    return (
      <div className={`relative inline-flex items-center justify-center ${className}`}>
        <svg width={size} height={size} className="transform -rotate-90">
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="transparent"
            stroke="#21262d"
            strokeWidth={strokeWidth}
          />
        </svg>
        {showCenterText && (
          <div className="absolute flex flex-col items-center justify-center text-center">
            <span className="text-xl font-mono font-bold text-slate-400">0</span>
            <span className="text-[10px] font-mono text-slate-500 uppercase">Vulns</span>
          </div>
        )}
      </div>
    );
  }

  // Calculate segments
  const segments = [
    { count: critical, color: "#ef4444", label: "Critical" },
    { count: high, color: "#f59e0b", label: "High" },
    { count: medium, color: "#eab308", label: "Medium" },
    { count: low, color: "#3b82f6", label: "Low" },
    { count: info, color: "#64748b", label: "Info" },
  ].filter((s) => s.count > 0);

  let accumulatedPercent = 0;

  return (
    <div className={`relative inline-flex items-center justify-center ${className}`}>
      <svg width={size} height={size} className="transform -rotate-90">
        {/* Background track */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="transparent"
          stroke="#161b22"
          strokeWidth={strokeWidth}
        />
        {/* Render segments */}
        {segments.map((segment, idx) => {
          const percent = segment.count / total;
          const strokeDasharray = `${circumference * percent} ${circumference * (1 - percent)}`;
          const strokeDashoffset = -circumference * accumulatedPercent;
          accumulatedPercent += percent;

          return (
            <circle
              key={idx}
              cx={center}
              cy={center}
              r={radius}
              fill="transparent"
              stroke={segment.color}
              strokeWidth={strokeWidth}
              strokeDasharray={strokeDasharray}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap={segments.length === 1 ? "round" : "butt"}
              className="transition-all duration-700 ease-out"
            />
          );
        })}
      </svg>
      {showCenterText && (
        <div className="absolute flex flex-col items-center justify-center text-center pointer-events-none">
          <span className="text-2xl font-mono font-black text-slate-100">{total}</span>
          <span className="text-[10px] font-mono uppercase tracking-widest text-slate-400">
            {critical > 0 ? "Threats" : "Total"}
          </span>
        </div>
      )}
    </div>
  );
};
