"use client";

import React, { useEffect, useRef } from "react";
import clsx from "clsx";

interface TerminalLogProps {
  logs: string[];
  maxHeight?: string;
  className?: string;
  autoScroll?: boolean;
  title?: string;
}

export const TerminalLog: React.FC<TerminalLogProps> = ({
  logs,
  maxHeight = "320px",
  className = "",
  autoScroll = true,
  title = "EXECUTION AUDIT LOG STREAM",
}) => {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  // Syntax highlight log lines
  const formatLine = (line: string) => {
    if (line.includes("[CRITICAL]") || line.includes("ERR") || line.includes("FAIL")) {
      return <span className="text-red-400 font-semibold">{line}</span>;
    }
    if (line.includes("[WARN]") || line.includes("WARNING")) {
      return <span className="text-amber-400">{line}</span>;
    }
    if (line.includes("[SUCCESS]") || line.includes("OK") || line.includes("PASS")) {
      return <span className="text-emerald-400">{line}</span>;
    }
    if (line.includes("[INFO]") || line.includes("EXEC")) {
      return <span className="text-cyber-cyan">{line}</span>;
    }
    return <span className="text-slate-300">{line}</span>;
  };

  return (
    <div
      className={clsx(
        "rounded-lg border border-border bg-[#070b12] font-mono text-xs overflow-hidden shadow-lg",
        className
      )}
    >
      {/* Terminal Bar */}
      <div className="flex items-center justify-between px-3.5 py-2 border-b border-border/80 bg-background-card/80">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500/80 inline-block"></span>
            <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/80 inline-block"></span>
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80 inline-block"></span>
          </div>
          <span className="text-[11px] font-mono text-slate-400 ml-2 font-medium tracking-wide">
            {title}
          </span>
        </div>
        <span className="text-[10px] text-slate-500 font-mono uppercase tracking-widest">
          {logs.length} entries
        </span>
      </div>

      {/* Terminal Screen */}
      <div
        ref={containerRef}
        style={{ maxHeight }}
        className="p-3.5 overflow-y-auto space-y-1 select-text scroll-smooth"
      >
        {logs.length === 0 ? (
          <p className="text-slate-500 italic py-2">Awaiting telemetry telemetry stream...</p>
        ) : (
          logs.map((log, index) => (
            <div key={index} className="flex items-start gap-2 leading-relaxed">
              <span className="text-slate-600 select-none text-[10px] w-6 text-right shrink-0">
                {index + 1}
              </span>
              <span className="text-cyber-teal shrink-0 select-none">&gt;</span>
              <span className="break-all">{formatLine(log)}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
