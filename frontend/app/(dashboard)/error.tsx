"use client";

import React, { useEffect } from "react";
import { Button } from "@/components/ui/button";

export default function DashboardError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("Dashboard error:", error);
  }, [error]);

  return (
    <div className="min-h-[60vh] flex flex-col items-center justify-center text-center p-6">
      <div className="w-12 h-12 rounded-full bg-red-950/80 border border-red-800/60 flex items-center justify-center text-severity-critical mb-4">
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
      </div>
      <h2 className="text-xl font-mono font-bold text-slate-100 mb-2">Module Telemetry Failure</h2>
      <p className="text-sm text-slate-400 max-w-md mb-6">
        An error occurred while loading this security module: {error.message || "Unknown error"}
      </p>
      <div className="flex gap-4">
        <Button variant="primary" onClick={() => reset()}>
          Retry Telemetry Sync
        </Button>
        <Button variant="secondary" onClick={() => window.location.href = "/dashboard"}>
          Return to Dashboard
        </Button>
      </div>
    </div>
  );
}
