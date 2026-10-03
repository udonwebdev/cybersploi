"use client";

import React from "react";
import { useToastStore } from "@/lib/store/toast-store";
import clsx from "clsx";

export const ToastContainer: React.FC = () => {
  const { toasts, removeToast } = useToastStore();

  if (toasts.length === 0) return null;

  const typeStyles = {
    success: "border-cyber-emerald/60 bg-emerald-950/90 text-emerald-100",
    error: "border-severity-critical/60 bg-red-950/90 text-red-100",
    warning: "border-severity-high/60 bg-amber-950/90 text-amber-100",
    info: "border-cyber-teal/60 bg-slate-900/95 text-slate-100",
  };

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={clsx(
            "p-4 rounded-lg border shadow-xl backdrop-blur-md pointer-events-auto transition-all animate-in slide-in-from-right-5 duration-200 flex items-start justify-between gap-3",
            typeStyles[t.type || "info"]
          )}
        >
          <div>
            <h4 className="text-sm font-semibold font-mono tracking-wide">{t.title}</h4>
            {t.description && <p className="text-xs opacity-80 mt-1">{t.description}</p>}
          </div>
          <button
            onClick={() => removeToast(t.id)}
            className="text-white/60 hover:text-white p-1"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      ))}
    </div>
  );
};
