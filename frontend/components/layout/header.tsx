"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuthStore } from "@/lib/store/auth-store";
import { authApi } from "@/lib/api/auth";
import { systemApi } from "@/lib/api/system";
import {
  BellIcon,
  ArrowRightOnRectangleIcon,
  BuildingOffice2Icon,
  ShieldExclamationIcon,
  ShieldCheckIcon,
  BoltIcon,
  MagnifyingGlassIcon,
  CommandLineIcon,
} from "@heroicons/react/24/outline";
import { StatusPulse } from "@/components/ui/status-pulse";

export const Header: React.FC = () => {
  const router = useRouter();
  const { user, login, logout, token, hasConsented, initAuth } = useAuthStore();
  const [systemOnline, setSystemOnline] = useState<boolean | null>(null);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    initAuth();
    let isMounted = true;

    // Load active operator profile
    const loadProfile = async () => {
      try {
        const currentUser = await authApi.getMe();
        if (isMounted && currentUser) {
          const currentToken =
            token ||
            (typeof window !== "undefined"
              ? localStorage.getItem("cybersploi_token")
              : null);
          if (currentToken) {
            login(currentToken, currentUser);
          }
        }
      } catch (e) {
        // Silently continue if session is handled elsewhere
      }
    };

    loadProfile();

    const checkStatus = async () => {
      try {
        const health = await systemApi.getHealth();
        if (isMounted) setSystemOnline(health.status === "operational");
      } catch {
        if (isMounted) setSystemOnline(false);
      }
    };

    checkStatus();
    const interval = setInterval(checkStatus, 30000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const handleLogout = () => {
    logout();
    window.location.href = "/login";
  };

  const defaultOrgName = "CYBERSPLOI Cyber Defense Mesh";
  const orgName = mounted && user?.organizationName ? user.organizationName : defaultOrgName;

  return (
    <header className="h-16 bg-[#090e17]/85 backdrop-blur-xl border-b border-[#1e293b]/90 px-6 flex items-center justify-between sticky top-0 z-20 shadow-md">
      {/* Organization Indicator & Live Threat Banner */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2.5 px-3 py-1.5 rounded-xl bg-background-card/90 border border-[#1e293b] text-xs font-mono text-slate-300 shadow-sm">
          <div className="w-5 h-5 rounded-md bg-cyber-blue/15 border border-cyber-cyan/30 flex items-center justify-center">
            <img src="/shield-logo.png" alt="Emblem" className="w-3.5 h-3.5 object-contain" />
          </div>
          <span className="font-bold text-slate-100 tracking-tight" suppressHydrationWarning>
            {orgName}
          </span>
          <span className="text-cyber-cyan/80 text-[10px] font-black border-l border-slate-700 pl-2">
            GRID-01
          </span>
        </div>

        {/* Global Quick Action / Search bar */}
        <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-xl bg-background-subtle/90 border border-[#1e293b] text-xs font-mono text-slate-400 focus-within:border-cyber-cyan/60 transition-colors">
          <MagnifyingGlassIcon className="w-3.5 h-3.5 text-slate-500" />
          <input
            type="text"
            placeholder="Quick search assets, CVEs, nodes... (Ctrl+K)"
            className="bg-transparent text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none w-64 font-sans"
            onKeyDown={(e) => {
              if (e.key === "Enter" && e.currentTarget.value) {
                router.push(`/vulnerabilities?search=${encodeURIComponent(e.currentTarget.value)}`);
              }
            }}
          />
          <kbd className="px-1.5 py-0.5 text-[9px] bg-slate-800 text-slate-400 rounded border border-slate-700">⌘K</kbd>
        </div>

        {mounted && !hasConsented && (
          <Link
            href="/consent"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-amber-950/80 border border-amber-500/50 text-amber-300 text-xs font-mono animate-pulse shadow-glow-warning"
          >
            <ShieldExclamationIcon className="w-4 h-4 text-amber-400" />
            <span className="font-bold">Target Consent Required</span>
          </Link>
        )}
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-3.5">
        {/* Quick Pentest Trigger */}
        <Link
          href="/pentest"
          className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-gradient-to-r from-cyber-blue/20 to-cyber-cyan/20 border border-cyber-cyan/40 hover:border-cyber-cyan text-cyber-cyan hover:text-white text-xs font-mono font-bold transition-all shadow-glow hover:scale-105"
        >
          <CommandLineIcon className="w-3.5 h-3.5" />
          <span>Launch Scan</span>
        </Link>

        {/* Live Status Pill with StatusPulse */}
        <div className="flex items-center gap-2 text-xs font-mono px-3 py-1.5 rounded-full border border-[#1e293b] bg-background-card/90 backdrop-blur-sm shadow-sm">
          <StatusPulse
            status={systemOnline === true ? "online" : systemOnline === false ? "critical" : "degraded"}
            label={systemOnline === true ? "CYBERSPLOI CORE :8000" : systemOnline === false ? "CORE OFFLINE" : "SYNCING"}
            size="sm"
          />
        </div>

        {/* Notifications Bell */}
        <button
          className="relative text-slate-400 hover:text-cyber-cyan p-2 rounded-xl hover:bg-white/5 border border-transparent hover:border-slate-800 transition-colors"
          title="Security Notifications"
        >
          <BellIcon className="w-5 h-5" />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-cyber-cyan rounded-full shadow-[0_0_8px_#00d2ff]"></span>
        </button>

        {/* User Identity & Logout */}
        <div className="flex items-center gap-3 pl-3 border-l border-[#1e293b]">
          <div
            className="w-9 h-9 rounded-xl bg-gradient-to-b from-[#162032] to-[#0c121d] border border-cyber-cyan/30 flex items-center justify-center text-xs font-black text-cyber-cyan uppercase shadow-glow"
            suppressHydrationWarning
          >
            {mounted && user?.firstName ? user.firstName[0] : mounted && user?.email ? user.email[0] : "O"}
          </div>
          <div className="hidden md:flex flex-col text-left">
            <span
              className="text-xs font-bold text-slate-200 leading-none tracking-tight"
              suppressHydrationWarning
            >
              {mounted && user?.firstName ? `${user.firstName} ${user.lastName || ""}` : mounted && user?.email ? user.email : "Operator"}
            </span>
            <span
              className="text-[10px] font-mono text-cyber-cyan/80 mt-0.5 uppercase tracking-wider font-semibold"
              suppressHydrationWarning
            >
              {mounted && user?.role ? user.role : "Cyber Commander"}
            </span>
          </div>

          <button
            onClick={handleLogout}
            className="text-slate-400 hover:text-severity-critical p-2 rounded-xl hover:bg-red-500/10 border border-transparent hover:border-red-500/30 transition-all ml-1"
            title="Sign out"
          >
            <ArrowRightOnRectangleIcon className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
};
export default Header;
