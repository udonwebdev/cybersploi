"use client";

import React, { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import clsx from "clsx";
import {
  HomeIcon,
  ServerStackIcon,
  CommandLineIcon,
  EyeIcon,
  BugAntIcon,
  GlobeAltIcon,
  ClipboardDocumentCheckIcon,
  BookOpenIcon,
  DocumentChartBarIcon,
  Cog6ToothIcon,
  ChevronDoubleLeftIcon,
  ChevronDoubleRightIcon,
  FireIcon,
  ShieldExclamationIcon,
} from "@heroicons/react/24/outline";
import { BrandLogo } from "@/components/ui/brand-logo";

interface NavItem {
  label: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
}

interface NavGroup {
  title: string;
  items: NavItem[];
}

const navGroups: NavGroup[] = [
  {
    title: "Overview",
    items: [
      { label: "Dashboard", href: "/dashboard", icon: HomeIcon },
      { label: "Assets & Targets", href: "/assets", icon: ServerStackIcon },
      { label: "Vulnerabilities", href: "/vulnerabilities", icon: ShieldExclamationIcon },
    ],
  },
  {
    title: "Security Testing",
    items: [
      { label: "Security Scanner", href: "/offensive-engine", icon: ShieldExclamationIcon, badge: "Scan" },
      { label: "Penetration Testing", href: "/pentest", icon: CommandLineIcon, badge: "AI" },
      { label: "Red Team Simulations", href: "/red-team", icon: FireIcon, badge: "Sim" },
      { label: "Malware Analysis", href: "/malware-lab", icon: BugAntIcon, badge: "Lab" },
    ],
  },
  {
    title: "Defense & Monitoring",
    items: [
      { label: "Incident Response", href: "/blue-team", icon: EyeIcon },
      { label: "Threat Intelligence", href: "/threat-intel", icon: GlobeAltIcon, badge: "Live" },
      { label: "Compliance & Audits", href: "/compliance", icon: ClipboardDocumentCheckIcon },
    ],
  },
  {
    title: "Reports & Settings",
    items: [
      { label: "Security Hub", href: "/pen-hub", icon: BookOpenIcon },
      { label: "Reports", href: "/reports", icon: DocumentChartBarIcon },
      { label: "Settings", href: "/settings", icon: Cog6ToothIcon },
    ],
  },
];

export const Sidebar: React.FC = () => {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);

  return (
    <aside
      className={clsx(
        "h-screen bg-[#070b14]/95 backdrop-blur-2xl border-r border-[#1e293b]/80 transition-all duration-300 flex flex-col z-30 sticky top-0 shadow-2xl",
        collapsed ? "w-20" : "w-64"
      )}
    >
      {/* Brand Header */}
      <div className="h-16 flex items-center justify-between px-3.5 border-b border-[#1e293b] bg-gradient-to-r from-background-card/80 to-background/50">
        <div className="overflow-hidden flex items-center">
          <BrandLogo
            size={collapsed ? "sm" : "md"}
            showText={!collapsed}
            linkTo="/dashboard"
          />
        </div>
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="text-slate-400 hover:text-cyber-cyan p-1.5 rounded-lg hover:bg-white/5 transition-all ml-1"
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? (
            <ChevronDoubleRightIcon className="w-4 h-4" />
          ) : (
            <ChevronDoubleLeftIcon className="w-4 h-4" />
          )}
        </button>
      </div>

      {/* Navigation Groups */}
      <nav className="flex-1 overflow-y-auto py-4 px-3 space-y-4">
        {navGroups.map((group) => (
          <div key={group.title} className="space-y-1">
            {!collapsed && (
              <div className="px-3 pb-1.5 text-[10px] uppercase tracking-wider text-slate-500 font-semibold flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-cyber-blue/40 inline-block"></span>
                {group.title}
              </div>
            )}
            {group.items.map((item) => {
              const isActive = pathname === item.href || pathname.startsWith(`${item.href}/`);
              const Icon = item.icon;

              return (
                <Link
                  key={item.href}
                  href={item.href}
                  title={collapsed ? item.label : undefined}
                  className={clsx(
                    "flex items-center gap-3 px-3 py-2 rounded-xl text-xs font-medium transition-all group relative",
                    isActive
                      ? "bg-gradient-to-r from-cyber-blue/20 to-cyber-cyan/10 text-white font-semibold border border-cyber-cyan/40 shadow-glow"
                      : "text-slate-400 hover:text-slate-100 hover:bg-white/[0.04] hover:border-slate-800 border border-transparent"
                  )}
                >
                  <Icon
                    className={clsx(
                      "w-4 h-4 flex-shrink-0 transition-transform duration-200 group-hover:scale-110",
                      isActive ? "text-cyber-cyan filter drop-shadow-[0_0_6px_#00d2ff]" : "text-slate-400 group-hover:text-cyber-cyan"
                    )}
                  />
                  {!collapsed && (
                    <div className="flex items-center justify-between w-full">
                      <span className="truncate tracking-tight">{item.label}</span>
                      {item.badge && (
                        <span
                          className={clsx(
                            "text-[9px] font-mono px-1.5 py-0.5 rounded font-semibold uppercase tracking-wide",
                            item.badge === "Live"
                              ? "bg-emerald-950/80 text-emerald-400 border border-emerald-500/40"
                              : item.badge === "Sim"
                              ? "bg-red-950/80 text-red-400 border border-red-500/40"
                              : "bg-cyber-blue/20 text-cyber-cyan border border-cyber-cyan/40"
                          )}
                        >
                          {item.badge}
                        </span>
                      )}
                    </div>
                  )}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>

      {/* Footer System Status */}
      <div className="p-3 border-t border-[#1e293b] bg-gradient-to-t from-[#06090f] to-[#0a0e17]/80">
        <div className="flex items-center gap-2.5 p-2 rounded-xl bg-background-card/60 border border-[#1e293b]/60">
          <div className="relative flex h-2.5 w-2.5 shrink-0">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-400 shadow-[0_0_8px_#00f59b]"></span>
          </div>
          {!collapsed && (
            <div className="flex flex-col overflow-hidden min-w-0">
              <div className="flex items-center gap-1.5">
                <span className="text-[11px] font-bold text-slate-200 tracking-wide">System Status</span>
                <span className="text-[8px] font-mono px-1 py-0.2 rounded bg-emerald-500/20 text-emerald-400 uppercase font-bold">ONLINE</span>
              </div>
              <span className="text-[10px] text-slate-500 truncate">
                Ready for Security Scans
              </span>
            </div>
          )}
        </div>
      </div>
    </aside>
  );
};
export default Sidebar;
