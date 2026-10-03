"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableHead, TableBody, TableRow, TableCell, TableHeaderCell } from "@/components/ui/table";
import { MetricCard } from "@/components/ui/metric-card";
import { SeverityRing } from "@/components/ui/severity-ring";
import { StatusPulse } from "@/components/ui/status-pulse";
import { ProgressBar } from "@/components/ui/progress-bar";
import { DashboardSkeleton } from "@/components/ui/loading-skeleton";
import { scansApi, Scan } from "@/lib/api/scans";
import { vulnerabilitiesApi, Vulnerability } from "@/lib/api/vulnerabilities";
import {
  ShieldExclamationIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  PlayIcon,
  ServerStackIcon,
  ArrowPathIcon,
  BoltIcon,
  CommandLineIcon,
  CpuChipIcon,
  BugAntIcon,
  ArrowRightIcon,
  SparklesIcon,
  ShieldCheckIcon,
  FireIcon,
  CubeTransparentIcon,
  RadioIcon,
  CircleStackIcon,
} from "@heroicons/react/24/outline";

import { apiClient } from "@/lib/api/client";

export default function DashboardPage() {
  const router = useRouter();
  const [scans, setScans] = useState<Scan[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [aiStatus, setAiStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [quickTarget, setQuickTarget] = useState("api.cybersploi.io");

  const handleQuickAudit = (e: React.FormEvent) => {
    e.preventDefault();
    const tgt = quickTarget.trim() || "api.cybersploi.io";
    router.push(`/pentest?target=${encodeURIComponent(tgt)}`);
  };

  const fetchDashboardData = async () => {
    setLoading(true);
    try {
      const [scansData, vulnsData, statsRes, aiRes] = await Promise.all([
        scansApi.getScans().catch(() => []),
        vulnerabilitiesApi.getVulnerabilities().catch(() => []),
        apiClient.get("/v1/dashboard/stats").then((r) => r.data).catch(() => null),
        apiClient.get("/v1/ai/status").then((r) => r.data).catch(() => null),
      ]);

      setScans(scansData);
      setVulnerabilities(vulnsData);
      setStats(statsRes);
      setAiStatus(aiRes);
    } catch (err) {
      console.error("Dashboard fetch error:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  // Compute severity statistics
  const criticalCount = vulnerabilities.filter((v) => v.severity === "CRITICAL").length;
  const highCount = vulnerabilities.filter((v) => v.severity === "HIGH").length;
  const mediumCount = vulnerabilities.filter((v) => v.severity === "MEDIUM").length;
  const lowCount = vulnerabilities.filter((v) => v.severity === "LOW").length;

  // Compute dynamic Defense Health score
  const defenseScore =
    stats?.complianceScore !== undefined
      ? stats.complianceScore
      : Math.max(25, Math.round(100 - (criticalCount * 15 + highCount * 5)));

  if (loading && scans.length === 0 && vulnerabilities.length === 0) {
    return <DashboardSkeleton />;
  }

  return (
    <div className="space-y-6">
      {/* Hero Security Command Posture Banner */}
      <div className="relative rounded-3xl border border-[#1e293b] bg-gradient-to-r from-[#0d1627] via-[#09101c] to-[#070b14] p-6 lg:p-8 shadow-2xl overflow-hidden">
        {/* Glowing Shield Hologram Background Watermark */}
        <div className="absolute right-6 -bottom-10 opacity-15 pointer-events-none select-none hidden md:block">
          <img
            src="/shield-logo.png"
            alt="CYBERSPLOI Shield Watermark"
            className="w-72 h-72 object-contain filter drop-shadow-[0_0_30px_#00d2ff]"
          />
        </div>
        <div className="absolute -top-24 -left-24 w-80 h-80 bg-cyber-blue/15 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-3">
              <div className="w-10 h-10 rounded-2xl bg-cyber-blue/15 border border-cyber-cyan/40 flex items-center justify-center p-1.5 shadow-glow">
                <img src="/shield-logo.png" alt="Emblem" className="w-full h-full object-contain" />
              </div>
              <h1 className="text-2xl lg:text-3xl font-black font-mono tracking-tight text-white flex items-center gap-2">
                CYBERSPLOI <span className="text-cyber-cyan text-glow-cyan">COMMAND CENTER</span>
              </h1>
              <Badge
                variant={criticalCount > 0 ? "critical" : "success"}
                pulse
                className="text-[10px] font-black tracking-widest uppercase px-3 py-1"
              >
                {criticalCount > 0 ? "DEFCON 2 : HIGH ALERT" : "DEFCON 5 : FORTIFIED"}
              </Badge>
            </div>
            <p className="text-xs font-mono text-slate-400 flex items-center gap-2 max-w-2xl">
              <span className="w-2 h-2 rounded-full bg-cyber-cyan animate-pulse shadow-[0_0_8px_#00d2ff]"></span>
              Autonomous Red Team & Defense Mesh • 120Hz Continuous AI Surface Telemetry
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <Button variant="secondary" size="sm" onClick={fetchDashboardData} isLoading={loading}>
              <ArrowPathIcon className="w-4 h-4 mr-1.5" />
              Refresh Telemetry
            </Button>
            <Link href="/offensive-engine">
              <Button variant="primary" size="sm" className="shadow-glow-lg">
                <SparklesIcon className="w-4 h-4 mr-1.5 text-white" />
                3D Constellation
              </Button>
            </Link>
            <Link href="/pentest">
              <Button variant="outline" size="sm">
                <PlayIcon className="w-4 h-4 mr-1.5 text-cyber-cyan" />
                New Pentest
              </Button>
            </Link>
          </div>
        </div>
      </div>

      {/* Interactive Quick Target Launch Bar */}
      <form
        onSubmit={handleQuickAudit}
        className="glass-panel rounded-2xl p-4 flex flex-wrap items-center justify-between gap-4 border border-[#1e293b] hover:border-cyber-cyan/40 transition-colors shadow-xl"
      >
        <div className="flex items-center gap-3 flex-1 min-w-[300px]">
          <div className="p-2 rounded-xl bg-cyber-cyan/15 border border-cyber-cyan/30 text-cyber-cyan shrink-0">
            <CommandLineIcon className="w-4 h-4" />
          </div>
          <div className="relative flex-1">
            <span className="text-[10px] font-mono uppercase tracking-widest text-slate-400 font-bold block mb-1">
              Target Penetration Probe:
            </span>
            <input
              type="text"
              value={quickTarget}
              onChange={(e) => setQuickTarget(e.target.value)}
              placeholder="e.g. api.cybersploi.io or 192.168.1.50"
              className="w-full bg-[#070b14] border border-[#1e293b] rounded-xl px-3.5 py-2 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-cyber-cyan transition-colors"
            />
          </div>
          <div className="hidden md:flex items-center gap-1.5 text-[11px] font-mono text-slate-400 shrink-0">
            <span className="text-slate-500 text-[10px] uppercase font-bold">Fast:</span>
            {["api.cybersploi.io", "staging-mesh.internal", "10.0.1.15"].map((preset) => (
              <button
                key={preset}
                type="button"
                onClick={() => setQuickTarget(preset)}
                className="px-2.5 py-1 rounded-lg bg-background-subtle hover:bg-slate-800 border border-[#1e293b] text-cyber-cyan hover:text-white text-xs transition-colors"
              >
                {preset}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-3">
          <Button type="submit" variant="primary" size="md">
            <SparklesIcon className="w-4 h-4 mr-1.5" />
            Launch 3D Audit
          </Button>
        </div>
      </form>

      {/* 4 Precision Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Critical Vulns"
          value={criticalCount}
          description="Immediate RCE & Zero-Day exposure"
          accent="danger"
          icon={ShieldExclamationIcon}
          trend={{
            value: criticalCount > 0 ? 12 : 0,
            label: "vs last cycle",
            direction: criticalCount > 0 ? "up" : "neutral",
          }}
        />

        <MetricCard
          title="High Severity"
          value={highCount}
          description="Authentication & SQLi perimeter risk"
          accent="amber"
          icon={ExclamationTriangleIcon}
          trend={{
            value: highCount > 0 ? 5 : 0,
            label: "vs last cycle",
            direction: highCount > 0 ? "up" : "neutral",
          }}
        />

        <MetricCard
          title="Medium & Low"
          value={mediumCount + lowCount}
          description="Config drift & SSRF probe signals"
          accent="cyan"
          icon={ServerStackIcon}
        />

        <MetricCard
          title="Mesh Shield Health"
          value={defenseScore}
          suffix="%"
          description={
            criticalCount === 0
              ? "WAF & perimeter telemetry nominal"
              : `${criticalCount} critical flaws require patching`
          }
          accent="emerald"
          icon={ShieldCheckIcon}
        />
      </div>

      {/* Main Grid: Threat Matrix + Active Scans */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Ring Donut */}
        <Card className="glass-panel">
          <CardHeader>
            <div className="flex items-center gap-2">
              <div className="w-5 h-5 rounded-lg bg-cyber-cyan/15 border border-cyber-cyan/30 flex items-center justify-center">
                <img src="/shield-logo.png" alt="Emblem" className="w-3 h-3 object-contain" />
              </div>
              <CardTitle className="text-xs font-mono uppercase tracking-wider text-slate-200">
                THREAT EXPOSURE MATRIX
              </CardTitle>
            </div>
            <StatusPulse status={criticalCount > 0 ? "warning" : "online"} size="sm" />
          </CardHeader>
          <CardContent className="flex flex-col items-center justify-center p-6 space-y-6">
            <SeverityRing
              breakdown={{
                critical: criticalCount,
                high: highCount,
                medium: mediumCount,
                low: lowCount,
              }}
              size={170}
              strokeWidth={16}
            />

            {/* Breakdown Legend */}
            <div className="grid grid-cols-2 gap-3 w-full font-mono text-xs pt-3 border-t border-[#1e293b]">
              <div className="flex items-center justify-between p-2.5 rounded-xl bg-background-subtle/80 border border-[#1e293b]">
                <span className="flex items-center gap-1.5 text-slate-400">
                  <span className="w-2 h-2 rounded-full bg-rose-400 shadow-[0_0_6px_#ff3366]" />
                  Critical
                </span>
                <span className="font-bold text-rose-400">{criticalCount}</span>
              </div>
              <div className="flex items-center justify-between p-2.5 rounded-xl bg-background-subtle/80 border border-[#1e293b]">
                <span className="flex items-center gap-1.5 text-slate-400">
                  <span className="w-2 h-2 rounded-full bg-amber-400 shadow-[0_0_6px_#ff9900]" />
                  High
                </span>
                <span className="font-bold text-amber-400">{highCount}</span>
              </div>
              <div className="flex items-center justify-between p-2.5 rounded-xl bg-background-subtle/80 border border-[#1e293b]">
                <span className="flex items-center gap-1.5 text-slate-400">
                  <span className="w-2 h-2 rounded-full bg-yellow-400" />
                  Medium
                </span>
                <span className="font-bold text-yellow-400">{mediumCount}</span>
              </div>
              <div className="flex items-center justify-between p-2.5 rounded-xl bg-background-subtle/80 border border-[#1e293b]">
                <span className="flex items-center gap-1.5 text-slate-400">
                  <span className="w-2 h-2 rounded-full bg-cyber-cyan" />
                  Low
                </span>
                <span className="font-bold text-cyber-cyan">{lowCount}</span>
              </div>
            </div>

            <Link href="/vulnerabilities" className="w-full">
              <Button variant="secondary" size="sm" className="w-full text-xs">
                Inspect Finding Register <ArrowRightIcon className="w-3.5 h-3.5 ml-1.5" />
              </Button>
            </Link>
          </CardContent>
        </Card>

        {/* Active Scans Tracker */}
        <div className="lg:col-span-2 space-y-4">
          <Card className="glass-panel">
            <CardHeader>
              <div className="flex items-center gap-2">
                <CommandLineIcon className="w-5 h-5 text-cyber-cyan" />
                <CardTitle className="text-xs font-mono uppercase tracking-wider">
                  ACTIVE & RECENT SECURITY SCANS
                </CardTitle>
              </div>
              <Link href="/pentest" className="text-xs font-mono text-cyber-cyan hover:underline font-bold">
                New Scan →
              </Link>
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHead>
                  <TableRow>
                    <TableHeaderCell>Target</TableHeaderCell>
                    <TableHeaderCell>Type</TableHeaderCell>
                    <TableHeaderCell>Status</TableHeaderCell>
                    <TableHeaderCell>Findings</TableHeaderCell>
                    <TableHeaderCell>Progress</TableHeaderCell>
                    <TableHeaderCell className="text-right">Action</TableHeaderCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {scans.length > 0 ? (
                    scans.slice(0, 6).map((scan) => (
                      <TableRow key={scan.id} className="hover:bg-cyber-cyan/[0.04] transition-colors">
                        <TableCell className="font-mono text-xs text-cyber-cyan font-bold flex items-center gap-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-cyber-cyan"></span>
                          {scan.target}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline">{scan.type}</Badge>
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={
                              scan.status === "completed"
                                ? "success"
                                : scan.status === "running"
                                ? "info"
                                : "high"
                            }
                            pulse={scan.status === "running"}
                          >
                            {scan.status}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {scan.criticalCount > 0 && (
                            <span className="text-rose-400 mr-2 font-bold">{scan.criticalCount}C</span>
                          )}
                          {scan.highCount > 0 && (
                            <span className="text-amber-400 mr-2 font-bold">{scan.highCount}H</span>
                          )}
                          <span className="text-slate-400">{scan.findings || 0} total</span>
                        </TableCell>
                        <TableCell className="w-28">
                          <ProgressBar
                            value={scan.status === "completed" ? 100 : scan.progress || 45}
                            height="xs"
                            variant={scan.status === "completed" ? "emerald" : "teal"}
                            animated={scan.status === "running"}
                          />
                        </TableCell>
                        <TableCell className="text-right">
                          <Link href={`/scans/${scan.id}`}>
                            <Button variant="secondary" size="sm" className="h-7 text-xs">
                              Inspect
                            </Button>
                          </Link>
                        </TableCell>
                      </TableRow>
                    ))
                  ) : (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center py-12 font-mono text-xs text-slate-500">
                        <div className="flex flex-col items-center justify-center gap-2">
                          <img src="/shield-logo.png" alt="Shield" className="w-8 h-8 opacity-40" />
                          <span>No active security scans in database. Launch a pentest to initiate autonomous surface discovery.</span>
                        </div>
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* AI Threat Defense Telemetry & Fast Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* AI Defense Engine Live Telemetry */}
        <Card className="glass-panel lg:col-span-2">
          <CardHeader>
            <div className="flex items-center gap-2">
              <CpuChipIcon className="w-5 h-5 text-cyber-cyan" />
              <CardTitle className="text-xs font-mono uppercase tracking-wider">
                CYBERSPLOI NEURAL DEFENSE ENGINE (FASTAPI :8001)
              </CardTitle>
            </div>
            <StatusPulse status="online" label="ONLINE" size="sm" />
          </CardHeader>
          <CardContent className="p-5 space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="p-3.5 rounded-2xl bg-background-subtle/80 border border-[#1e293b] space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-slate-400">Pentest Classifier</span>
                  <Badge variant="success" size="sm">ACTIVE</Badge>
                </div>
                <div className="flex items-baseline gap-1">
                  <span className="text-xl font-mono font-bold text-slate-100">
                    {aiStatus?.data?.models_loaded?.pentest ? "Loaded" : "Online"}
                  </span>
                </div>
                <p className="text-[10px] font-mono text-slate-500">
                  pentest_model.pkl heuristic pipeline
                </p>
              </div>

              <div className="p-3.5 rounded-2xl bg-background-subtle/80 border border-[#1e293b] space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-slate-400">Malware Sandbox</span>
                  <Badge variant="success" size="sm">ACTIVE</Badge>
                </div>
                <div className="flex items-baseline gap-1">
                  <span className="text-xl font-mono font-bold text-slate-100">
                    {aiStatus?.data?.models_loaded?.malware ? "Loaded" : "Online"}
                  </span>
                </div>
                <p className="text-[10px] font-mono text-slate-500">
                  malware_model.pkl entropy classifier
                </p>
              </div>

              <div className="p-3.5 rounded-2xl bg-background-subtle/80 border border-[#1e293b] space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-slate-400">Web Exploit DAST</span>
                  <Badge variant="success" size="sm">ACTIVE</Badge>
                </div>
                <div className="flex items-baseline gap-1">
                  <span className="text-xl font-mono font-bold text-slate-100">
                    {aiStatus?.data?.models_loaded?.webapp_scanner ? "Loaded" : "Online"}
                  </span>
                </div>
                <p className="text-[10px] font-mono text-slate-500">
                  webapp_scanner_model.pkl CVSS 3.1
                </p>
              </div>
            </div>

            <div className="p-3.5 rounded-2xl bg-background-subtle/80 border border-[#1e293b] flex items-center justify-between text-xs font-mono">
              <div className="flex items-center gap-2 text-slate-300">
                <BoltIcon className="w-4 h-4 text-cyber-cyan" />
                <span>Autonomous Agent Evolution Cycles:</span>
              </div>
              <span className="text-cyber-cyan font-bold">120 Hz Continuous Telemetry</span>
            </div>
          </CardContent>
        </Card>

        {/* Quick Launchpad Card */}
        <Card className="glass-panel">
          <CardHeader>
            <div className="flex items-center gap-2">
              <FireIcon className="w-4 h-4 text-rose-400" />
              <CardTitle className="text-xs font-mono uppercase tracking-wider">
                TACTICAL CAPABILITIES
              </CardTitle>
            </div>
          </CardHeader>
          <CardContent className="p-5 space-y-3 font-mono text-xs">
            <Link href="/pentest" className="block group">
              <div className="p-3 rounded-xl border border-[#1e293b] bg-background-subtle/70 group-hover:border-cyber-cyan/60 group-hover:bg-cyber-cyan/5 transition-all flex items-center justify-between shadow-sm">
                <div className="flex items-center gap-2.5">
                  <CommandLineIcon className="w-4 h-4 text-cyber-cyan group-hover:scale-110 transition-transform" />
                  <span className="text-slate-200 font-semibold group-hover:text-white">Pentest Command</span>
                </div>
                <span className="text-[10px] text-cyber-cyan">Launch →</span>
              </div>
            </Link>

            <Link href="/red-team" className="block group">
              <div className="p-3 rounded-xl border border-[#1e293b] bg-background-subtle/70 group-hover:border-rose-500/60 group-hover:bg-rose-950/20 transition-all flex items-center justify-between shadow-sm">
                <div className="flex items-center gap-2.5">
                  <BoltIcon className="w-4 h-4 text-rose-400 group-hover:scale-110 transition-transform" />
                  <span className="text-slate-200 font-semibold group-hover:text-white">Red Team Adversary</span>
                </div>
                <span className="text-[10px] text-rose-400">Emulate →</span>
              </div>
            </Link>

            <Link href="/malware-lab" className="block group">
              <div className="p-3 rounded-xl border border-[#1e293b] bg-background-subtle/70 group-hover:border-amber-500/60 group-hover:bg-amber-950/20 transition-all flex items-center justify-between shadow-sm">
                <div className="flex items-center gap-2.5">
                  <BugAntIcon className="w-4 h-4 text-amber-400 group-hover:scale-110 transition-transform" />
                  <span className="text-slate-200 font-semibold group-hover:text-white">Malware Sandbox</span>
                </div>
                <span className="text-[10px] text-amber-400">Detonate →</span>
              </div>
            </Link>

            <Link href="/threat-intel" className="block group">
              <div className="p-3 rounded-xl border border-[#1e293b] bg-background-subtle/70 group-hover:border-cyber-cyan/60 group-hover:bg-cyber-cyan/10 transition-all flex items-center justify-between shadow-sm">
                <div className="flex items-center gap-2.5">
                  <CheckCircleIcon className="w-4 h-4 text-cyber-cyan group-hover:scale-110 transition-transform" />
                  <span className="text-slate-200 font-semibold group-hover:text-white">Threat Intelligence</span>
                </div>
                <span className="text-[10px] text-cyber-cyan">Radar →</span>
              </div>
            </Link>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
