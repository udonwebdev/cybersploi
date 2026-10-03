"use client";

import React, { useState } from "react";
import { AssessmentBrain } from "@/lib/api/red-team";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  CpuChipIcon,
  ShieldCheckIcon,
  ShieldExclamationIcon,
  QuestionMarkCircleIcon,
  KeyIcon,
  ServerIcon,
  CommandLineIcon,
  DocumentMagnifyingGlassIcon,
  ArrowPathIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon,
  GlobeAltIcon,
  CircleStackIcon,
  ArrowsRightLeftIcon,
  CubeTransparentIcon,
  SparklesIcon
} from "@heroicons/react/24/outline";

interface AssessmentBrainViewProps {
  brain?: AssessmentBrain | null;
  isLoading?: boolean;
}

export const AssessmentBrainView: React.FC<AssessmentBrainViewProps> = ({
  brain,
  isLoading = false
}) => {
  const [selectedSurface, setSelectedSurface] = useState<string | null>(null);
  const [expandedRootCause, setExpandedRootCause] = useState<string | null>(null);

  if (isLoading || !brain) {
    return (
      <Card className="border-cyber-teal/30 bg-background-card">
        <CardContent className="p-12 text-center space-y-4 font-mono">
          <div className="w-12 h-12 mx-auto rounded-full border-2 border-cyber-teal border-t-transparent animate-spin" />
          <div className="text-base font-bold text-slate-100">
            Initializing Assessment Brain Knowledge Model...
          </div>
          <p className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
            Synthesizing 12-surface attack matrix, hypothesis verification queue,
            authorization boundaries, and root-cause correlation models.
          </p>
        </CardContent>
      </Card>
    );
  }

  const surfaceKeys = Object.keys(brain.surfaceMatrix || {});
  const activeSurfaceData = selectedSurface && brain.surfaceMatrix ? brain.surfaceMatrix[selectedSurface] : null;

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "VERIFIED":
        return <Badge variant="success" className="font-mono text-[10px]">VERIFIED</Badge>;
      case "ASSESSED":
        return <Badge variant="info" className="font-mono text-[10px]">ASSESSED</Badge>;
      case "PARTIALLY_ASSESSED":
        return <Badge variant="warning" className="font-mono text-[10px]">PARTIAL</Badge>;
      default:
        return <Badge variant="outline" className="font-mono text-[10px] text-slate-400">UNPROBED</Badge>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Brain Header Summary & Persistent Memory Telemetry */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3.5 font-mono text-xs">
        <Card className="bg-background-card border-border">
          <CardContent className="p-3.5">
            <span className="text-[10px] text-slate-400 uppercase">Knowledge Stores</span>
            <div className="text-lg font-bold text-slate-100 mt-1 flex items-center gap-1.5">
              <CircleStackIcon className="w-4 h-4 text-cyber-teal" />
              {brain.memoryStats?.totalAssets || 0} Assets
            </div>
            <span className="text-[10px] text-slate-500">Persistent memory registry</span>
          </CardContent>
        </Card>

        <Card className="bg-background-card border-border">
          <CardContent className="p-3.5">
            <span className="text-[10px] text-slate-400 uppercase">Active Services</span>
            <div className="text-lg font-bold text-slate-100 mt-1 flex items-center gap-1.5">
              <ServerIcon className="w-4 h-4 text-purple-400" />
              {brain.memoryStats?.totalServices || 0} Ports
            </div>
            <span className="text-[10px] text-slate-500">Socket listeners confirmed</span>
          </CardContent>
        </Card>

        <Card className="bg-background-card border-border">
          <CardContent className="p-3.5">
            <span className="text-[10px] text-slate-400 uppercase">Cartographed Routes</span>
            <div className="text-lg font-bold text-slate-100 mt-1 flex items-center gap-1.5">
              <CommandLineIcon className="w-4 h-4 text-blue-400" />
              {brain.memoryStats?.totalRoutes || 0} Routes
            </div>
            <span className="text-[10px] text-slate-500">HTTP / API endpoints</span>
          </CardContent>
        </Card>

        <Card className="bg-background-card border-border">
          <CardContent className="p-3.5">
            <span className="text-[10px] text-slate-400 uppercase">Investigation Queue</span>
            <div className="text-lg font-bold text-amber-400 mt-1 flex items-center gap-1.5">
              <QuestionMarkCircleIcon className="w-4 h-4 text-amber-400" />
              {brain.questionQueue?.length || 0} Questions
            </div>
            <span className="text-[10px] text-slate-500">Hypothesis-driven queue</span>
          </CardContent>
        </Card>

        <Card className="bg-background-card border-border">
          <CardContent className="p-3.5">
            <span className="text-[10px] text-slate-400 uppercase">Root Causes</span>
            <div className="text-lg font-bold text-red-400 mt-1 flex items-center gap-1.5">
              <ShieldExclamationIcon className="w-4 h-4 text-red-400" />
              {brain.rootCauses?.length || 0} Correlated
            </div>
            <span className="text-[10px] text-slate-500">Architectural sources</span>
          </CardContent>
        </Card>

        <Card className="bg-background-card border-border">
          <CardContent className="p-3.5">
            <span className="text-[10px] text-slate-400 uppercase">Operator Decisions</span>
            <div className="text-lg font-bold text-emerald-400 mt-1 flex items-center gap-1.5">
              <SparklesIcon className="w-4 h-4 text-emerald-400" />
              {brain.memoryStats?.decisionLogsCount || 0} Cycles
            </div>
            <span className="text-[10px] text-slate-500">Reasoning audit trace</span>
          </CardContent>
        </Card>
      </div>

      {/* 1. 12-Surface Attack Matrix Grid */}
      <Card className="border-border bg-background-card">
        <CardHeader className="border-b border-border/40 pb-3 flex flex-row items-center justify-between">
          <div className="flex items-center gap-2.5">
            <CpuChipIcon className="w-5 h-5 text-cyber-teal" />
            <CardTitle className="text-sm font-bold font-mono tracking-wide text-slate-100">
              12-SURFACE ATTACK MATRIX TELEMETRY
            </CardTitle>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Systematic inspection across all dimensions of attack surface
          </span>
        </CardHeader>
        <CardContent className="p-4 space-y-4">
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
            {surfaceKeys.map((key) => {
              const surf = brain.surfaceMatrix[key];
              const isSelected = selectedSurface === key;

              return (
                <div
                  key={key}
                  onClick={() => setSelectedSurface(isSelected ? null : key)}
                  className={`p-3 rounded-xl border font-mono cursor-pointer transition-all ${
                    isSelected
                      ? "border-cyber-teal bg-cyber-teal/10 shadow-md shadow-cyber-teal/10"
                      : "border-border/60 bg-background/60 hover:border-slate-600 hover:bg-white/[0.02]"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <span className="text-xs font-bold text-slate-200 tracking-wider truncate">
                      {key}
                    </span>
                    {getStatusBadge(surf.status)}
                  </div>

                  <div className="flex items-center justify-between text-[11px] text-slate-400 mt-2 pt-2 border-t border-border/30">
                    <span>Coverage: <strong className="text-slate-200">{surf.coveragePct}%</strong></span>
                    <span>Items: <strong className="text-cyber-teal">{surf.assessedCount}</strong></span>
                  </div>

                  {surf.verifiedCount > 0 && (
                    <div className="mt-1 text-[10px] text-emerald-400 font-semibold">
                      ✓ {surf.verifiedCount} findings verified
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Drawer for selected surface */}
          {selectedSurface && activeSurfaceData && (
            <div className="mt-4 p-4 rounded-xl border border-cyber-teal/40 bg-cyber-teal/5 font-mono text-xs space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-slate-300 font-bold uppercase">Surface Drill-down:</span>
                  <span className="text-cyber-teal font-extrabold">{selectedSurface}</span>
                  {getStatusBadge(activeSurfaceData.status)}
                </div>
                <button
                  onClick={() => setSelectedSurface(null)}
                  className="text-slate-400 hover:text-slate-200 text-xs px-2 py-0.5 rounded border border-border"
                >
                  Close
                </button>
              </div>

              <div className="max-h-48 overflow-y-auto space-y-1.5 pr-2">
                {activeSurfaceData.items && activeSurfaceData.items.length > 0 ? (
                  activeSurfaceData.items.map((it: any, idx: number) => (
                    <div
                      key={idx}
                      className="p-2 rounded bg-background/80 border border-border/40 text-[11px] flex items-center justify-between gap-2"
                    >
                      <span className="text-slate-300 font-mono truncate">
                        {it.type || it.header || it.workflow || it.category || "ITEM"}:{" "}
                        <span className="text-slate-100">{it.value || it.path || it.target || it.name || JSON.stringify(it)}</span>
                      </span>
                      {it.status && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-border">
                          HTTP {it.status}
                        </span>
                      )}
                    </div>
                  ))
                ) : (
                  <div className="text-slate-400 italic text-[11px] py-2">
                    No discrete elements recorded for this surface yet.
                  </div>
                )}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* 2. Question-Driven Investigation Queue */}
      <Card className="border-border bg-background-card">
        <CardHeader className="border-b border-border/40 pb-3 flex flex-row items-center justify-between">
          <div className="flex items-center gap-2.5">
            <QuestionMarkCircleIcon className="w-5 h-5 text-amber-400" />
            <CardTitle className="text-sm font-bold font-mono tracking-wide text-slate-100">
              QUESTION-DRIVEN INVESTIGATION QUEUE
            </CardTitle>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Formulated hypotheses with explicit proving & disproving criteria
          </span>
        </CardHeader>
        <CardContent className="p-4 space-y-3">
          {brain.questionQueue && brain.questionQueue.length > 0 ? (
            <div className="space-y-3">
              {brain.questionQueue.map((q, idx) => (
                <div
                  key={q.id || idx}
                  className="p-3.5 rounded-xl border border-border bg-background/70 font-mono text-xs space-y-2.5"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30 text-[10px] font-bold">
                        {q.id}
                      </span>
                      <span className="font-bold text-slate-100 text-sm">{q.question}</span>
                    </div>
                    <Badge variant="outline" className="text-[10px] font-mono">
                      {q.status || "PENDING"}
                    </Badge>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px] pt-1">
                    <div className="p-2.5 rounded-lg bg-white/[0.02] border border-border/40 space-y-1">
                      <span className="text-slate-400 text-[10px] uppercase font-bold">Target & Security Property</span>
                      <div className="text-slate-200">
                        <code>{q.target}</code>
                      </div>
                      <div className="text-slate-400 text-[10px]">{q.securityProperty}</div>
                    </div>

                    <div className="p-2.5 rounded-lg bg-white/[0.02] border border-border/40 space-y-1">
                      <span className="text-slate-400 text-[10px] uppercase font-bold">Operational Assumption</span>
                      <div className="text-slate-300 text-[11px] italic">"{q.assumption}"</div>
                      <div className="text-cyber-teal font-semibold text-[10px]">
                        Derived Hypothesis: {q.derivedHypothesis}
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px] border-t border-border/30 pt-2">
                    <div className="text-emerald-400/90 flex items-start gap-1.5">
                      <CheckCircleIcon className="w-4 h-4 flex-shrink-0 text-emerald-400 mt-0.5" />
                      <div>
                        <strong className="text-[10px] uppercase block text-emerald-300">Proving Evidence:</strong>
                        <span className="text-[10px] text-slate-300">{q.provingEvidence}</span>
                      </div>
                    </div>

                    <div className="text-red-400/90 flex items-start gap-1.5">
                      <XCircleIcon className="w-4 h-4 flex-shrink-0 text-red-400 mt-0.5" />
                      <div>
                        <strong className="text-[10px] uppercase block text-red-300">Disproving Criteria:</strong>
                        <span className="text-[10px] text-slate-300">{q.disprovingEvidence}</span>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-slate-400 italic text-xs py-4 text-center font-mono">
              Investigation queue empty; all surface inquiries processed.
            </div>
          )}
        </CardContent>
      </Card>

      {/* 3. Deep Auth State Machine & Authorization Invariants */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Auth State Machine */}
        <Card className="border-border bg-background-card">
          <CardHeader className="border-b border-border/40 pb-3">
            <div className="flex items-center gap-2">
              <KeyIcon className="w-5 h-5 text-cyber-teal" />
              <CardTitle className="text-sm font-bold font-mono text-slate-100">
                AUTHENTICATION STATE MACHINE
              </CardTitle>
            </div>
          </CardHeader>
          <CardContent className="p-4 space-y-4 font-mono text-xs">
            <div className="space-y-1">
              <span className="text-[10px] text-slate-400 uppercase">State Machine Progression</span>
              <div className="flex flex-wrap items-center gap-1.5 pt-1">
                {(brain.authStateMachine?.states || []).map((state, i) => {
                  const isCurrent = brain.authStateMachine?.currentState === state;
                  return (
                    <React.Fragment key={state}>
                      <span
                        className={`px-2 py-1 rounded text-[10px] font-bold border transition-all ${
                          isCurrent
                            ? "bg-cyber-teal text-slate-900 border-cyber-teal shadow-md shadow-cyber-teal/20"
                            : "bg-background border-border text-slate-400"
                        }`}
                      >
                        {state}
                      </span>
                      {i < (brain.authStateMachine?.states || []).length - 1 && (
                        <span className="text-slate-600 font-bold">→</span>
                      )}
                    </React.Fragment>
                  );
                })}
              </div>
            </div>

            {/* Cookie Hygiene Flags */}
            <div className="border-t border-border/40 pt-3 space-y-2">
              <span className="text-[10px] text-slate-400 uppercase font-bold">Session Cookie Hygiene</span>
              {brain.authStateMachine?.sessionTokens && brain.authStateMachine.sessionTokens.length > 0 ? (
                brain.authStateMachine.sessionTokens.map((c, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded-lg bg-background border border-border/60 flex items-center justify-between text-[11px]"
                  >
                    <span className="font-bold text-slate-200">{c.name}</span>
                    <div className="flex items-center gap-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] ${c.isHttpOnly ? "bg-emerald-950/60 text-emerald-400 border border-emerald-500/30" : "bg-red-950/60 text-red-400 border border-red-500/30"}`}>
                        HttpOnly: {c.isHttpOnly ? "YES" : "NO"}
                      </span>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] ${c.isSecure ? "bg-emerald-950/60 text-emerald-400 border border-emerald-500/30" : "bg-red-950/60 text-red-400 border border-red-500/30"}`}>
                        Secure: {c.isSecure ? "YES" : "NO"}
                      </span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-slate-400 text-[11px] italic">No active session cookies recorded.</div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Authorization Invariants Matrix */}
        <Card className="border-border bg-background-card">
          <CardHeader className="border-b border-border/40 pb-3">
            <div className="flex items-center gap-2">
              <ShieldCheckIcon className="w-5 h-5 text-emerald-400" />
              <CardTitle className="text-sm font-bold font-mono text-slate-100">
                AUTHORIZATION INVARIANTS & ROLES
              </CardTitle>
            </div>
          </CardHeader>
          <CardContent className="p-4 space-y-3 font-mono text-xs">
            {brain.authorizationMatrix && brain.authorizationMatrix.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-[11px] text-left border-collapse">
                  <thead>
                    <tr className="border-b border-border/60 text-[10px] text-slate-400 uppercase">
                      <th className="py-1.5 pr-2">Identity</th>
                      <th className="py-1.5 pr-2">Role</th>
                      <th className="py-1.5 pr-2">Resource</th>
                      <th className="py-1.5 pr-2">Expected</th>
                      <th className="py-1.5 pr-2">Observed</th>
                      <th className="py-1.5">Violation?</th>
                    </tr>
                  </thead>
                  <tbody>
                    {brain.authorizationMatrix.map((a, i) => (
                      <tr key={i} className="border-b border-border/30 hover:bg-white/[0.02]">
                        <td className="py-2 pr-2 text-slate-300 font-semibold">{a.identity}</td>
                        <td className="py-2 pr-2 text-slate-400">{a.role}</td>
                        <td className="py-2 pr-2 font-mono text-cyber-teal truncate max-w-[120px]">{a.resource}</td>
                        <td className="py-2 pr-2 text-slate-400">{a.expectedAccess}</td>
                        <td className="py-2 pr-2">
                          <span className={`px-1 rounded text-[10px] ${a.observedAccess === "ALLOW" ? "text-emerald-400 bg-emerald-950/40" : "text-slate-400 bg-slate-800"}`}>
                            {a.observedAccess} ({a.statusCode})
                          </span>
                        </td>
                        <td className="py-2">
                          {a.inconsistent ? (
                            <span className="px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-500/40 font-bold text-[10px]">
                              VIOLATION
                            </span>
                          ) : (
                            <span className="text-emerald-400 text-[10px] font-bold">PASS</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="text-slate-400 italic text-xs py-4 text-center">
                Authorization invariant matrix model in progress.
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* 4. Architectural Root Causes vs. Symptoms */}
      <Card className="border-border bg-background-card">
        <CardHeader className="border-b border-border/40 pb-3 flex flex-row items-center justify-between">
          <div className="flex items-center gap-2.5">
            <ArrowsRightLeftIcon className="w-5 h-5 text-red-400" />
            <CardTitle className="text-sm font-bold font-mono tracking-wide text-slate-100">
              ARCHITECTURAL ROOT CAUSES VS. SYMPTOMS
            </CardTitle>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Unifies duplicate surface weaknesses under root architectural deficits
          </span>
        </CardHeader>
        <CardContent className="p-4 space-y-3 font-mono text-xs">
          {brain.rootCauses && brain.rootCauses.length > 0 ? (
            brain.rootCauses.map((rc) => {
              const isExpanded = expandedRootCause === rc.id;

              return (
                <div
                  key={rc.id}
                  className="rounded-xl border border-border bg-background/70 overflow-hidden transition-all"
                >
                  <div
                    onClick={() => setExpandedRootCause(isExpanded ? null : rc.id)}
                    className="p-3.5 flex flex-wrap items-center justify-between gap-2 cursor-pointer hover:bg-white/[0.02]"
                  >
                    <div className="flex items-center gap-3">
                      <span className="px-2 py-0.5 rounded bg-red-950/60 text-red-400 border border-red-500/30 text-[10px] font-bold">
                        {rc.severity}
                      </span>
                      <div>
                        <div className="font-bold text-slate-100 text-sm">{rc.title}</div>
                        <div className="text-[11px] text-slate-400 mt-0.5">
                          Root: <span className="text-slate-300 font-semibold">{rc.rootCause}</span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      <span className="text-[11px] text-cyber-teal font-semibold">
                        {rc.symptoms?.length || 0} Correlated Symptoms
                      </span>
                      <button className="text-slate-400 hover:text-slate-200 text-xs px-2 py-1 rounded border border-border">
                        {isExpanded ? "Collapse" : "View Symptoms"}
                      </button>
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="p-3.5 bg-white/[0.01] border-t border-border/40 space-y-2 text-[11px]">
                      <span className="text-[10px] text-slate-400 uppercase font-bold block">
                        Correlated Vulnerability Symptoms:
                      </span>
                      <div className="space-y-1.5">
                        {(rc.symptoms || []).map((s, idx) => (
                          <div
                            key={idx}
                            className="p-2 rounded bg-background border border-border/40 flex items-center justify-between gap-2"
                          >
                            <span className="text-slate-200 font-bold truncate">
                              • {s.title}
                            </span>
                            <div className="flex items-center gap-2">
                              <Badge variant={s.severity === "HIGH" ? "destructive" : "warning"} className="text-[9px]">
                                {s.severity}
                              </Badge>
                              <span className="text-[10px] text-slate-500 font-mono">{s.cve}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          ) : (
            <div className="text-slate-400 italic text-xs py-4 text-center font-mono">
              Zero active root cause deficits identified. System exhibits unified architectural posture.
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};
