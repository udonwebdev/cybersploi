"use client";

import React from "react";
import { WellbeingScorecard, TechStack } from "@/lib/api/red-team";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  ShieldCheckIcon,
  ShieldExclamationIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  XCircleIcon,
  ServerIcon,
  CpuChipIcon,
  LockClosedIcon,
  KeyIcon,
  DocumentMagnifyingGlassIcon,
  GlobeAltIcon,
  SparklesIcon,
  ArrowRightIcon,
  FireIcon,
  BoltIcon
} from "@heroicons/react/24/outline";

interface WellbeingScorecardViewProps {
  scorecard?: WellbeingScorecard | null;
  techStack?: TechStack | null;
  crawledPages?: any[];
  discoveredForms?: any[];
  isLoading?: boolean;
  onHandoffBlueTeam?: () => void;
}

export const WellbeingScorecardView: React.FC<WellbeingScorecardViewProps> = ({
  scorecard,
  techStack,
  crawledPages = [],
  discoveredForms = [],
  isLoading = false,
  onHandoffBlueTeam,
}) => {
  if (isLoading || !scorecard) {
    return (
      <Card className="border-cyber-teal/30 bg-background-card">
        <CardContent className="p-12 text-center space-y-4 font-mono">
          <div className="w-12 h-12 mx-auto rounded-full border-2 border-cyber-teal border-t-transparent animate-spin" />
          <div className="text-base font-bold text-slate-100">
            Synthesizing 6-Pillar Wellbeing Scorecard...
          </div>
          <p className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
            Engine is executing recursive spidering, socket verification, security header cartography,
            and empirical exploitability evaluations.
          </p>
        </CardContent>
      </Card>
    );
  }

  // Grade styling
  const getGradeTheme = (grade: string) => {
    switch (grade) {
      case "A+":
      case "A":
        return {
          text: "text-emerald-400",
          border: "border-emerald-500/50",
          bg: "bg-emerald-950/20",
          glow: "shadow-emerald-500/20",
          ring: "stroke-emerald-400",
        };
      case "B":
        return {
          text: "text-cyan-400",
          border: "border-cyan-500/50",
          bg: "bg-cyan-950/20",
          glow: "shadow-cyan-500/20",
          ring: "stroke-cyan-400",
        };
      case "C":
        return {
          text: "text-amber-400",
          border: "border-amber-500/50",
          bg: "bg-amber-950/20",
          glow: "shadow-amber-500/20",
          ring: "stroke-amber-400",
        };
      case "D":
      case "F":
      default:
        return {
          text: "text-red-400",
          border: "border-red-500/50",
          bg: "bg-red-950/20",
          glow: "shadow-red-500/20",
          ring: "stroke-red-400",
        };
    }
  };

  const gradeTheme = getGradeTheme(scorecard.letterGrade);

  const getPillarIcon = (id: string) => {
    switch (id) {
      case "perimeter":
        return <GlobeAltIcon className="w-5 h-5 text-blue-400" />;
      case "web_hardening":
        return <ShieldCheckIcon className="w-5 h-5 text-cyber-teal" />;
      case "identity_access":
        return <KeyIcon className="w-5 h-5 text-purple-400" />;
      case "cryptography":
        return <LockClosedIcon className="w-5 h-5 text-emerald-400" />;
      case "data_protection":
        return <DocumentMagnifyingGlassIcon className="w-5 h-5 text-amber-400" />;
      case "api_resilience":
        return <ServerIcon className="w-5 h-5 text-rose-400" />;
      default:
        return <CpuChipIcon className="w-5 h-5 text-cyan-400" />;
    }
  };

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Top Banner: Grade, Overall Score, TEI & Executive Summary */}
      <div className={`p-6 rounded-2xl border ${gradeTheme.border} ${gradeTheme.bg} shadow-xl ${gradeTheme.glow} relative overflow-hidden backdrop-blur-md`}>
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          {/* Grade & Score Gauge */}
          <div className="flex items-center gap-6">
            <div className={`w-24 h-24 rounded-2xl border-2 ${gradeTheme.border} flex flex-col items-center justify-center bg-black/40 shadow-inner shrink-0`}>
              <span className={`text-4xl font-black ${gradeTheme.text}`}>
                {scorecard.letterGrade}
              </span>
              <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider mt-0.5">
                GRADE
              </span>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center gap-3">
                <span className="text-3xl font-black text-slate-100">
                  {scorecard.overallScore}
                </span>
                <span className="text-slate-400 text-sm font-semibold">/ 100</span>
                <Badge
                  variant={
                    scorecard.threatIndex === "MINIMAL" || scorecard.threatIndex === "LOW"
                      ? "success"
                      : scorecard.threatIndex === "MODERATE"
                      ? "info"
                      : scorecard.threatIndex === "ELEVATED"
                      ? "warning"
                      : "destructive"
                  }
                  size="sm"
                  className="font-bold uppercase tracking-wider ml-2"
                >
                  {scorecard.threatIndex} THREAT EXPOSURE
                </Badge>
              </div>

              <div className="text-sm font-semibold text-slate-200">
                {scorecard.summaryHeadline}
              </div>

              <div className="text-[11px] text-slate-400 flex flex-wrap items-center gap-4 pt-1">
                <span>Calculated: {new Date(scorecard.generatedAt).toLocaleString()}</span>
                <span>•</span>
                <span>Audited Pillars: {scorecard.pillars?.length || 6}</span>
                <span>•</span>
                <span>Crawled Pages: {crawledPages.length}</span>
                <span>•</span>
                <span>Forms Profiled: {discoveredForms.length}</span>
              </div>
            </div>
          </div>

          {/* Quick Blue Team Handoff Trigger */}
          {onHandoffBlueTeam && (
            <div className="shrink-0 flex flex-col sm:flex-row lg:flex-col gap-2.5">
              <Button
                onClick={onHandoffBlueTeam}
                className="bg-blue-600 hover:bg-blue-500 text-white font-mono text-xs px-4 py-2 flex items-center justify-center gap-2 border border-blue-400/40 shadow-lg shadow-blue-500/20"
              >
                <ShieldCheckIcon className="w-4 h-4 text-blue-200" />
                Give Report to Blue Team
              </Button>
              <span className="text-[10px] text-slate-400 text-center">
                Stages virtual patches & WAF rules
              </span>
            </div>
          )}
        </div>
      </div>

      {/* 6 Enterprise Security Pillars Breakdown */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
            <SparklesIcon className="w-4 h-4 text-cyber-teal" />
            6-Pillar Security Health Matrix
          </h2>
          <span className="text-[11px] text-slate-400">
            Weighted Empirical Evaluation (Perimeter, Ingress, Auth, Crypto, Data, API)
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {scorecard.pillars?.map((pillar) => {
            const isHealthy = pillar.score >= 80;
            const isWarning = pillar.score >= 50 && pillar.score < 80;
            const isCritical = pillar.score < 50;

            return (
              <Card
                key={pillar.id}
                className={`bg-background-card border transition-all hover:border-slate-600 ${
                  isCritical
                    ? "border-red-500/30"
                    : isWarning
                    ? "border-amber-500/30"
                    : "border-border"
                }`}
              >
                <CardHeader className="pb-2 border-b border-border/40 flex flex-row items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    {getPillarIcon(pillar.id)}
                    <CardTitle className="text-xs font-bold text-slate-200 truncate">
                      {pillar.name}
                    </CardTitle>
                  </div>
                  <Badge
                    variant={isHealthy ? "success" : isWarning ? "warning" : "destructive"}
                    size="sm"
                    className="uppercase text-[10px]"
                  >
                    {pillar.status}
                  </Badge>
                </CardHeader>
                <CardContent className="p-4 space-y-3">
                  {/* Pillar Score & Progress */}
                  <div>
                    <div className="flex items-center justify-between mb-1 text-[11px]">
                      <span className="text-slate-400">Pillar Score (Weight {pillar.weightPercent}%)</span>
                      <span className={`font-bold ${isHealthy ? "text-emerald-400" : isWarning ? "text-amber-400" : "text-red-400"}`}>
                        {pillar.score} / 100
                      </span>
                    </div>
                    <div className="w-full bg-black/60 rounded-full h-1.5 overflow-hidden border border-border/40">
                      <div
                        className={`h-full rounded-full transition-all duration-700 ${
                          isHealthy
                            ? "bg-emerald-500"
                            : isWarning
                            ? "bg-amber-500"
                            : "bg-red-500"
                        }`}
                        style={{ width: `${pillar.score}%` }}
                      />
                    </div>
                  </div>

                  {/* Deductions or Clean Status */}
                  <div className="space-y-1 pt-1">
                    {pillar.deductions && pillar.deductions.length > 0 ? (
                      pillar.deductions.map((ded, idx) => (
                        <div key={idx} className="flex items-start gap-1.5 text-[11px] text-red-300/90 leading-tight">
                          <XCircleIcon className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
                          <span>{ded}</span>
                        </div>
                      ))
                    ) : (
                      <div className="flex items-center gap-1.5 text-[11px] text-emerald-400">
                        <CheckCircleIcon className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                        <span>No deductions. Hardening rules enforced.</span>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </div>

      {/* Technology Stack & Discovered Surface Cartography */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card className="lg:col-span-1 bg-background-card border-border">
          <CardHeader className="border-b border-border/40 pb-3">
            <CardTitle className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <CpuChipIcon className="w-4 h-4 text-purple-400" />
              Technology Stack Fingerprint
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4 space-y-3 font-mono text-xs">
            <div>
              <span className="text-[10px] text-slate-400 uppercase">Web Server</span>
              <div className="mt-1">
                {techStack?.server ? (
                  <Badge variant="outline" className="text-cyan-300 border-cyan-500/40">
                    {techStack.server}
                  </Badge>
                ) : (
                  <span className="text-slate-500">Generic / Obfuscated</span>
                )}
              </div>
            </div>

            <div>
              <span className="text-[10px] text-slate-400 uppercase">Frameworks & Runtime</span>
              <div className="flex flex-wrap gap-1.5 mt-1">
                {techStack?.frameworks && techStack.frameworks.length > 0 ? (
                  techStack.frameworks.map((f, i) => (
                    <Badge key={i} variant="outline" className="text-purple-300 border-purple-500/40">
                      {f}
                    </Badge>
                  ))
                ) : (
                  <span className="text-slate-500">None detected</span>
                )}
              </div>
            </div>

            <div>
              <span className="text-[10px] text-slate-400 uppercase">Frontend Libraries</span>
              <div className="flex flex-wrap gap-1.5 mt-1">
                {techStack?.frontend && techStack.frontend.length > 0 ? (
                  techStack.frontend.map((f, i) => (
                    <Badge key={i} variant="outline" className="text-emerald-300 border-emerald-500/40">
                      {f}
                    </Badge>
                  ))
                ) : (
                  <span className="text-slate-500">None detected</span>
                )}
              </div>
            </div>

            <div>
              <span className="text-[10px] text-slate-400 uppercase">CDN / Reverse Proxy</span>
              <div className="mt-1">
                {techStack?.cdn ? (
                  <Badge variant="outline" className="text-amber-300 border-amber-500/40">
                    {techStack.cdn}
                  </Badge>
                ) : (
                  <span className="text-slate-500">Direct Origin / None</span>
                )}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Deep Crawl Surface: Crawled Pages & Forms */}
        <Card className="lg:col-span-2 bg-background-card border-border">
          <CardHeader className="border-b border-border/40 pb-3 flex flex-row items-center justify-between">
            <CardTitle className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <GlobeAltIcon className="w-4 h-4 text-cyan-400" />
              Deep Surface Cartography ({crawledPages.length} Pages Crawled • {discoveredForms.length} Forms Mapped)
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4 space-y-4 font-mono text-xs max-h-80 overflow-y-auto">
            <div>
              <div className="text-[11px] font-bold text-slate-300 mb-2">Discovered Internal Pages & Assets</div>
              {crawledPages.length > 0 ? (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                  {crawledPages.slice(0, 16).map((page, idx) => (
                    <div
                      key={idx}
                      className="p-2 bg-background-subtle rounded border border-border/40 text-[11px] text-cyan-300 truncate"
                      title={page}
                    >
                      {page}
                    </div>
                  ))}
                  {crawledPages.length > 16 && (
                    <div className="p-2 text-[11px] text-slate-500 text-center sm:col-span-2">
                      + {crawledPages.length - 16} additional internal paths catalogued
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-slate-500">No crawled pages catalogued.</div>
              )}
            </div>

            {discoveredForms.length > 0 && (
              <div className="pt-2 border-t border-border/40">
                <div className="text-[11px] font-bold text-slate-300 mb-2">Mapped Interaction Forms</div>
                <div className="space-y-1.5">
                  {discoveredForms.slice(0, 6).map((form, idx) => (
                    <div
                      key={idx}
                      className="p-2 bg-background-subtle rounded border border-border/40 flex items-center justify-between text-[11px]"
                    >
                      <div className="text-slate-200">
                        <span className="font-bold text-cyber-teal uppercase mr-2">[{form.method}]</span>
                        <span className="text-slate-300">{form.action}</span>
                      </div>
                      <span className="text-slate-500 text-[10px]">
                        {form.inputs?.length || 0} input parameters
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Side-by-Side: Critical Exposures vs. Verified Defense Strengths */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Critical Exposures */}
        <Card className="bg-background-card border-red-500/30">
          <CardHeader className="border-b border-border/40 pb-3">
            <CardTitle className="text-xs font-bold uppercase tracking-wider text-red-400 flex items-center gap-2">
              <ShieldExclamationIcon className="w-4 h-4 text-red-400" />
              Prioritized Critical Exposures ({scorecard.criticalExposures?.length || 0})
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4 space-y-3 font-mono text-xs">
            {scorecard.criticalExposures && scorecard.criticalExposures.length > 0 ? (
              scorecard.criticalExposures.map((exp, idx) => (
                <div key={idx} className="p-3 bg-red-950/20 border border-red-500/40 rounded-xl space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-bold text-red-200 text-xs">{exp.title}</span>
                    <Badge
                      variant={
                        exp.exploitability === "DIRECTLY_EXPLOITABLE"
                          ? "destructive"
                          : "warning"
                      }
                      size="sm"
                      className="text-[10px] uppercase font-bold"
                    >
                      {exp.exploitability ? exp.exploitability.replace(/_/g, " ") : "CONFIRMED"}
                    </Badge>
                  </div>
                  {exp.cwe && <div className="text-[10px] text-slate-400">CWE: {exp.cwe}</div>}
                  {exp.remediationSummary && (
                    <div className="text-[11px] text-slate-300 leading-relaxed pt-1">
                      <span className="text-amber-400 font-semibold">Remediation: </span>
                      {exp.remediationSummary}
                    </div>
                  )}
                </div>
              ))
            ) : (
              <div className="p-6 text-center text-emerald-400 font-mono text-xs">
                <CheckCircleIcon className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
                Zero high-severity perimeter exposures detected.
              </div>
            )}
          </CardContent>
        </Card>

        {/* Verified Defense Strengths */}
        <Card className="bg-background-card border-emerald-500/30">
          <CardHeader className="border-b border-border/40 pb-3">
            <CardTitle className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-2">
              <ShieldCheckIcon className="w-4 h-4 text-emerald-400" />
              Verified Defense Strengths ({scorecard.strengths?.length || 0})
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4 space-y-2.5 font-mono text-xs">
            {scorecard.strengths && scorecard.strengths.length > 0 ? (
              scorecard.strengths.map((str, idx) => (
                <div key={idx} className="p-2.5 bg-emerald-950/20 border border-emerald-500/30 rounded-lg flex items-start gap-2 text-[11px] text-emerald-300">
                  <CheckCircleIcon className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span>{str}</span>
                </div>
              ))
            ) : (
              <div className="p-6 text-center text-slate-500">
                No active defensive countermeasures confirmed present.
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Compliance Posture Matrix (OWASP Top 10 & CIS Controls v8) */}
      {scorecard.compliance && (
        <Card className="bg-background-card border-border">
          <CardHeader className="border-b border-border/40 pb-3">
            <CardTitle className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <LockClosedIcon className="w-4 h-4 text-amber-400" />
              Regulatory & Standards Compliance Alignment
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4 space-y-4 font-mono text-xs">
            {/* OWASP Top 10 */}
            <div>
              <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">
                OWASP Top 10 (2021) Posture
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
                {Object.entries(scorecard.compliance.owaspTop10_2021 || {}).map(([key, val]) => (
                  <div key={key} className="p-2 bg-background-subtle rounded border border-border/40 text-center">
                    <div className="text-[10px] text-slate-400 uppercase truncate" title={key}>
                      {key.replace(/^a\d+_/i, "").replace(/_/g, " ")}
                    </div>
                    <Badge
                      variant={val === "PASS" ? "success" : val === "WARNING" ? "warning" : "destructive"}
                      size="sm"
                      className="mt-1 font-bold text-[10px]"
                    >
                      {val}
                    </Badge>
                  </div>
                ))}
              </div>
            </div>

            {/* CIS Controls */}
            <div className="pt-2 border-t border-border/40">
              <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">
                CIS Critical Security Controls v8
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {Object.entries(scorecard.compliance.cisControlsV8 || {}).map(([key, val]) => (
                  <div key={key} className="p-2 bg-background-subtle rounded border border-border/40 text-center">
                    <div className="text-[10px] text-slate-400 uppercase truncate" title={key}>
                      {key.replace(/([A-Z])/g, " $1")}
                    </div>
                    <Badge
                      variant={val === "COMPLIANT" ? "success" : val === "ACTION_REQUIRED" ? "warning" : "destructive"}
                      size="sm"
                      className="mt-1 font-bold text-[10px]"
                    >
                      {val.replace(/_/g, " ")}
                    </Badge>
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};
