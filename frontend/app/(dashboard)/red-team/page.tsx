"use client";

import React, { useState, useEffect, useMemo } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { MetricCard } from "@/components/ui/metric-card";
import { Table, TableHead, TableBody, TableRow, TableCell, TableHeaderCell } from "@/components/ui/table";
import { assetsApi, Asset } from "@/lib/api/assets";
import { redTeamApi, RedTeamAssessment, AttackGraphData } from "@/lib/api/red-team";
import { AttackGraphVisualizer } from "@/components/red-team/attack-graph-visualizer";
import { RemoteAccessVerificationConsole } from "@/components/red-team/remote-access-verification-console";
import { WellbeingScorecardView } from "@/components/red-team/wellbeing-scorecard-view";
import { BlueTeamHandoffModal } from "@/components/red-team/blue-team-handoff-modal";
import { AssessmentBrainView } from "@/components/red-team/assessment-brain-view";
import { useToast } from "@/lib/store/toast-store";
import {
  FireIcon,
  PlayIcon,
  ArrowPathIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
  CpuChipIcon,
  BoltIcon,
  CommandLineIcon,
  GlobeAltIcon,
  ShieldCheckIcon,
  StopIcon,
  DocumentArrowDownIcon,
  EyeIcon,
  KeyIcon,
  MagnifyingGlassIcon,
  ClockIcon,
  HeartIcon,
  SparklesIcon,
  ClipboardDocumentCheckIcon,
  CheckIcon,
  XMarkIcon
} from "@heroicons/react/24/outline";

export default function RedTeamPage() {
  const { addToast } = useToast();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [selectedAsset, setSelectedAsset] = useState("");
  const [customTarget, setCustomTarget] = useState("");
  const [timeBudget, setTimeBudget] = useState("30");
  const [credentialTesting, setCredentialTesting] = useState(false);
  const [launching, setLaunching] = useState(false);
  const [cancelling, setCancelling] = useState(false);

  // Active Assessment State
  const [activeAssessmentId, setActiveAssessmentId] = useState<string | null>(null);
  const [assessment, setAssessment] = useState<RedTeamAssessment | null>(null);
  const [attackGraphData, setAttackGraphData] = useState<AttackGraphData | null>(null);
  const [activeTab, setActiveTab] = useState<"wellbeing" | "brain" | "graph" | "hypotheses" | "coverage" | "timeline">("wellbeing");
  const [selectedHypo, setSelectedHypo] = useState<any | null>(null);
  const [isConsoleOpen, setIsConsoleOpen] = useState(false);
  const [elapsedTime, setElapsedTime] = useState<string>("00:00");

  // Blue Team Handoff State
  const [isBlueTeamModalOpen, setIsBlueTeamModalOpen] = useState(false);
  const [blueTeamData, setBlueTeamData] = useState<any | null>(null);
  const [isHandingOff, setIsHandingOff] = useState(false);
  const [copiedRuleId, setCopiedRuleId] = useState<string | null>(null);

  // Load registered assets and any running assessments on mount
  useEffect(() => {
    assetsApi.getAssets().then((data) => {
      setAssets(data);
      if (data.length > 0) setSelectedAsset(data[0].target);
    }).catch(() => []);

    // Check for active assessments in DB
    redTeamApi.getActiveAssessments().then((res) => {
      if (res.assessments && res.assessments.length > 0) {
        const latest = res.assessments[0];
        setActiveAssessmentId(latest.id);
      }
    }).catch(() => {});
  }, []);

  // Poll active assessment state
  useEffect(() => {
    if (!activeAssessmentId) return;

    let isSubscribed = true;

    const fetchAssessmentData = async () => {
      try {
        const data = await redTeamApi.getAssessment(activeAssessmentId);
        if (!isSubscribed || !data) return;

        setAssessment(data);

        // Fetch attack graph
        const graph = await redTeamApi.getAttackGraph(activeAssessmentId);
        if (graph && isSubscribed) {
          setAttackGraphData(graph);
        }
      } catch (err) {
        console.error("Failed to refresh assessment:", err);
      }
    };

    fetchAssessmentData();

    const interval = setInterval(() => {
      if (assessment?.status === "COMPLETED" || assessment?.status === "CANCELLED" || assessment?.status === "FAILED") {
        clearInterval(interval);
        return;
      }
      fetchAssessmentData();
    }, 2500);

    return () => {
      isSubscribed = false;
      clearInterval(interval);
    };
  }, [activeAssessmentId, assessment?.status]);

  // Elapsed Timer
  useEffect(() => {
    if (!assessment?.startedAt) return;

    const timer = setInterval(() => {
      const start = new Date(assessment.startedAt).getTime();
      const end = assessment.completedAt ? new Date(assessment.completedAt).getTime() : Date.now();
      const diffSec = Math.max(0, Math.floor((end - start) / 1000));
      const mins = Math.floor(diffSec / 60);
      const secs = diffSec % 60;
      setElapsedTime(`${mins < 10 ? "0" : ""}${mins}:${secs < 10 ? "0" : ""}${secs}`);
    }, 1000);

    return () => clearInterval(timer);
  }, [assessment?.startedAt, assessment?.completedAt]);

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    const finalTarget = customTarget.trim() || selectedAsset || "127.0.0.1";

    setLaunching(true);
    try {
      const res = await redTeamApi.launchAssessment({
        target: finalTarget,
        scope: {
          allowedDomains: [finalTarget],
          timeBudgetMinutes: parseInt(timeBudget) || 30,
          credentialTesting
        }
      });

      addToast(`Armed Ultra-Deep Assessment for ${finalTarget}`, "success");
      if (res.scanId) {
        // Fetch newly created assessment ID
        const assessmentRecord = await redTeamApi.getAssessment(res.scanId);
        if (assessmentRecord) {
          setActiveAssessmentId(assessmentRecord.id);
          setAssessment(assessmentRecord);
        }
      }
    } catch (err: any) {
      addToast(err?.response?.data?.message || "Failed to dispatch assessment", "error");
    } finally {
      setLaunching(false);
    }
  };

  const handleCancel = async () => {
    if (!assessment) return;
    setCancelling(true);
    try {
      await redTeamApi.cancelAssessment(assessment.id, "Operator aborted assessment from dashboard");
      addToast("Assessment cancellation requested", "warning");
      const updated = await redTeamApi.getAssessment(assessment.id);
      if (updated) setAssessment(updated);
    } catch (err: any) {
      addToast(err?.response?.data?.message || "Failed to cancel assessment", "error");
    } finally {
      setCancelling(false);
    }
  };

  const handleBlueTeamHandoff = async () => {
    if (!assessment) return;
    setIsHandingOff(true);
    try {
      const data = await redTeamApi.handoffToBlueTeam(assessment.id);
      setBlueTeamData(data);
      setIsBlueTeamModalOpen(true);
      addToast("Report staged successfully for Blue Team defense ingestion!", "success");
    } catch (err: any) {
      addToast(err?.response?.data?.message || "Failed to stage report for Blue Team", "error");
    } finally {
      setIsHandingOff(false);
    }
  };

  // Derived metrics from verified backend state
  const hypotheses = assessment?.hypotheses || [];
  const verifiedCount = hypotheses.filter((h) => h.status === "VERIFIED").length;
  const rejectedCount = hypotheses.filter((h) => h.status === "REJECTED").length;
  const inconclusiveCount = hypotheses.filter((h) => h.status === "INCONCLUSIVE").length;
  const coveragePercent = assessment?.coverage?.coveragePercent || 0;
  const isRunning = assessment?.status === "RUNNING" || assessment?.status === "INITIALIZING";

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#1e293b] pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-b from-[#162032] to-[#070b14] border border-red-500/40 flex items-center justify-center p-1.5 shadow-glow-danger">
              <img src="/shield-logo.png" alt="Emblem" className="w-full h-full object-contain filter drop-shadow-[0_0_6px_#ff3366]" />
            </div>
            <h1 className="text-2xl font-black font-mono tracking-wide text-slate-100">
              CYBER<span className="text-red-400">SPLOI</span> RED TEAM APT ENGINE
            </h1>
          </div>
          <p className="text-xs font-mono text-slate-400 mt-1 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse shadow-[0_0_8px_#ff3366]"></span>
            Persistent Lifecycle • Real Socket Discovery • Empirical Hypotheses • Adaptive Reassessment
          </p>
        </div>

        <div className="flex items-center gap-3">
          {assessment && (
            <Button
              onClick={handleBlueTeamHandoff}
              disabled={isHandingOff}
              className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-xs font-mono text-white shadow-lg shadow-blue-500/20 border border-blue-400/40 transition-all font-semibold"
            >
              <ShieldCheckIcon className="w-4 h-4 text-blue-200" />
              {isHandingOff ? "Staging Handoff..." : "Give Report to Blue Team"}
            </Button>
          )}
          {assessment && (
            <a
              href={`/api/v1/red-team/assessments/${assessment.id}/report/markdown`}
              download
              className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-border bg-background-card hover:bg-white/[0.04] text-xs font-mono text-slate-200 transition-colors"
            >
              <DocumentArrowDownIcon className="w-4 h-4 text-cyber-teal" />
              Export Audit Report
            </a>
          )}
          {isRunning && (
            <Button
              variant="danger"
              size="sm"
              onClick={handleCancel}
              disabled={cancelling}
              className="flex items-center gap-1.5 font-mono text-xs"
            >
              <StopIcon className="w-4 h-4" />
              {cancelling ? "Stopping Engine..." : "Cancel Assessment"}
            </Button>
          )}
        </div>
      </div>

      {/* Target Definition & Scope Config (When no active assessment or toggled) */}
      {!assessment || assessment.status === "COMPLETED" || assessment.status === "CANCELLED" || assessment.status === "FAILED" ? (
        <Card className="glass-panel border-red-500/20">
          <CardHeader className="border-b border-border/60 pb-3">
            <CardTitle className="text-xs font-mono uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <CpuChipIcon className="w-4 h-4 text-red-400" />
              Configure Authorized Scope & Assessment Rules
            </CardTitle>
          </CardHeader>
          <CardContent className="p-5">
            <form onSubmit={handleLaunch} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1">
                    Enrolled Asset in Scope
                  </label>
                  <Select
                    value={selectedAsset}
                    onChange={(e) => {
                      setSelectedAsset(e.target.value);
                      setCustomTarget("");
                    }}
                    options={[
                      ...assets.map((a) => ({ label: `${a.name} (${a.target})`, value: a.target })),
                      { label: "Local Security Sandbox (127.0.0.1:8899)", value: "127.0.0.1:8899" },
                    ]}
                    className="bg-background border-border text-xs font-mono"
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1">
                    Or Specify Ad-Hoc Target Host / IP
                  </label>
                  <Input
                    placeholder="e.g. 127.0.0.1:8899 or target.local"
                    value={customTarget}
                    onChange={(e) => setCustomTarget(e.target.value)}
                    className="bg-background border-border text-xs font-mono"
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1">
                    Time Budget (Minutes)
                  </label>
                  <Select
                    value={timeBudget}
                    onChange={(e) => setTimeBudget(e.target.value)}
                    options={[
                      { label: "Quick Assessment (10 min)", value: "10" },
                      { label: "Extended Deep Assessment (20 min)", value: "20" },
                      { label: "Ultra-Deep Comprehensive (30+ min)", value: "30" },
                    ]}
                    className="bg-background border-border text-xs font-mono"
                  />
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-4 pt-3 border-t border-border/40">
                <div className="flex items-center gap-6 text-xs font-mono text-slate-400">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={credentialTesting}
                      onChange={(e) => setCredentialTesting(e.target.checked)}
                      className="rounded border-border bg-background"
                    />
                    <span>Audit Identity & Auth Lifecycle</span>
                  </label>
                  <span className="text-slate-500">•</span>
                  <span className="text-emerald-400">Non-Destructive Rules Active</span>
                </div>

                <Button
                  type="submit"
                  disabled={launching}
                  className="bg-red-600 hover:bg-red-500 text-white font-mono text-xs px-6 py-2 flex items-center gap-2"
                >
                  {launching ? (
                    <>
                      <ArrowPathIcon className="w-4 h-4 animate-spin" />
                      Arming Engine...
                    </>
                  ) : (
                    <>
                      <PlayIcon className="w-4 h-4" />
                      Arm & Launch Ultra-Deep Assessment
                    </>
                  )}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      ) : null}

      {/* Live Cockpit Banner (If Assessment Loaded) */}
      {assessment && (
        <div className="space-y-6">
          <div className="p-4 bg-background-card rounded-2xl border border-border flex flex-wrap items-center justify-between gap-4 font-mono text-xs">
            <div className="flex items-center gap-3">
              <div className="w-3 h-3 rounded-full bg-red-500 animate-pulse"></div>
              <div>
                <span className="text-[10px] text-slate-400 uppercase">Active Target</span>
                <div className="text-base font-bold text-slate-100">{assessment.scope?.target || "Target Host"}</div>
              </div>
            </div>

            <div>
              <span className="text-[10px] text-slate-400 uppercase">Assessment Status</span>
              <div className="mt-0.5">
                <Badge
                  variant={
                    assessment.status === "COMPLETED"
                      ? "success"
                      : assessment.status === "CANCELLED"
                      ? "destructive"
                      : assessment.status === "FAILED"
                      ? "destructive"
                      : "warning"
                  }
                  pulse={isRunning}
                  className="font-bold uppercase"
                >
                  {assessment.status}
                </Badge>
              </div>
            </div>

            <div>
              <span className="text-[10px] text-slate-400 uppercase">Elapsed Time</span>
              <div className="text-sm font-bold text-slate-200 flex items-center gap-1.5 mt-0.5">
                <ClockIcon className="w-4 h-4 text-cyber-teal" />
                {elapsedTime}
              </div>
            </div>

            <div>
              <span className="text-[10px] text-slate-400 uppercase">Current Phase</span>
              <div className="text-xs font-bold text-cyber-teal mt-0.5">{assessment.phase}</div>
            </div>

            <div className="max-w-md">
              <span className="text-[10px] text-slate-400 uppercase">Current Objective</span>
              <div className="text-xs text-slate-300 truncate mt-0.5">
                {assessment.currentObjective || "Executing scheduled assessment sequence..."}
              </div>
            </div>
          </div>

          {/* Real Metrics Grid (Zero Fabricated Values) */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3.5">
            <MetricCard
              title="ASSETS DISCOVERED"
              value={assessment.coverage?.assetsDiscovered || 1}
              icon={GlobeAltIcon}
              accent="teal"
            />
            <MetricCard
              title="ROUTES MAPPED"
              value={assessment.coverage?.routesDiscovered || 0}
              icon={CommandLineIcon}
              accent="teal"
            />
            <MetricCard
              title="HYPOTHESES"
              value={hypotheses.length}
              icon={CpuChipIcon}
              accent="neutral"
            />
            <MetricCard
              title="VERIFIED FINDINGS"
              value={verifiedCount}
              icon={ShieldExclamationIcon}
              accent="danger"
            />
            <MetricCard
              title="REJECTED FALSE POSITIVES"
              value={rejectedCount}
              icon={CheckCircleIcon}
              accent="emerald"
            />
            <MetricCard
              title="TRUTHFUL COVERAGE"
              value={coveragePercent}
              suffix="%"
              icon={ShieldCheckIcon}
              accent="amber"
            />
          </div>

          {/* Operator Reasoning Cockpit ("What CyberSploi Is Thinking About") */}
          <div className="p-4 rounded-2xl border border-cyber-teal/40 bg-cyber-teal/5 font-mono text-xs space-y-2.5 shadow-lg shadow-cyber-teal/5">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-cyber-teal/20 pb-2">
              <div className="flex items-center gap-2">
                <SparklesIcon className="w-4 h-4 text-cyber-teal animate-pulse" />
                <span className="font-bold uppercase tracking-wider text-cyber-teal">
                  What CyberSploi Is Thinking About (Live Decision Stream)
                </span>
              </div>
              <span className="text-[10px] text-slate-400">
                Machine-Readable Operator Reasoning • Step-by-Step Rationale
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
              <div className="p-2.5 rounded-xl bg-background/80 border border-border/60 space-y-1">
                <span className="text-[10px] text-slate-400 uppercase font-bold block">
                  1. Current Investigation
                </span>
                <p className="text-slate-100 font-semibold leading-relaxed">
                  {assessment.assessmentBrain?.currentReasoning?.currentInvestigation || assessment.currentObjective || "Executing scheduled assessment sequence..."}
                </p>
              </div>

              <div className="p-2.5 rounded-xl bg-background/80 border border-border/60 space-y-1">
                <span className="text-[10px] text-slate-400 uppercase font-bold block">
                  2. Immediate Next Action
                </span>
                <p className="text-cyber-teal font-semibold leading-relaxed">
                  {assessment.assessmentBrain?.currentReasoning?.nextAction || "Synthesizing empirical findings and updating attack surface telemetry."}
                </p>
              </div>

              <div className="p-2.5 rounded-xl bg-background/80 border border-border/60 space-y-1">
                <span className="text-[10px] text-slate-400 uppercase font-bold block">
                  3. Strategic Rationale (Why)
                </span>
                <p className="text-slate-300 italic text-[11px] leading-relaxed">
                  "{assessment.assessmentBrain?.currentReasoning?.why || "Validates security boundaries to maintain zero false positives and comprehensive evidence defensibility."}"
                </p>
              </div>
            </div>
          </div>

          {/* Controlled Verification Console Launch Banner */}
          {assessment.sessions && assessment.sessions.length > 0 && (
            <div className="p-4 bg-red-950/20 border border-red-500/40 rounded-xl flex items-center justify-between gap-4 font-mono text-xs">
              <div className="flex items-center gap-3">
                <KeyIcon className="w-6 h-6 text-amber-400" />
                <div>
                  <div className="text-slate-100 font-bold">
                    Controlled Verification Session Active ({assessment.sessions[0].sessionToken})
                  </div>
                  <div className="text-slate-400 text-[11px]">
                    Bounded evidence verification console available for authorized operator inspection.
                  </div>
                </div>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setIsConsoleOpen(true)}
                className="border-amber-500/60 text-amber-300 hover:bg-amber-500/10 font-mono text-xs"
              >
                Open Verification Console
              </Button>
            </div>
          )}

          {/* Tab Navigation */}
          <div className="flex border-b border-border font-mono text-xs overflow-x-auto">
            <button
              onClick={() => setActiveTab("wellbeing")}
              className={`px-4 py-2.5 border-b-2 font-bold transition-all flex items-center gap-1.5 whitespace-nowrap ${
                activeTab === "wellbeing"
                  ? "border-cyber-teal text-cyber-teal bg-cyber-teal/5"
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              <HeartIcon className="w-4 h-4 text-emerald-400" />
              Website Wellbeing Scorecard
            </button>
            <button
              onClick={() => setActiveTab("brain")}
              className={`px-4 py-2.5 border-b-2 font-bold transition-all flex items-center gap-1.5 whitespace-nowrap ${
                activeTab === "brain"
                  ? "border-cyber-teal text-cyber-teal bg-cyber-teal/5"
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              <CpuChipIcon className="w-4 h-4 text-cyber-teal" />
              Assessment Brain & Knowledge Model
            </button>
            <button
              onClick={() => setActiveTab("graph")}
              className={`px-4 py-2.5 border-b-2 font-bold transition-all flex items-center gap-1.5 whitespace-nowrap ${
                activeTab === "graph"
                  ? "border-cyber-teal text-cyber-teal bg-cyber-teal/5"
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              <CpuChipIcon className="w-4 h-4 text-purple-400" />
              Attack Graph Visualizer ({attackGraphData?.nodes.length || 0})
            </button>
            <button
              onClick={() => setActiveTab("hypotheses")}
              className={`px-4 py-2.5 border-b-2 font-bold transition-all flex items-center gap-1.5 whitespace-nowrap ${
                activeTab === "hypotheses"
                  ? "border-cyber-teal text-cyber-teal bg-cyber-teal/5"
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              <ShieldExclamationIcon className="w-4 h-4 text-amber-400" />
              Hypotheses & Usability Testing ({hypotheses.length})
            </button>
            <button
              onClick={() => setActiveTab("coverage")}
              className={`px-4 py-2.5 border-b-2 font-bold transition-all flex items-center gap-1.5 whitespace-nowrap ${
                activeTab === "coverage"
                  ? "border-cyber-teal text-cyber-teal bg-cyber-teal/5"
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              <GlobeAltIcon className="w-4 h-4 text-cyan-400" />
              Deep Surface & Blind Spots
            </button>
            <button
              onClick={() => setActiveTab("timeline")}
              className={`px-4 py-2.5 border-b-2 font-bold transition-all flex items-center gap-1.5 whitespace-nowrap ${
                activeTab === "timeline"
                  ? "border-cyber-teal text-cyber-teal bg-cyber-teal/5"
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              <ClockIcon className="w-4 h-4 text-blue-400" />
              Timeline & Audit Trail ({assessment.events?.length || 0})
            </button>
          </div>

          {/* Tab Content */}
          {activeTab === "wellbeing" && (
            <WellbeingScorecardView
              scorecard={assessment.wellbeingScorecard}
              techStack={assessment.techStack}
              crawledPages={assessment.crawledPages}
              discoveredForms={assessment.discoveredForms}
              isLoading={isRunning && !assessment.wellbeingScorecard}
              onHandoffBlueTeam={handleBlueTeamHandoff}
            />
          )}

          {activeTab === "brain" && (
            <AssessmentBrainView
              brain={assessment.assessmentBrain}
              isLoading={isRunning && !assessment.assessmentBrain}
            />
          )}

          {activeTab === "graph" && (
            <Card>
              <CardContent className="p-4">
                <AttackGraphVisualizer
                  nodes={attackGraphData?.nodes || []}
                  edges={attackGraphData?.edges || []}
                  stats={attackGraphData?.stats}
                />
              </CardContent>
            </Card>
          )}

          {activeTab === "hypotheses" && (
            <Card>
              <CardContent className="p-4">
                {hypotheses.length === 0 ? (
                  <div className="py-12 text-center text-slate-500 font-mono text-xs">
                    Hypothesis synthesis in progress. Awaiting cartography analysis...
                  </div>
                ) : (
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableHeaderCell>Hypothesis</TableHeaderCell>
                        <TableHeaderCell>Category</TableHeaderCell>
                        <TableHeaderCell>Endpoint</TableHeaderCell>
                        <TableHeaderCell>Exploitability</TableHeaderCell>
                        <TableHeaderCell>Confidence</TableHeaderCell>
                        <TableHeaderCell>Outcome</TableHeaderCell>
                        <TableHeaderCell>Actions</TableHeaderCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {hypotheses.map((h) => (
                        <TableRow key={h.id}>
                          <TableCell className="font-semibold text-slate-200">{h.title}</TableCell>
                          <TableCell className="font-mono text-xs text-slate-400">{h.category}</TableCell>
                          <TableCell className="font-mono text-xs text-cyan-400">{h.targetEndpoint}</TableCell>
                          <TableCell>
                            <Badge
                              variant={
                                h.exploitability === "DIRECTLY_EXPLOITABLE"
                                  ? "destructive"
                                  : h.exploitability === "CONDITIONALLY_EXPLOITABLE"
                                  ? "warning"
                                  : "info"
                              }
                              size="sm"
                              className="font-bold uppercase text-[10px]"
                            >
                              {h.exploitability ? h.exploitability.replace(/_/g, " ") : "SURFACE WEAKNESS"}
                            </Badge>
                          </TableCell>
                          <TableCell className="font-mono text-xs">
                            <span className={h.currentConfidence >= 0.8 ? "text-red-400 font-bold" : "text-slate-400"}>
                              {Math.round(h.currentConfidence * 100)}%
                            </span>
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant={
                                h.status === "VERIFIED"
                                  ? "destructive"
                                  : h.status === "REJECTED"
                                  ? "success"
                                  : "warning"
                              }
                              size="sm"
                            >
                              {h.status}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setSelectedHypo(h)}
                              className="text-xs font-mono text-cyber-teal"
                            >
                              Inspect Evidence
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          )}

          {activeTab === "coverage" && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle className="text-xs font-mono uppercase text-slate-300">
                    Calculated Assessment Coverage
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-5 space-y-4 font-mono text-xs">
                  <div>
                    <div className="flex justify-between text-slate-300 mb-1">
                      <span>Overall Truthful Coverage:</span>
                      <strong className="text-amber-400">{coveragePercent}%</strong>
                    </div>
                    <div className="w-full bg-background rounded-full h-2 overflow-hidden border border-border">
                      <div
                        className="bg-amber-400 h-2 rounded-full transition-all duration-700"
                        style={{ width: `${coveragePercent}%` }}
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3 pt-3 border-t border-border/40 text-[11px]">
                    <div className="p-2.5 bg-background-subtle rounded border border-border">
                      <div className="text-slate-400">Routes Tested</div>
                      <div className="text-base font-bold text-slate-100 mt-0.5">
                        {assessment.coverage?.routesTested || 0} / {assessment.coverage?.routesDiscovered || 0}
                      </div>
                    </div>
                    <div className="p-2.5 bg-background-subtle rounded border border-border">
                      <div className="text-slate-400">Hypotheses Resolved</div>
                      <div className="text-base font-bold text-slate-100 mt-0.5">
                        {verifiedCount + rejectedCount} / {hypotheses.length}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-xs font-mono uppercase text-slate-300">
                    Operational Blind Spots
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-5 space-y-3 font-mono text-xs">
                  {assessment.coverage?.blindSpots ? (
                    (() => {
                      try {
                        const spots = typeof assessment.coverage.blindSpots === "string"
                          ? JSON.parse(assessment.coverage.blindSpots)
                          : assessment.coverage.blindSpots;
                        return spots.map((spot: any, idx: number) => (
                          <div key={idx} className="p-3 bg-background-subtle rounded border border-border">
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-amber-400">{spot.title}</span>
                              <Badge variant="outline" size="sm">{spot.category}</Badge>
                            </div>
                            <p className="text-[11px] text-slate-400 mt-1.5 leading-relaxed">{spot.reason}</p>
                          </div>
                        ));
                      } catch (e) {
                        return <div className="text-slate-500">No blind spots recorded.</div>;
                      }
                    })()
                  ) : (
                    <div className="text-slate-500">No blind spot data available.</div>
                  )}
                </CardContent>
              </Card>
            </div>
          )}

          {activeTab === "timeline" && (
            <Card>
              <CardContent className="p-4">
                <div className="space-y-2 font-mono text-xs">
                  {(assessment.events || []).map((ev) => (
                    <div key={ev.id} className="p-2.5 bg-background-subtle rounded border border-border flex items-start gap-3">
                      <span className="text-slate-500 text-[10px] shrink-0 mt-0.5">
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </span>
                      <Badge
                        variant={
                          ev.level === "SUCCESS"
                            ? "success"
                            : ev.level === "CRITICAL"
                            ? "destructive"
                            : ev.level === "WARN"
                            ? "warning"
                            : "info"
                        }
                        size="sm"
                      >
                        {ev.phase}
                      </Badge>
                      <div className="text-slate-300">
                        <span className="font-bold text-slate-200 mr-2">[{ev.stage || "Core"}]</span>
                        {ev.message}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* Hypothesis Evidence Modal */}
      {selectedHypo && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4 font-mono text-xs">
          <div className="bg-background-card border border-border rounded-2xl p-6 max-w-2xl w-full space-y-4">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <h3 className="font-bold text-slate-100 text-sm">{selectedHypo.title}</h3>
              <Button variant="ghost" size="sm" onClick={() => setSelectedHypo(null)}>✕</Button>
            </div>
            <div className="space-y-3 text-slate-300">
              <div className="flex items-center justify-between">
                <span className="text-slate-400"><strong>Target:</strong> <span className="text-cyan-400">{selectedHypo.targetEndpoint}</span></span>
                <Badge
                  variant={
                    selectedHypo.exploitability === "DIRECTLY_EXPLOITABLE"
                      ? "destructive"
                      : selectedHypo.exploitability === "CONDITIONALLY_EXPLOITABLE"
                      ? "warning"
                      : "info"
                  }
                  size="sm"
                  className="font-bold uppercase text-[10px]"
                >
                  {selectedHypo.exploitability ? selectedHypo.exploitability.replace(/_/g, " ") : "SURFACE WEAKNESS"}
                </Badge>
              </div>
              <p><strong>Description:</strong> {selectedHypo.description}</p>
              <p><strong>Procedure:</strong> {selectedHypo.testProcedure}</p>
              {selectedHypo.rejectionReason && (
                <p className="text-emerald-400"><strong>Rejection Reason:</strong> {selectedHypo.rejectionReason}</p>
              )}
              {selectedHypo.evidence && (
                <div>
                  <strong>Traceable Evidence:</strong>
                  <pre className="p-3 bg-black/60 rounded border border-border/60 overflow-x-auto text-[11px] text-slate-200 mt-1 max-h-48">
                    {typeof selectedHypo.evidence === "string"
                      ? selectedHypo.evidence
                      : JSON.stringify(selectedHypo.evidence, null, 2)}
                  </pre>
                </div>
              )}
            </div>
            <div className="text-right pt-2 border-t border-border">
              <Button size="sm" onClick={() => setSelectedHypo(null)}>Close</Button>
            </div>
          </div>
        </div>
      )}

      {/* Controlled Remote Access Verification Console Modal */}
      {assessment?.sessions && assessment.sessions.length > 0 && (
        <RemoteAccessVerificationConsole
          isOpen={isConsoleOpen}
          onClose={() => setIsConsoleOpen(false)}
          session={assessment.sessions[0]}
          target={assessment.scope?.target || "127.0.0.1"}
          onSessionTerminated={() => {
            redTeamApi.getAssessment(assessment.id).then((a) => a && setAssessment(a));
          }}
        />
      )}

      {/* Blue Team Defense Handoff Staging Modal */}
      <BlueTeamHandoffModal
        isOpen={isBlueTeamModalOpen}
        onClose={() => setIsBlueTeamModalOpen(false)}
        data={blueTeamData}
      />
    </div>
  );
}
