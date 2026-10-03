"use client";

import React, { useState } from "react";
import { Modal } from "@/components/ui/modal";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  ShieldCheckIcon,
  ShieldExclamationIcon,
  CheckIcon,
  ClipboardDocumentCheckIcon,
  CommandLineIcon,
  SparklesIcon,
  InformationCircleIcon
} from "@heroicons/react/24/outline";

interface BlueTeamHandoffModalProps {
  isOpen: boolean;
  onClose: () => void;
  data: {
    assessmentId?: string;
    target?: string;
    status?: string;
    defenseEngineStatus?: string;
    summary?: {
      totalMitigations: number;
      wafRulesCount: number;
      remediationTasksCount: number;
      criticalAlerts: number;
    };
    wafRules?: Array<{
      ruleId: string;
      description: string;
      severity: string;
      targetPath: string;
      modSecurityExpression: string;
      cloudflareExpression: string;
    }>;
    firewallRules?: any[];
    remediationTasks?: Array<{
      taskId: string;
      title: string;
      priority: string;
      cwe?: string;
      remediation: string;
    }>;
  } | null;
}

export const BlueTeamHandoffModal: React.FC<BlueTeamHandoffModalProps> = ({
  isOpen,
  onClose,
  data,
}) => {
  const [activeTab, setActiveTab] = useState<"waf" | "cloudflare" | "tasks">("waf");
  const [copiedId, setCopiedId] = useState<string | null>(null);

  if (!data) return null;

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const summary = data.summary || {
    totalMitigations: 0,
    wafRulesCount: 0,
    remediationTasksCount: 0,
    criticalAlerts: 0,
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="BLUE TEAM DEFENSE HANDOFF ORCHESTRATOR"
      maxWidth="xl"
    >
      <div className="space-y-5 font-mono text-xs p-1">
        {/* Defense Staging Banner */}
        <div className="p-4 rounded-xl bg-blue-950/40 border border-blue-500/40 text-blue-200 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 font-bold text-sm text-blue-100">
              <ShieldCheckIcon className="w-5 h-5 text-blue-400" />
              Defense Ingestion Pipeline: STANDBY
            </div>
            <Badge variant="warning" size="sm" className="font-bold uppercase">
              Awaiting Defense Engine Activation
            </Badge>
          </div>
          <p className="text-[11px] text-blue-300/90 leading-relaxed">
            All red-team assessment findings have been mapped to automated defense configurations.
            When the Blue Team service module is brought online, these virtual patches and WAF rules
            can be directly deployed to origin gateways, reverse proxies, and cloud firewalls.
          </p>
        </div>

        {/* Telemetry Summary Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
          <div className="p-3 bg-background-subtle rounded-lg border border-border">
            <span className="text-[10px] text-slate-400 uppercase">Mitigations Staged</span>
            <div className="text-lg font-bold text-slate-100 mt-0.5">
              {summary.totalMitigations}
            </div>
          </div>
          <div className="p-3 bg-background-subtle rounded-lg border border-border">
            <span className="text-[10px] text-slate-400 uppercase">WAF Virtual Patches</span>
            <div className="text-lg font-bold text-cyan-400 mt-0.5">
              {summary.wafRulesCount}
            </div>
          </div>
          <div className="p-3 bg-background-subtle rounded-lg border border-border">
            <span className="text-[10px] text-slate-400 uppercase">Prioritized Tasks</span>
            <div className="text-lg font-bold text-purple-400 mt-0.5">
              {summary.remediationTasksCount}
            </div>
          </div>
          <div className="p-3 bg-background-subtle rounded-lg border border-border">
            <span className="text-[10px] text-slate-400 uppercase">Critical Blockers</span>
            <div className="text-lg font-bold text-red-400 mt-0.5">
              {summary.criticalAlerts}
            </div>
          </div>
        </div>

        {/* View Switcher */}
        <div className="flex border-b border-border text-xs">
          <button
            onClick={() => setActiveTab("waf")}
            className={`px-4 py-2 border-b-2 font-bold transition-all ${
              activeTab === "waf"
                ? "border-cyber-teal text-cyber-teal bg-cyber-teal/5"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            ModSecurity WAF Rules ({data.wafRules?.length || 0})
          </button>
          <button
            onClick={() => setActiveTab("cloudflare")}
            className={`px-4 py-2 border-b-2 font-bold transition-all ${
              activeTab === "cloudflare"
                ? "border-cyber-teal text-cyber-teal bg-cyber-teal/5"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            Cloudflare Rules ({data.wafRules?.length || 0})
          </button>
          <button
            onClick={() => setActiveTab("tasks")}
            className={`px-4 py-2 border-b-2 font-bold transition-all ${
              activeTab === "tasks"
                ? "border-cyber-teal text-cyber-teal bg-cyber-teal/5"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            Remediation Tasks ({data.remediationTasks?.length || 0})
          </button>
        </div>

        {/* Tab 1: ModSecurity Rules */}
        {activeTab === "waf" && (
          <div className="space-y-3 max-h-72 overflow-y-auto pr-1">
            {data.wafRules && data.wafRules.length > 0 ? (
              data.wafRules.map((rule) => (
                <div
                  key={rule.ruleId}
                  className="p-3 bg-background-subtle rounded-xl border border-border space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-cyan-400">{rule.ruleId}</span>
                      <span className="text-slate-400 text-[11px]">• {rule.description}</span>
                    </div>
                    <Badge
                      variant={rule.severity === "CRITICAL" ? "destructive" : "warning"}
                      size="sm"
                    >
                      {rule.severity}
                    </Badge>
                  </div>

                  <div className="relative">
                    <pre className="p-2.5 bg-black/70 rounded border border-border/60 text-[11px] text-slate-200 overflow-x-auto">
                      {rule.modSecurityExpression}
                    </pre>
                    <button
                      onClick={() => handleCopy(rule.ruleId, rule.modSecurityExpression)}
                      className="absolute top-2 right-2 p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                      title="Copy Rule"
                    >
                      {copiedId === rule.ruleId ? (
                        <CheckIcon className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <ClipboardDocumentCheckIcon className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-slate-500 py-6 text-center">
                No virtual WAF rules required for current findings.
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Cloudflare Rules */}
        {activeTab === "cloudflare" && (
          <div className="space-y-3 max-h-72 overflow-y-auto pr-1">
            {data.wafRules && data.wafRules.length > 0 ? (
              data.wafRules.map((rule) => (
                <div
                  key={rule.ruleId}
                  className="p-3 bg-background-subtle rounded-xl border border-border space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-amber-400">{rule.ruleId}</span>
                    <span className="text-[11px] text-slate-400">{rule.targetPath}</span>
                  </div>

                  <div className="relative">
                    <pre className="p-2.5 bg-black/70 rounded border border-border/60 text-[11px] text-amber-200 overflow-x-auto">
                      {rule.cloudflareExpression}
                    </pre>
                    <button
                      onClick={() => handleCopy(`cf-${rule.ruleId}`, rule.cloudflareExpression)}
                      className="absolute top-2 right-2 p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                      title="Copy Expression"
                    >
                      {copiedId === `cf-${rule.ruleId}` ? (
                        <CheckIcon className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <ClipboardDocumentCheckIcon className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-slate-500 py-6 text-center">
                No Cloudflare firewall expressions required.
              </div>
            )}
          </div>
        )}

        {/* Tab 3: Remediation Queue */}
        {activeTab === "tasks" && (
          <div className="space-y-2.5 max-h-72 overflow-y-auto pr-1">
            {data.remediationTasks && data.remediationTasks.length > 0 ? (
              data.remediationTasks.map((task) => (
                <div
                  key={task.taskId}
                  className="p-3 bg-background-subtle rounded-xl border border-border space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-200">{task.title}</span>
                    <Badge
                      variant={task.priority.startsWith("P0") ? "destructive" : "warning"}
                      size="sm"
                    >
                      {task.priority}
                    </Badge>
                  </div>
                  {task.cwe && <div className="text-[10px] text-slate-400">CWE: {task.cwe}</div>}
                  <div className="text-[11px] text-slate-300 leading-relaxed bg-black/40 p-2 rounded border border-border/40">
                    <span className="text-cyber-teal font-semibold">Defensive Patch: </span>
                    {task.remediation}
                  </div>
                </div>
              ))
            ) : (
              <div className="text-slate-500 py-6 text-center">
                No active remediation tasks in queue.
              </div>
            )}
          </div>
        )}

        {/* Footer info & Close */}
        <div className="flex items-center justify-between pt-3 border-t border-border/60">
          <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
            <InformationCircleIcon className="w-4 h-4 text-blue-400" />
            <span>Target: {data.target || "Local Scope"}</span>
          </div>
          <Button onClick={onClose} size="sm" className="font-mono text-xs">
            Acknowledge & Close
          </Button>
        </div>
      </div>
    </Modal>
  );
};
