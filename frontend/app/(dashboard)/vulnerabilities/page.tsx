"use client";

import React, { useState, useEffect } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Modal } from "@/components/ui/modal";
import { Table, TableHead, TableBody, TableRow, TableCell, TableHeaderCell } from "@/components/ui/table";
import { MetricCard } from "@/components/ui/metric-card";
import { vulnerabilitiesApi, Vulnerability } from "@/lib/api/vulnerabilities";
import { useToast } from "@/lib/store/toast-store";
import {
  ShieldExclamationIcon,
  MagnifyingGlassIcon,
  ArrowPathIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  FunnelIcon,
  CommandLineIcon,
  DocumentArrowDownIcon,
  BugAntIcon,
} from "@heroicons/react/24/outline";

export default function VulnerabilitiesPage() {
  const { addToast } = useToast();
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");

  // Selected vulnerability for detail modal
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);

  const fetchData = async () => {
    setLoading(true);
    try {
      const data = await vulnerabilitiesApi.getVulnerabilities();
      setVulnerabilities(data);
    } catch {
      addToast("Failed to fetch vulnerability feed", "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleStatusChange = async (id: string, newStatus: Vulnerability["status"]) => {
    try {
      await vulnerabilitiesApi.updateStatus(id, newStatus);
      setVulnerabilities((prev) =>
        prev.map((v) => (v.id === id ? { ...v, status: newStatus } : v))
      );
      if (selectedVuln && selectedVuln.id === id) {
        setSelectedVuln({ ...selectedVuln, status: newStatus });
      }
      addToast(`Vulnerability status updated to ${newStatus.replace("_", " ")} in database`, "success");
    } catch {
      addToast("Failed to update status in database", "error");
    }
  };

  const filtered = vulnerabilities.filter((v) => {
    const matchesSearch =
      v.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      v.target.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (v.cve && v.cve.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesSeverity = severityFilter === "all" || v.severity === severityFilter;
    const matchesStatus = statusFilter === "all" || v.status === statusFilter;
    return matchesSearch && matchesSeverity && matchesStatus;
  });

  const criticalCount = vulnerabilities.filter((v) => v.severity === "CRITICAL").length;
  const highCount = vulnerabilities.filter((v) => v.severity === "HIGH").length;
  const resolvedCount = vulnerabilities.filter((v) => v.status === "RESOLVED").length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#1e293b] pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-gradient-to-b from-[#162032] to-[#070b14] border border-cyber-cyan/40 flex items-center justify-center p-1.5 shadow-glow">
              <img src="/shield-logo.png" alt="Emblem" className="w-full h-full object-contain filter drop-shadow-[0_0_6px_#00d2ff]" />
            </div>
            <h1 className="text-2xl font-bold font-mono tracking-tight text-white flex items-center gap-2">
              CYBER<span className="text-cyber-cyan">SPLOI</span> VULNERABILITY REGISTER
            </h1>
          </div>
          <p className="text-xs font-mono text-slate-400 mt-1 flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-cyber-cyan animate-pulse shadow-[0_0_8px_#00d2ff]"></span>
            Continuous AI-powered vulnerability discovery, CVSS 3.1 scoring, and automated remediation playbooks.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchData}
            disabled={loading}
            className="border-cyber-border"
          >
            <ArrowPathIcon className={`w-4 h-4 mr-1.5 ${loading ? "animate-spin" : ""}`} />
            Sync Scanner
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={() => addToast("Exporting vulnerability CSV ledger...", "info")}
            className="flex items-center gap-1.5"
          >
            <DocumentArrowDownIcon className="w-4 h-4" />
            Export Ledger
          </Button>
        </div>
      </div>

      {/* Metrics Banner */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Critical Vulns"
          value={criticalCount}
          description="Immediate exploit risk"
          accent="danger"
          icon={ShieldExclamationIcon}
        />
        <MetricCard
          title="High Severity"
          value={highCount}
          description="Privilege & auth flaws"
          accent="amber"
          icon={ExclamationTriangleIcon}
        />
        <MetricCard
          title="Remediated Flaws"
          value={resolvedCount}
          description="Retested & patched"
          accent="emerald"
          icon={CheckCircleIcon}
        />
        <MetricCard
          title="Active Surface"
          value={filtered.length}
          description="Monitored in scope"
          accent="teal"
          icon={CommandLineIcon}
        />
      </div>

      {/* Filter and Vulnerabilities Table */}
      <Card className="bg-cyber-surface border-cyber-border">
        <CardHeader className="pb-3 border-b border-cyber-border/40">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <CardTitle className="text-base font-semibold text-cyber-text-primary flex items-center gap-2">
              <span>Discovered Vulnerability Register</span>
              <Badge variant="outline" className="text-xs font-mono border-cyber-accent text-cyber-accent">
                {filtered.length} Findings
              </Badge>
            </CardTitle>

            <div className="flex flex-wrap items-center gap-2.5">
              <div className="relative">
                <MagnifyingGlassIcon className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-cyber-text-muted" />
                <Input
                  placeholder="Search CVE, title, or target..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-9 h-8 text-xs w-52 sm:w-64 bg-cyber-bg border-cyber-border"
                />
              </div>

              <Select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                options={[
                  { label: "All Severities", value: "all" },
                  { label: "Critical (CVSS 9.0+)", value: "CRITICAL" },
                  { label: "High (CVSS 7.0 - 8.9)", value: "HIGH" },
                  { label: "Medium (CVSS 4.0 - 6.9)", value: "MEDIUM" },
                  { label: "Low (CVSS 0.1 - 3.9)", value: "LOW" },
                ]}
                className="h-8 text-xs bg-cyber-bg border-cyber-border w-36"
              />

              <Select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                options={[
                  { label: "All Statuses", value: "all" },
                  { label: "Open", value: "OPEN" },
                  { label: "In Progress", value: "IN_PROGRESS" },
                  { label: "Resolved", value: "RESOLVED" },
                  { label: "False Positive", value: "FALSE_POSITIVE" },
                ]}
                className="h-8 text-xs bg-cyber-bg border-cyber-border w-32"
              />
            </div>
          </div>
        </CardHeader>

        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHead>
                <TableRow className="bg-cyber-bg/60 font-mono text-[11px]">
                  <TableHeaderCell>VULNERABILITY & CVE</TableHeaderCell>
                  <TableHeaderCell>AFFECTED ASSET</TableHeaderCell>
                  <TableHeaderCell>CVSS SCORE</TableHeaderCell>
                  <TableHeaderCell>STATUS</TableHeaderCell>
                  <TableHeaderCell>DISCOVERED</TableHeaderCell>
                  <TableHeaderCell className="text-right">ACTION</TableHeaderCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center py-8 text-cyber-text-secondary">
                      <div className="flex items-center justify-center gap-2">
                        <ArrowPathIcon className="w-4 h-4 animate-spin text-cyber-accent" />
                        <span>Running telemetry scan...</span>
                      </div>
                    </TableCell>
                  </TableRow>
                ) : filtered.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center py-8 text-cyber-text-muted">
                      No vulnerabilities match the selected filter criteria.
                    </TableCell>
                  </TableRow>
                ) : (
                  filtered.map((vuln) => (
                    <TableRow key={vuln.id} className="hover:bg-cyber-bg/40 transition-colors">
                      <TableCell>
                        <div className="font-medium text-cyber-text-primary text-xs">{vuln.title}</div>
                        <div className="flex items-center gap-2 mt-0.5">
                          {vuln.cve && (
                            <span className="text-[10px] font-mono text-cyber-accent bg-cyber-bg px-1.5 py-0.2 rounded border border-cyber-border">
                              {vuln.cve}
                            </span>
                          )}
                          <span className="text-[10px] text-cyber-text-muted font-mono">{vuln.id}</span>
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-cyber-text-secondary">
                        {vuln.target}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            vuln.severity === "CRITICAL"
                              ? "critical"
                              : vuln.severity === "HIGH"
                              ? "high"
                              : vuln.severity === "MEDIUM"
                              ? "medium"
                              : "low"
                          }
                          className="font-mono text-[11px]"
                        >
                          {vuln.cvss.toFixed(1)} {vuln.severity}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            vuln.status === "RESOLVED"
                              ? "success"
                              : vuln.status === "IN_PROGRESS"
                              ? "warning"
                              : vuln.status === "FALSE_POSITIVE"
                              ? "outline"
                              : "destructive"
                          }
                          className="text-[10px]"
                        >
                          {vuln.status.replace("_", " ")}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs text-cyber-text-secondary">
                        {new Date(vuln.createdAt).toLocaleDateString("en-US", {
                          month: "short",
                          day: "numeric",
                        })}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setSelectedVuln(vuln)}
                          className="text-cyber-accent hover:text-white text-xs h-7 px-2"
                        >
                          Inspect →
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Vulnerability Inspector Modal */}
      <Modal
        isOpen={!!selectedVuln}
        onClose={() => setSelectedVuln(null)}
        title={selectedVuln ? `Inspection: ${selectedVuln.id}` : "Vulnerability Inspector"}
      >
        {selectedVuln && (
          <div className="space-y-4 text-sm">
            <div className="flex items-start justify-between gap-2 border-b border-cyber-border pb-3">
              <div>
                <h3 className="font-semibold text-cyber-text-primary text-base">{selectedVuln.title}</h3>
                <p className="text-xs font-mono text-cyber-text-secondary mt-0.5">
                  Target: <span className="text-cyber-accent">{selectedVuln.target}</span>
                </p>
              </div>
              <Badge
                variant={
                  selectedVuln.severity === "CRITICAL"
                    ? "critical"
                    : selectedVuln.severity === "HIGH"
                    ? "high"
                    : "medium"
                }
                className="font-mono text-xs"
              >
                CVSS {selectedVuln.cvss.toFixed(1)}
              </Badge>
            </div>

            <div>
              <h4 className="text-xs font-mono uppercase tracking-wider text-cyber-text-muted mb-1">
                Technical Vulnerability Description
              </h4>
              <p className="text-xs text-cyber-text-secondary bg-cyber-bg p-3 rounded border border-cyber-border leading-relaxed">
                {selectedVuln.description}
              </p>
            </div>

            {selectedVuln.remediation && (
              <div>
                <h4 className="text-xs font-mono uppercase tracking-wider text-emerald-400 mb-1 flex items-center gap-1.5">
                  <CheckCircleIcon className="w-4 h-4" />
                  Recommended Remediation Playbook
                </h4>
                <div className="p-3 rounded bg-emerald-950/20 border border-emerald-500/30 text-xs text-emerald-200 font-mono">
                  {selectedVuln.remediation}
                </div>
              </div>
            )}

            <div className="grid grid-cols-2 gap-3 pt-2 border-t border-cyber-border text-xs">
              <div>
                <span className="text-cyber-text-muted block mb-1">Current State</span>
                <Badge
                  variant={
                    selectedVuln.status === "RESOLVED"
                      ? "success"
                      : selectedVuln.status === "IN_PROGRESS"
                      ? "warning"
                      : "destructive"
                  }
                >
                  {selectedVuln.status.replace("_", " ")}
                </Badge>
              </div>
              <div>
                <span className="text-cyber-text-muted block mb-1">CVE / CWE Mapping</span>
                <span className="font-mono text-cyber-accent">{selectedVuln.cve || "CWE-Internal"}</span>
              </div>
            </div>

            <div className="flex flex-wrap justify-between items-center gap-2 pt-3 border-t border-cyber-border">
              <div className="flex gap-1.5">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleStatusChange(selectedVuln.id, "IN_PROGRESS")}
                  disabled={selectedVuln.status === "IN_PROGRESS"}
                  className="text-xs h-7 border-amber-500/40 text-amber-300 hover:bg-amber-950/40"
                >
                  Mark In Progress
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleStatusChange(selectedVuln.id, "RESOLVED")}
                  disabled={selectedVuln.status === "RESOLVED"}
                  className="text-xs h-7 border-emerald-500/40 text-emerald-300 hover:bg-emerald-950/40"
                >
                  Verify Patched
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleStatusChange(selectedVuln.id, "FALSE_POSITIVE")}
                  disabled={selectedVuln.status === "FALSE_POSITIVE"}
                  className="text-xs h-7 border-cyber-border text-cyber-text-muted"
                >
                  False Positive
                </Button>
              </div>
              <Button
                variant="primary"
                size="sm"
                onClick={() => setSelectedVuln(null)}
                className="text-xs h-7"
              >
                Close
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
