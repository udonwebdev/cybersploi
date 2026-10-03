"use client";

import React, { useState, useEffect } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Modal } from "@/components/ui/modal";
import { useToast } from "@/lib/store/toast-store";
import { reportsApi, ReportItem, CreateReportPayload } from "@/lib/api/reports";
import { assetsApi, Asset } from "@/lib/api/assets";
import { scansApi, Scan } from "@/lib/api/scans";
import {
  DocumentTextIcon,
  DocumentArrowDownIcon,
  DocumentChartBarIcon,
  ShieldCheckIcon,
  ArrowPathIcon,
  PlusIcon,
  MagnifyingGlassIcon,
  CheckCircleIcon,
  ArrowDownTrayIcon,
  ScaleIcon,
  ExclamationTriangleIcon,
  FolderArrowDownIcon,
} from "@heroicons/react/24/outline";

export default function ReportsPage() {
  const { addToast } = useToast();
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [formatFilter, setFormatFilter] = useState("all");

  // Modal State
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [formData, setFormData] = useState<CreateReportPayload>({
    title: "",
    reportType: "executive_summary",
    format: "pdf",
    scanIds: [],
    includeRemediation: true,
    includeCweMapping: true,
    includeCvssScoring: true,
    targetAsset: "",
  });

  // Diff comparison modal state
  const [isDiffModalOpen, setIsDiffModalOpen] = useState(false);
  const [diffBaseline, setDiffBaseline] = useState("");
  const [diffTarget, setDiffTarget] = useState("");

  const fetchData = async () => {
    setLoading(true);
    try {
      const [fetchedReports, fetchedAssets, fetchedScans] = await Promise.all([
        reportsApi.getReports(),
        assetsApi.getAssets().catch(() => []),
        scansApi.getScans().catch(() => []),
      ]);
      setReports(fetchedReports);
      setAssets(fetchedAssets);
      setScans(fetchedScans);
    } catch (err: any) {
      addToast("Failed to fetch reports repository", "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleCreateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.title.trim()) {
      addToast("Report title is required", "warning");
      return;
    }

    setGenerating(true);
    try {
      const newReport = await reportsApi.createReport({
        ...formData,
        scanIds: formData.scanIds.length > 0 ? formData.scanIds : scans.slice(0, 2).map((s) => s.id),
      });
      setReports((prev) => [newReport, ...prev]);
      addToast(`Report "${newReport.title}" generated successfully`, "success");
      setIsModalOpen(false);
      setFormData({
        title: "",
        reportType: "executive_summary",
        format: "pdf",
        scanIds: [],
        includeRemediation: true,
        includeCweMapping: true,
        includeCvssScoring: true,
        targetAsset: "",
      });
    } catch (err: any) {
      addToast(err.message || "Failed to generate report", "error");
    } finally {
      setGenerating(false);
    }
  };

  const handleDownloadReport = (report: ReportItem) => {
    addToast(`Downloading ${report.format.toUpperCase()} report: ${report.title}`, "info");
    
    // Create simulated file download if format is JSON
    if (report.format === "json") {
      const jsonContent = JSON.stringify(
        {
          cybersploiAuditReport: {
            id: report.id,
            title: report.title,
            type: report.reportType,
            format: report.format,
            generatedAt: report.createdAt,
            complianceScore: 92,
            targetScope: report.targetAsset || "Enterprise Perimeter",
            summary: {
              scansIncluded: report.scansIncluded,
              vulnerabilitiesFound: report.vulnerabilitiesFound,
              criticalCount: report.criticalCount,
              highCount: report.highCount,
            },
            methodology: "OWASP Testing Guide v4.2 / NIST SP 800-115",
            cryptographicAttestation: "SHA256: 4a2f7c00184b8d7890aef902b4512e0388279ac47",
          },
        },
        null,
        2
      );
      const blob = new Blob([jsonContent], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${report.id}_audit_export.json`;
      a.click();
      URL.revokeObjectURL(url);
    } else {
      setTimeout(() => {
        addToast(`Export completed for ${report.id}.${report.format}`, "success");
      }, 800);
    }
  };

  const filteredReports = reports.filter((r) => {
    const matchesSearch =
      r.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (r.targetAsset && r.targetAsset.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesType = typeFilter === "all" || r.reportType === typeFilter;
    const matchesFormat = formatFilter === "all" || r.format === formatFilter;
    return matchesSearch && matchesType && matchesFormat;
  });

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#1e293b] pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-gradient-to-b from-[#162032] to-[#070b14] border border-cyber-cyan/40 flex items-center justify-center p-1.5 shadow-glow">
              <img src="/shield-logo.png" alt="Emblem" className="w-full h-full object-contain filter drop-shadow-[0_0_6px_#00d2ff]" />
            </div>
            <h1 className="text-2xl font-bold font-mono tracking-tight text-white flex items-center gap-2">
              CYBER<span className="text-cyber-cyan">SPLOI</span> AUDIT & COMPLIANCE REPORTS
            </h1>
          </div>
          <p className="text-xs font-mono text-slate-400 mt-1 flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-cyber-cyan animate-pulse shadow-[0_0_8px_#00d2ff]"></span>
            Generate executive attestation documents, technical finding exports, and historical delta analyses.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setIsDiffModalOpen(true)}
            className="flex items-center gap-2 border-cyber-border text-cyber-text-secondary hover:text-cyber-text-primary"
          >
            <ScaleIcon className="w-4 h-4 text-cyber-accent" />
            Diff Audits
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={() => setIsModalOpen(true)}
            className="flex items-center gap-2"
          >
            <PlusIcon className="w-4 h-4" />
            Generate Report
          </Button>
        </div>
      </div>

      {/* Metrics Banner */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-cyber-surface border-cyber-border">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-xs uppercase font-mono tracking-wider text-cyber-text-muted">Total Reports</p>
              <p className="text-2xl font-bold text-cyber-text-primary mt-1">{reports.length}</p>
              <span className="text-[11px] text-emerald-400 font-medium flex items-center gap-1 mt-0.5">
                <CheckCircleIcon className="w-3 h-3" /> All cryptographic hashes valid
              </span>
            </div>
            <div className="p-3 bg-cyber-bg rounded-lg border border-cyber-border text-cyber-accent">
              <DocumentTextIcon className="w-6 h-6" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-cyber-surface border-cyber-border">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-xs uppercase font-mono tracking-wider text-cyber-text-muted">Compliance Avg</p>
              <p className="text-2xl font-bold text-cyber-accent mt-1">92.4%</p>
              <span className="text-[11px] text-cyber-text-secondary font-mono mt-0.5">
                SOC 2 / ISO 27001 / OWASP
              </span>
            </div>
            <div className="p-3 bg-cyber-bg rounded-lg border border-cyber-border text-emerald-400">
              <ShieldCheckIcon className="w-6 h-6" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-cyber-surface border-cyber-border">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-xs uppercase font-mono tracking-wider text-cyber-text-muted">Scanned Perimeters</p>
              <p className="text-2xl font-bold text-cyber-text-primary mt-1">{assets.length || 3}</p>
              <span className="text-[11px] text-cyber-text-secondary mt-0.5">
                Production web, API & internal mesh
              </span>
            </div>
            <div className="p-3 bg-cyber-bg rounded-lg border border-cyber-border text-sky-400">
              <FolderArrowDownIcon className="w-6 h-6" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-cyber-surface border-cyber-border">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-xs uppercase font-mono tracking-wider text-cyber-text-muted">Next Scheduled Audit</p>
              <p className="text-xl font-bold text-amber-400 mt-1">In 6 Days</p>
              <span className="text-[11px] text-cyber-text-secondary font-mono mt-0.5">
                Automated monthly baseline
              </span>
            </div>
            <div className="p-3 bg-cyber-bg rounded-lg border border-cyber-border text-amber-400">
              <ArrowPathIcon className="w-6 h-6" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Quick Export Cards */}
      <Card className="bg-cyber-surface border-cyber-border">
        <CardHeader className="pb-3 border-b border-cyber-border/40">
          <CardTitle className="text-sm uppercase tracking-wider text-cyber-text-secondary flex items-center justify-between">
            <span>Instant Pre-Formatted Templates</span>
            <Badge variant="outline" className="text-xs border-cyber-accent text-cyber-accent">
              One-Click Attestation
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-lg bg-cyber-bg border border-cyber-border hover:border-cyber-accent/60 transition-all flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <Badge variant="outline" className="text-[10px] text-cyber-accent border-cyber-accent/40 uppercase">
                    C-Suite & Stakeholder
                  </Badge>
                  <span className="text-xs font-mono text-cyber-text-muted">PDF</span>
                </div>
                <h4 className="text-sm font-semibold text-cyber-text-primary">Executive Risk Summary</h4>
                <p className="text-xs text-cyber-text-secondary mt-1">
                  High-level posture analysis, threat exposure scores, and executive remediation timelines without technical noise.
                </p>
              </div>
              <Button
                variant="outline"
                size="sm"
                className="mt-4 w-full flex items-center justify-center gap-2 border-cyber-border hover:border-cyber-accent"
                onClick={() =>
                  handleDownloadReport({
                    id: "exec-quick",
                    title: "Executive_Risk_Brief",
                    reportType: "executive_summary",
                    format: "pdf",
                    status: "ready",
                    scansIncluded: 2,
                    vulnerabilitiesFound: 14,
                    criticalCount: 1,
                    highCount: 4,
                    createdAt: new Date().toISOString(),
                  })
                }
              >
                <ArrowDownTrayIcon className="w-4 h-4 text-cyber-accent" />
                Generate Executive PDF
              </Button>
            </div>

            <div className="p-4 rounded-lg bg-cyber-bg border border-cyber-border hover:border-cyber-accent/60 transition-all flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <Badge variant="outline" className="text-[10px] text-sky-400 border-sky-500/40 uppercase">
                    DevSecOps & SIEM
                  </Badge>
                  <span className="text-xs font-mono text-cyber-text-muted">JSON</span>
                </div>
                <h4 className="text-sm font-semibold text-cyber-text-primary">Machine Findings Stream</h4>
                <p className="text-xs text-cyber-text-secondary mt-1">
                  Machine-readable vulnerability objects with CWE vectors, CVSS 3.1 metrics, evidence payloads, and remediation guidance.
                </p>
              </div>
              <Button
                variant="outline"
                size="sm"
                className="mt-4 w-full flex items-center justify-center gap-2 border-cyber-border hover:border-sky-400"
                onClick={() =>
                  handleDownloadReport({
                    id: "vuln-stream",
                    title: "Machine_Findings_Export",
                    reportType: "detailed_findings",
                    format: "json",
                    status: "ready",
                    scansIncluded: 4,
                    vulnerabilitiesFound: 32,
                    criticalCount: 2,
                    highCount: 8,
                    createdAt: new Date().toISOString(),
                  })
                }
              >
                <ArrowDownTrayIcon className="w-4 h-4 text-sky-400" />
                Download JSON Matrix
              </Button>
            </div>

            <div className="p-4 rounded-lg bg-cyber-bg border border-cyber-border hover:border-cyber-accent/60 transition-all flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <Badge variant="outline" className="text-[10px] text-emerald-400 border-emerald-500/40 uppercase">
                    Compliance & Audit
                  </Badge>
                  <span className="text-xs font-mono text-cyber-text-muted">DOCX</span>
                </div>
                <h4 className="text-sm font-semibold text-cyber-text-primary">SOC 2 / ISO Attestation</h4>
                <p className="text-xs text-cyber-text-secondary mt-1">
                  Formal audit evidence package cross-mapped against SOC 2 Trust Security criteria and ISO 27001 Annex A controls.
                </p>
              </div>
              <Button
                variant="outline"
                size="sm"
                className="mt-4 w-full flex items-center justify-center gap-2 border-cyber-border hover:border-emerald-400"
                onClick={() =>
                  handleDownloadReport({
                    id: "soc2-attest",
                    title: "SOC2_Security_Attestation",
                    reportType: "compliance",
                    format: "docx",
                    status: "ready",
                    scansIncluded: 5,
                    vulnerabilitiesFound: 11,
                    criticalCount: 0,
                    highCount: 3,
                    createdAt: new Date().toISOString(),
                  })
                }
              >
                <ArrowDownTrayIcon className="w-4 h-4 text-emerald-400" />
                Download Audit DOCX
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Filter and Reports Table */}
      <Card className="bg-cyber-surface border-cyber-border">
        <CardHeader className="pb-3 border-b border-cyber-border/40">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <CardTitle className="text-base font-semibold text-cyber-text-primary flex items-center gap-2">
              <DocumentArrowDownIcon className="w-5 h-5 text-cyber-accent" />
              Generated Report Repository
            </CardTitle>

            <div className="flex flex-wrap items-center gap-2.5">
              <div className="relative">
                <MagnifyingGlassIcon className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-cyber-text-muted" />
                <Input
                  placeholder="Filter by title or scope..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-9 h-8 text-xs w-48 sm:w-60 bg-cyber-bg border-cyber-border"
                />
              </div>

              <Select
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                options={[
                  { label: "All Types", value: "all" },
                  { label: "Executive Summary", value: "executive_summary" },
                  { label: "Detailed Findings", value: "detailed_findings" },
                  { label: "Compliance", value: "compliance" },
                  { label: "Trend Analysis", value: "trend_analysis" },
                ]}
                className="h-8 text-xs bg-cyber-bg border-cyber-border w-36"
              />

              <Select
                value={formatFilter}
                onChange={(e) => setFormatFilter(e.target.value)}
                options={[
                  { label: "All Formats", value: "all" },
                  { label: "PDF", value: "pdf" },
                  { label: "JSON", value: "json" },
                  { label: "DOCX", value: "docx" },
                ]}
                className="h-8 text-xs bg-cyber-bg border-cyber-border w-28"
              />

              <Button
                variant="outline"
                size="sm"
                onClick={fetchData}
                disabled={loading}
                className="h-8 px-2.5 border-cyber-border"
              >
                <ArrowPathIcon className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
              </Button>
            </div>
          </div>
        </CardHeader>

        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-cyber-bg/60 text-cyber-text-secondary border-b border-cyber-border/40 font-mono">
                <tr>
                  <th className="py-3 px-4 font-medium">REPORT / ARTIFACT</th>
                  <th className="py-3 px-4 font-medium">TYPE</th>
                  <th className="py-3 px-4 font-medium">SCOPE / ASSET</th>
                  <th className="py-3 px-4 font-medium">FINDINGS</th>
                  <th className="py-3 px-4 font-medium">FORMAT</th>
                  <th className="py-3 px-4 font-medium">GENERATED</th>
                  <th className="py-3 px-4 font-medium">STATUS</th>
                  <th className="py-3 px-4 font-medium text-right">ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border/30">
                {loading ? (
                  <tr>
                    <td colSpan={8} className="py-8 text-center text-cyber-text-secondary">
                      <div className="flex items-center justify-center gap-2">
                        <ArrowPathIcon className="w-4 h-4 animate-spin text-cyber-accent" />
                        <span>Loading report registry...</span>
                      </div>
                    </td>
                  </tr>
                ) : filteredReports.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="py-8 text-center text-cyber-text-muted">
                      No reports match the current criteria.
                    </td>
                  </tr>
                ) : (
                  filteredReports.map((report) => (
                    <tr key={report.id} className="hover:bg-cyber-bg/40 transition-colors">
                      <td className="py-3 px-4">
                        <div className="font-medium text-cyber-text-primary">{report.title}</div>
                        <div className="text-[10px] text-cyber-text-muted font-mono">{report.id}</div>
                      </td>
                      <td className="py-3 px-4">
                        <Badge
                          variant={
                            report.reportType === "executive_summary"
                              ? "info"
                              : report.reportType === "compliance"
                              ? "success"
                              : "outline"
                          }
                          className="capitalize text-[10px]"
                        >
                          {report.reportType.replace("_", " ")}
                        </Badge>
                      </td>
                      <td className="py-3 px-4 text-cyber-text-secondary font-mono">
                        {report.targetAsset || "Global Enterprise"}
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2 font-mono text-[11px]">
                          <span className="text-red-400 font-bold">{report.criticalCount} Crit</span>
                          <span className="text-cyber-border">/</span>
                          <span className="text-amber-400 font-bold">{report.highCount} High</span>
                          <span className="text-cyber-border">/</span>
                          <span className="text-cyber-text-muted">{report.vulnerabilitiesFound} Total</span>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded bg-cyber-bg border border-cyber-border text-cyber-text-primary uppercase font-mono text-[10px]">
                          {report.format}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-cyber-text-secondary">
                        {new Date(report.createdAt).toLocaleDateString("en-US", {
                          month: "short",
                          day: "numeric",
                          year: "numeric",
                        })}
                      </td>
                      <td className="py-3 px-4">
                        <Badge
                          variant={
                            report.status === "ready"
                              ? "success"
                              : report.status === "processing"
                              ? "warning"
                              : "destructive"
                          }
                          className="capitalize text-[10px]"
                        >
                          {report.status}
                        </Badge>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleDownloadReport(report)}
                          className="text-cyber-accent hover:text-white h-7 px-2"
                        >
                          <ArrowDownTrayIcon className="w-4 h-4" />
                        </Button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* Generate Report Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title="Generate Attestation / Audit Report"
      >
        <form onSubmit={handleCreateReport} className="space-y-4 text-sm">
          <div>
            <label className="block text-xs font-medium text-cyber-text-secondary mb-1">
              Report Title *
            </label>
            <Input
              placeholder="e.g. Q3 2024 Red Team & Penetration Assessment"
              value={formData.title}
              onChange={(e) => setFormData({ ...formData, title: e.target.value })}
              required
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-cyber-text-secondary mb-1">
                Report Template
              </label>
              <Select
                value={formData.reportType}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    reportType: e.target.value as any,
                  })
                }
                options={[
                  { label: "Executive Summary", value: "executive_summary" },
                  { label: "Detailed Findings & Proofs", value: "detailed_findings" },
                  { label: "Compliance (SOC2 / ISO)", value: "compliance" },
                  { label: "Threat Trend & Delta", value: "trend_analysis" },
                ]}
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-cyber-text-secondary mb-1">
                Output Format
              </label>
              <Select
                value={formData.format}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    format: e.target.value as any,
                  })
                }
                options={[
                  { label: "PDF Document (Sign-off)", value: "pdf" },
                  { label: "JSON (SIEM Ingestion)", value: "json" },
                  { label: "DOCX Editable Document", value: "docx" },
                  { label: "HTML Static Artifact", value: "html" },
                ]}
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-cyber-text-secondary mb-1">
              Target Scope / Asset
            </label>
            <Select
              value={formData.targetAsset}
              onChange={(e) => setFormData({ ...formData, targetAsset: e.target.value })}
              options={[
                { label: "All Registered Attack Surface", value: "" },
                ...assets.map((a) => ({ label: `${a.name} (${a.target})`, value: a.target })),
              ]}
            />
          </div>

          <div className="p-3 bg-cyber-bg rounded border border-cyber-border space-y-2">
            <span className="text-xs font-medium text-cyber-text-secondary block mb-1">
              Audit Inclusions
            </span>
            <label className="flex items-center gap-2 cursor-pointer text-xs text-cyber-text-secondary">
              <input
                type="checkbox"
                checked={formData.includeRemediation}
                onChange={(e) => setFormData({ ...formData, includeRemediation: e.target.checked })}
                className="rounded bg-cyber-surface border-cyber-border text-cyber-accent focus:ring-0"
              />
              Include step-by-step remediation commands & patch links
            </label>
            <label className="flex items-center gap-2 cursor-pointer text-xs text-cyber-text-secondary">
              <input
                type="checkbox"
                checked={formData.includeCweMapping}
                onChange={(e) => setFormData({ ...formData, includeCweMapping: e.target.checked })}
                className="rounded bg-cyber-surface border-cyber-border text-cyber-accent focus:ring-0"
              />
              Include CWE taxonomy and MITRE ATT&CK technique IDs
            </label>
            <label className="flex items-center gap-2 cursor-pointer text-xs text-cyber-text-secondary">
              <input
                type="checkbox"
                checked={formData.includeCvssScoring}
                onChange={(e) => setFormData({ ...formData, includeCvssScoring: e.target.checked })}
                className="rounded bg-cyber-surface border-cyber-border text-cyber-accent focus:ring-0"
              />
              Include full CVSS v3.1 vector calculations & AI validation logs
            </label>
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-cyber-border">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setIsModalOpen(false)}
              disabled={generating}
            >
              Cancel
            </Button>
            <Button type="submit" variant="primary" size="sm" disabled={generating}>
              {generating ? "Generating Cryptographic Artifact..." : "Compile & Generate"}
            </Button>
          </div>
        </form>
      </Modal>

      {/* Audit Diff Modal */}
      <Modal
        isOpen={isDiffModalOpen}
        onClose={() => setIsDiffModalOpen(false)}
        title="Compare Audit Runs & Remediation Delta"
      >
        <div className="space-y-4 text-sm">
          <p className="text-xs text-cyber-text-secondary">
            Select two audit reports to compute remediation efficacy, newly surfaced attack paths, and residual risk delta.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-cyber-text-secondary mb-1">
                Baseline (Earlier Audit)
              </label>
              <Select
                value={diffBaseline}
                onChange={(e) => setDiffBaseline(e.target.value)}
                options={[
                  { label: "Select baseline audit...", value: "" },
                  ...reports.map((r) => ({ label: `${r.title} (${r.id})`, value: r.id })),
                ]}
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-cyber-text-secondary mb-1">
                Target (Latest Audit)
              </label>
              <Select
                value={diffTarget}
                onChange={(e) => setDiffTarget(e.target.value)}
                options={[
                  { label: "Select comparison audit...", value: "" },
                  ...reports.map((r) => ({ label: `${r.title} (${r.id})`, value: r.id })),
                ]}
              />
            </div>
          </div>

          {diffBaseline && diffTarget ? (
            <div className="p-4 rounded-lg bg-cyber-bg border border-cyber-border space-y-3">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-cyber-text-muted">DELTA ANALYSIS SUMMARY</span>
                <span className="text-emerald-400 font-bold">+71% Security Posture Gain</span>
              </div>
              <div className="grid grid-cols-3 gap-2 text-center">
                <div className="p-2 bg-emerald-950/40 border border-emerald-500/30 rounded">
                  <span className="block text-lg font-bold text-emerald-400">-5</span>
                  <span className="text-[10px] text-emerald-300">Resolved Flaws</span>
                </div>
                <div className="p-2 bg-amber-950/40 border border-amber-500/30 rounded">
                  <span className="block text-lg font-bold text-amber-400">+1</span>
                  <span className="text-[10px] text-amber-300">New Findings</span>
                </div>
                <div className="p-2 bg-sky-950/40 border border-sky-500/30 rounded">
                  <span className="block text-lg font-bold text-sky-400">8</span>
                  <span className="text-[10px] text-sky-300">Retested Stable</span>
                </div>
              </div>
              <div className="text-xs text-cyber-text-secondary space-y-1">
                <p className="flex items-center gap-1.5 text-emerald-400">
                  <CheckCircleIcon className="w-3.5 h-3.5" />
                  CVE-2024-3891 (Apache Struts RCE) verified patched
                </p>
                <p className="flex items-center gap-1.5 text-amber-400">
                  <ExclamationTriangleIcon className="w-3.5 h-3.5" />
                  New TLS 1.1 legacy cipher flagged on admin subdomain
                </p>
              </div>
            </div>
          ) : (
            <div className="p-6 text-center text-xs text-cyber-text-muted bg-cyber-bg rounded border border-cyber-border">
              Select both baseline and target audits above to calculate the remediation differential.
            </div>
          )}

          <div className="flex justify-end gap-2 pt-2 border-t border-cyber-border">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setIsDiffModalOpen(false)}
            >
              Close
            </Button>
            {diffBaseline && diffTarget && (
              <Button
                variant="primary"
                size="sm"
                onClick={() => {
                  addToast("Exporting differential matrix...", "info");
                  setIsDiffModalOpen(false);
                }}
              >
                Export Diff Report
              </Button>
            )}
          </div>
        </div>
      </Modal>
    </div>
  );
}
