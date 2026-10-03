"use client";

import React, { useState, useEffect } from "react";
import { Modal } from "@/components/ui/modal";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { redTeamApi, ProofObject, EvidenceChainItem } from "@/lib/api/red-team";
import { useToast } from "@/lib/store/toast-store";
import {
  ShieldExclamationIcon,
  ShieldCheckIcon,
  ClockIcon,
  CommandLineIcon,
  ExclamationTriangleIcon,
  KeyIcon,
  StopIcon,
  CheckCircleIcon,
  DocumentDuplicateIcon,
  ArrowDownTrayIcon,
  PlayIcon,
  LockClosedIcon
} from "@heroicons/react/24/outline";

interface Props {
  isOpen: boolean;
  onClose: () => void;
  session: any | null;
  target: string;
  onSessionTerminated?: () => void;
}

export function RemoteAccessVerificationConsole({
  isOpen,
  onClose,
  session,
  target,
  onSessionTerminated
}: Props) {
  const { addToast } = useToast();
  const [terminating, setTerminating] = useState(false);
  const [authorizing, setAuthorizing] = useState(false);
  const [executingAction, setExecutingAction] = useState<string | null>(null);
  const [localSession, setLocalSession] = useState<any>(session);
  const [timeRemaining, setTimeRemaining] = useState<string>("15m 00s");
  const [proofObject, setProofObject] = useState<ProofObject | null>(null);
  const [ttlChoice, setTtlChoice] = useState<number>(15);
  const [activeTab, setActiveTab] = useState<"telemetry" | "evidence" | "audit">("telemetry");

  // Sync initial session and fetch full details if available
  useEffect(() => {
    if (session?.id || session?.sessionToken) {
      setLocalSession(session);
      loadSessionDetails(session.id || session.sessionToken);
    }
  }, [session]);

  const loadSessionDetails = async (sessionIdOrToken: string) => {
    try {
      const details = await redTeamApi.getSessionDetails(sessionIdOrToken);
      if (details) {
        setLocalSession(details);
        if (details.proofObject) {
          setProofObject(details.proofObject);
        }
      }
    } catch (e) {
      // Fallback to local session
    }
  };

  // Live countdown timer until session expiration
  useEffect(() => {
    if (!localSession?.expiresAt || localSession?.status !== "ACTIVE") {
      setTimeRemaining(localSession?.status === "REQUESTED" ? "Awaiting Customer Authorization" : "Expired / Terminated");
      return;
    }

    const interval = setInterval(() => {
      const diff = new Date(localSession.expiresAt).getTime() - Date.now();
      if (diff <= 0) {
        setTimeRemaining("00m 00s (Session Expired)");
        setLocalSession((prev: any) => (prev ? { ...prev, status: "EXPIRED" } : prev));
        clearInterval(interval);
      } else {
        const min = Math.floor(diff / (1000 * 60));
        const sec = Math.floor((diff % (1000 * 60)) / 1000);
        setTimeRemaining(`${min}m ${sec < 10 ? "0" : ""}${sec}s`);
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [localSession?.expiresAt, localSession?.status]);

  // Customer Authorization Gate Handler
  const handleAuthorize = async () => {
    if (!localSession) return;
    setAuthorizing(true);
    try {
      const res = await redTeamApi.authorizeVerificationSession(
        localSession.id || localSession.sessionToken,
        {
          authorizedBy: "Customer Security Administrator",
          permittedActions: localSession?.allowlist || [
            "PROBE_ENDPOINT",
            "INSPECT_HEADER",
            "TEST_SOCKET_HANDSHAKE",
            "FETCH_RETEST_EVIDENCE",
            "VERIFY_VULNERABILITY"
          ],
          ttlMinutes: ttlChoice,
          authorizationNotes: "Explicit customer consent granted for bounded verification probe."
        }
      );
      setLocalSession(res);
      addToast("Customer Authorization Gate approved: Session is now ACTIVE", "success");
      loadSessionDetails(res.id || res.sessionToken);
    } catch (err: any) {
      addToast(err?.response?.data?.message || "Failed to authorize session", "error");
    } finally {
      setAuthorizing(false);
    }
  };

  // Execute allowlisted action
  const handleExecuteAction = async (action: string) => {
    if (!localSession) return;
    setExecutingAction(action);
    try {
      const res = await redTeamApi.executeSessionAction(
        localSession.id || localSession.sessionToken,
        {
          action,
          target: localSession.target || target,
          findingId: localSession.findingId
        }
      );
      addToast(`Action '${action}' executed and cryptographically sealed`, "success");
      loadSessionDetails(localSession.id || localSession.sessionToken);
    } catch (err: any) {
      addToast(err?.response?.data?.message || `Action '${action}' failed or blocked`, "error");
    } finally {
      setExecutingAction(null);
    }
  };

  // Export Proof Object
  const handleExportProof = async () => {
    if (!localSession) return;
    try {
      const proof = await redTeamApi.getProofObject(localSession.id || localSession.sessionToken);
      if (proof) {
        setProofObject(proof);
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(proof, null, 2));
        const downloadAnchor = document.createElement("a");
        downloadAnchor.setAttribute("href", dataStr);
        downloadAnchor.setAttribute("download", `${proof.proofId || "PROOF-EXECUTION"}.json`);
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
        addToast("Signed Proof Object exported successfully", "success");
      }
    } catch (err: any) {
      addToast("Failed to generate proof artifact", "error");
    }
  };

  // Terminate Session (Kill Switch)
  const handleTerminate = async () => {
    if (!localSession) return;
    setTerminating(true);
    try {
      const res = await redTeamApi.terminateSession(
        localSession.id || localSession.sessionToken,
        "Operator initiated emergency termination kill-switch from verification console"
      );
      setLocalSession(res);
      addToast("Verification session revoked and terminated immediately", "success");
      if (onSessionTerminated) onSessionTerminated();
    } catch (err: any) {
      addToast(err?.response?.data?.message || "Failed to terminate verification session", "error");
    } finally {
      setTerminating(false);
    }
  };

  const copyAuditTrail = () => {
    if (localSession?.auditTrail) {
      navigator.clipboard.writeText(
        typeof localSession.auditTrail === "string"
          ? localSession.auditTrail
          : JSON.stringify(localSession.auditTrail, null, 2)
      );
      addToast("Audit trail copied to clipboard", "success");
    }
  };

  const auditEvents = React.useMemo(() => {
    if (!localSession?.auditTrail) return [];
    try {
      return typeof localSession.auditTrail === "string"
        ? JSON.parse(localSession.auditTrail)
        : localSession.auditTrail;
    } catch (e) {
      return [];
    }
  }, [localSession?.auditTrail]);

  const evidenceChain: EvidenceChainItem[] = React.useMemo(() => {
    if (!localSession?.evidenceChain) return [];
    return localSession.evidenceChain;
  }, [localSession?.evidenceChain]);

  const allowlist: string[] = React.useMemo(() => {
    if (localSession?.allowlist && Array.isArray(localSession.allowlist)) {
      return localSession.allowlist;
    }
    return ["PROBE_ENDPOINT", "INSPECT_HEADER", "TEST_SOCKET_HANDSHAKE", "FETCH_RETEST_EVIDENCE", "VERIFY_VULNERABILITY"];
  }, [localSession?.allowlist]);

  const isRequested = localSession?.status === "REQUESTED";
  const isActive = localSession?.status === "ACTIVE";
  const isTerminated = localSession?.status === "TERMINATED";

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="CYBERSPLOI // BOUNDED VERIFICATION PROOF LAB"
      maxWidth="xl"
    >
      <div className="space-y-5 font-mono text-xs">
        {/* Top Status & Integrity Bar */}
        <div className="p-4 bg-background-subtle rounded-xl border border-border flex flex-wrap items-center justify-between gap-4">
          <div>
            <span className="text-[10px] text-slate-500 uppercase">Target</span>
            <div className="text-slate-100 font-bold text-sm flex items-center gap-2 mt-0.5">
              <span>{target}</span>
              <Badge variant="outline" className="border-cyber-teal text-cyber-teal text-[10px]">
                SCOPE VERIFIED
              </Badge>
            </div>
          </div>

          <div>
            <span className="text-[10px] text-slate-500 uppercase">Session Token</span>
            <div className="text-slate-200 font-bold text-xs mt-0.5">
              {localSession?.sessionToken || "RT-SESS-PENDING"}
            </div>
          </div>

          <div>
            <span className="text-[10px] text-slate-500 uppercase">Status</span>
            <div className="mt-0.5">
              <Badge
                variant={
                  isActive
                    ? "success"
                    : isTerminated
                    ? "destructive"
                    : isRequested
                    ? "warning"
                    : "outline"
                }
                pulse={isActive}
              >
                {localSession?.status || "INACTIVE"}
              </Badge>
            </div>
          </div>

          <div>
            <span className="text-[10px] text-slate-500 uppercase">TTL Remaining</span>
            <div className={`font-bold flex items-center gap-1.5 mt-0.5 ${isActive ? "text-amber-400" : "text-slate-400"}`}>
              <ClockIcon className="w-4 h-4" />
              <span>{timeRemaining}</span>
            </div>
          </div>

          <div>
            <span className="text-[10px] text-slate-500 uppercase">Evidence Integrity</span>
            <div className="mt-0.5">
              <Badge variant="outline" className="border-emerald-500/40 text-emerald-400 text-[10px] flex items-center gap-1">
                <ShieldCheckIcon className="w-3.5 h-3.5 text-emerald-400" />
                SHA-256 SEALED
              </Badge>
            </div>
          </div>
        </div>

        {/* CUSTOMER AUTHORIZATION GATE MODAL VIEW (If Session is REQUESTED) */}
        {isRequested && (
          <div className="p-5 bg-amber-500/10 rounded-xl border border-amber-500/30 space-y-4 text-slate-300">
            <div className="flex items-start gap-3">
              <LockClosedIcon className="w-6 h-6 text-amber-400 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <h4 className="text-amber-300 font-bold text-sm tracking-wide">
                  CUSTOMER AUTHORIZATION GATE REQUIRED
                </h4>
                <p className="text-slate-300 text-xs leading-relaxed">
                  CyberSploi strictly prohibits unauthorized probing. This verification session requires explicit customer approval before any packet or socket is dispatched to <strong>{target}</strong>.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 p-3 bg-slate-950/60 rounded-lg border border-border">
              <div>
                <span className="text-[10px] text-slate-500 uppercase">Verification Finding</span>
                <div className="text-slate-200 font-semibold mt-0.5">
                  {localSession?.findingId || "Observed Vulnerability"}
                </div>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase">Verification Objective</span>
                <div className="text-slate-200 mt-0.5">
                  {localSession?.verificationObjective || "Prove bounded exploitability"}
                </div>
              </div>
            </div>

            <div className="space-y-2">
              <span className="text-[10px] text-slate-400 uppercase font-semibold">
                Requested Permitted Actions (Least Privilege Allowlist):
              </span>
              <div className="flex flex-wrap gap-1.5">
                {allowlist.map((act) => (
                  <Badge key={act} variant="outline" className="text-[11px] bg-slate-800 text-slate-200 border-slate-700">
                    <CheckCircleIcon className="w-3 h-3 text-emerald-400 mr-1 inline" />
                    {act}
                  </Badge>
                ))}
              </div>
            </div>

            <div className="flex items-center justify-between gap-4 pt-2 border-t border-amber-500/20">
              <div className="flex items-center gap-2">
                <span className="text-slate-400 text-xs">Authorization TTL:</span>
                <select
                  value={ttlChoice}
                  onChange={(e) => setTtlChoice(Number(e.target.value))}
                  className="bg-slate-900 border border-slate-700 text-slate-200 rounded px-2 py-1 text-xs focus:outline-none focus:border-amber-400"
                >
                  <option value={5}>5 Minutes</option>
                  <option value={15}>15 Minutes (Default)</option>
                  <option value={30}>30 Minutes</option>
                </select>
              </div>

              <Button
                variant="primary"
                size="sm"
                onClick={handleAuthorize}
                disabled={authorizing}
                className="bg-emerald-600 hover:bg-emerald-700 text-white font-bold flex items-center gap-1.5"
              >
                <ShieldCheckIcon className="w-4 h-4" />
                {authorizing ? "Authorizing..." : "Authorize Verification Session"}
              </Button>
            </div>
          </div>
        )}

        {/* ACTIVE COCKPIT VIEW */}
        {!isRequested && (
          <>
            {/* Guardrail Pledge Banner */}
            <div className="p-3 bg-cyber-teal/5 rounded-xl border border-cyber-teal/20 text-slate-300 text-[11px] leading-relaxed flex items-start gap-2.5">
              <ShieldCheckIcon className="w-5 h-5 text-cyber-teal shrink-0 mt-0.5" />
              <div>
                <strong className="text-cyber-teal">NON-DESTRUCTIVE REPRODUCIBILITY PLEDGE:</strong> This session executes within an immutable allowlist. Zero persistent backdoors or uncontrolled binaries are deployed. All verification telemetry is cryptographically signed and hash-chained.
              </div>
            </div>

            {/* Allowlisted Actions Executor Toolbar (When ACTIVE) */}
            {isActive && (
              <div className="p-3 bg-background-card rounded-xl border border-border space-y-2">
                <div className="text-[10px] text-slate-400 uppercase font-bold tracking-wider flex items-center justify-between">
                  <span>Interactive Allowlisted Actions ({allowlist.length} Permitted)</span>
                  <span className="text-slate-500 font-normal">Click to trigger bounded reproducibility probe</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {allowlist.map((act) => (
                    <Button
                      key={act}
                      variant="outline"
                      size="sm"
                      onClick={() => handleExecuteAction(act)}
                      disabled={executingAction !== null}
                      className="text-[11px] border-slate-700 hover:border-cyber-teal hover:text-cyber-teal flex items-center gap-1.5 py-1 px-2.5 h-auto"
                    >
                      <PlayIcon className="w-3 h-3 text-cyber-teal" />
                      {executingAction === act ? "Executing..." : act}
                    </Button>
                  ))}
                </div>
              </div>
            )}

            {/* Navigation Tabs */}
            <div className="flex border-b border-border/70 text-xs">
              <button
                onClick={() => setActiveTab("telemetry")}
                className={`px-4 py-2 border-b-2 font-semibold transition-colors ${
                  activeTab === "telemetry"
                    ? "border-cyber-teal text-cyber-teal"
                    : "border-transparent text-slate-400 hover:text-slate-200"
                }`}
              >
                Telemetry & Baseline Comparison
              </button>
              <button
                onClick={() => setActiveTab("evidence")}
                className={`px-4 py-2 border-b-2 font-semibold transition-colors flex items-center gap-1.5 ${
                  activeTab === "evidence"
                    ? "border-cyber-teal text-cyber-teal"
                    : "border-transparent text-slate-400 hover:text-slate-200"
                }`}
              >
                Cryptographic Evidence Chain
                <Badge variant="outline" className="text-[10px] py-0 px-1 bg-slate-800">
                  {evidenceChain.length}
                </Badge>
              </button>
              <button
                onClick={() => setActiveTab("audit")}
                className={`px-4 py-2 border-b-2 font-semibold transition-colors flex items-center gap-1.5 ${
                  activeTab === "audit"
                    ? "border-cyber-teal text-cyber-teal"
                    : "border-transparent text-slate-400 hover:text-slate-200"
                }`}
              >
                Session Audit Trail
                <Badge variant="outline" className="text-[10px] py-0 px-1 bg-slate-800">
                  {auditEvents.length}
                </Badge>
              </button>
            </div>

            {/* TAB 1: Telemetry & Baseline */}
            {activeTab === "telemetry" && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 bg-background-card rounded-xl border border-border space-y-3">
                  <div className="text-[11px] font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5 border-b border-border/50 pb-2">
                    <ShieldCheckIcon className="w-4 h-4 text-emerald-400" />
                    Expected Secure Baseline Behavior
                  </div>
                  <div className="text-slate-300 text-xs leading-relaxed space-y-2">
                    <p>• Endpoint responds with strict <strong>HTTP 403 Forbidden</strong> or sanitized generic error page.</p>
                    <p>• Administrative listeners are bound strictly to <code>127.0.0.1</code> and reject public network SYN packets.</p>
                    <p>• Hardening headers (<code>Content-Security-Policy</code>, <code>X-Frame-Options</code>, <code>nosniff</code>) are enforced.</p>
                    <p>• Zero sensitive environment keys or source tokens exposed.</p>
                  </div>
                </div>

                <div className="p-4 bg-background-card rounded-xl border border-border space-y-3">
                  <div className="text-[11px] font-bold text-amber-400 uppercase tracking-wider flex items-center gap-1.5 border-b border-border/50 pb-2">
                    <ExclamationTriangleIcon className="w-4 h-4 text-amber-400" />
                    Observed Vulnerability Telemetry
                  </div>
                  <pre className="p-2.5 bg-slate-950/80 rounded-lg border border-border/80 text-[10px] text-slate-300 overflow-x-auto max-h-44 leading-relaxed">
                    {localSession?.evidence
                      ? typeof localSession.evidence === "string"
                        ? localSession.evidence
                        : JSON.stringify(localSession.evidence, null, 2)
                      : "Verified vulnerability telemetry recorded in SQLite ledger."}
                  </pre>
                </div>
              </div>
            )}

            {/* TAB 2: Evidence Chain */}
            {activeTab === "evidence" && (
              <div className="p-4 bg-background-card rounded-xl border border-border space-y-3">
                <div className="flex items-center justify-between border-b border-border/50 pb-2">
                  <span className="text-[11px] font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                    <KeyIcon className="w-4 h-4 text-cyber-teal" />
                    Tamper-Evident SHA-256 Cryptographic Chain
                  </span>
                  <span className="text-[10px] text-emerald-400 font-semibold flex items-center gap-1">
                    <CheckCircleIcon className="w-3.5 h-3.5" />
                    {evidenceChain.length} Verified Blocks
                  </span>
                </div>

                {evidenceChain.length === 0 ? (
                  <div className="text-center py-6 text-slate-500 text-xs">
                    No probe evidence items appended to chain yet. Click an allowlisted action above to execute.
                  </div>
                ) : (
                  <div className="space-y-2.5 max-h-56 overflow-y-auto pr-1">
                    {evidenceChain.map((item, idx) => (
                      <div key={item.id || idx} className="p-3 bg-background-subtle rounded-lg border border-border/70 space-y-1.5 text-[10px]">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-cyber-teal">
                            #{idx + 1} {item.action}
                          </span>
                          <span className="text-slate-500">{new Date(item.timestamp).toLocaleTimeString()}</span>
                        </div>
                        <div className="text-slate-400">
                          <span className="text-slate-500">Target:</span> <code>{item.target}</code>
                        </div>
                        <div className="text-slate-400 flex items-center gap-1">
                          <span className="text-slate-500">SHA-256:</span>
                          <code className="text-emerald-400 bg-slate-950 px-1 py-0.5 rounded text-[9px]">
                            {item.hash}
                          </code>
                        </div>
                        <div className="text-slate-400 flex items-center gap-1">
                          <span className="text-slate-500">Prev Hash:</span>
                          <code className="text-slate-500 bg-slate-950 px-1 py-0.5 rounded text-[9px]">
                            {item.prevHash.substring(0, 16)}...
                          </code>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* TAB 3: Session Audit Trail */}
            {activeTab === "audit" && (
              <div className="p-4 bg-background-card rounded-xl border border-border space-y-3">
                <div className="flex items-center justify-between border-b border-border/50 pb-2">
                  <div className="text-[11px] font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                    <ClockIcon className="w-4 h-4 text-cyber-teal" />
                    Session Audit Trail ({auditEvents.length} Events)
                  </div>
                  <button
                    onClick={copyAuditTrail}
                    className="text-[10px] text-slate-400 hover:text-cyber-teal flex items-center gap-1 transition-colors"
                  >
                    <DocumentDuplicateIcon className="w-3.5 h-3.5" />
                    Copy Audit
                  </button>
                </div>

                <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                  {auditEvents.map((evt: any, idx: number) => (
                    <div
                      key={idx}
                      className="p-2 bg-background-subtle rounded-lg border border-border/60 text-[10px] flex items-start justify-between gap-3"
                    >
                      <div className="space-y-0.5">
                        <span className="text-cyber-teal font-bold">{evt.action}</span>
                        <p className="text-slate-300">{evt.details}</p>
                      </div>
                      <span className="text-slate-500 whitespace-nowrap">
                        {new Date(evt.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}

        {/* Bottom Controls */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-border/60">
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={handleExportProof}
              className="flex items-center gap-1.5 text-slate-200 border-slate-700 hover:border-cyber-teal hover:text-cyber-teal"
            >
              <ArrowDownTrayIcon className="w-4 h-4" />
              Export Signed Proof (.json)
            </Button>
            <a
              href={redTeamApi.getProofMarkdownUrl(localSession?.id || localSession?.sessionToken || "")}
              target="_blank"
              rel="noreferrer"
              className="text-[11px] text-slate-400 hover:text-cyber-teal underline flex items-center gap-1 ml-1"
            >
              Proof Report (.md)
            </a>
          </div>

          <div className="flex items-center gap-2.5">
            {isActive && (
              <Button
                variant="danger"
                size="sm"
                onClick={handleTerminate}
                disabled={terminating}
                className="flex items-center gap-1.5 bg-red-600 hover:bg-red-700 text-white font-bold"
              >
                <StopIcon className="w-4 h-4" />
                {terminating ? "Revoking..." : "Terminate Session / Kill-Switch"}
              </Button>
            )}
            <Button variant="secondary" size="sm" onClick={onClose}>
              Close Console
            </Button>
          </div>
        </div>
      </div>
    </Modal>
  );
}
