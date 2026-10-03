"use client";

import React, { useState } from "react";
import { AttackGraphNode, AttackGraphEdge } from "@/lib/api/red-team";
import { Badge } from "@/components/ui/badge";
import {
  GlobeAltIcon,
  ServerIcon,
  ShieldExclamationIcon,
  KeyIcon,
  CommandLineIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  BoltIcon
} from "@heroicons/react/24/outline";

interface Props {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  stats?: {
    totalNodes: number;
    totalEdges: number;
    criticalPaths: number;
  };
}

export function AttackGraphVisualizer({ nodes, edges, stats }: Props) {
  const [selectedNode, setSelectedNode] = useState<AttackGraphNode | null>(nodes[0] || null);

  const getNodeColor = (category: string, severity?: string) => {
    switch (category) {
      case "TARGET":
        return "border-blue-500 bg-blue-500/10 text-blue-400 shadow-[0_0_15px_rgba(59,130,246,0.2)]";
      case "ASSET":
        return "border-cyan-500 bg-cyan-500/10 text-cyan-400";
      case "SERVICE":
        return "border-purple-500 bg-purple-500/10 text-purple-400";
      case "APPLICATION":
        return "border-indigo-500 bg-indigo-500/10 text-indigo-300";
      case "ENDPOINT":
        return "border-teal-500 bg-teal-500/10 text-teal-400";
      case "VULNERABILITY":
        return severity === "critical"
          ? "border-red-500 bg-red-500/15 text-red-400 shadow-[0_0_15px_rgba(239,68,68,0.3)] animate-pulse"
          : severity === "high"
          ? "border-orange-500 bg-orange-500/15 text-orange-400"
          : "border-amber-500 bg-amber-500/10 text-amber-400";
      case "PRIVILEGE":
        return "border-fuchsia-500 bg-fuchsia-500/15 text-fuchsia-300 shadow-[0_0_15px_rgba(217,70,239,0.3)]";
      default:
        return "border-slate-600 bg-slate-800 text-slate-300";
    }
  };

  const getNodeIcon = (category: string) => {
    switch (category) {
      case "TARGET":
        return <GlobeAltIcon className="w-4 h-4" />;
      case "ASSET":
        return <GlobeAltIcon className="w-4 h-4" />;
      case "SERVICE":
        return <ServerIcon className="w-4 h-4" />;
      case "APPLICATION":
        return <CommandLineIcon className="w-4 h-4" />;
      case "ENDPOINT":
        return <CommandLineIcon className="w-4 h-4" />;
      case "VULNERABILITY":
        return <ShieldExclamationIcon className="w-4 h-4" />;
      case "PRIVILEGE":
        return <KeyIcon className="w-4 h-4" />;
      default:
        return <BoltIcon className="w-4 h-4" />;
    }
  };

  // Group nodes by category columns for intuitive cyber attack path layout
  const targetNodes = nodes.filter(n => n.category === "TARGET" || n.category === "ASSET");
  const serviceNodes = nodes.filter(n => n.category === "SERVICE" || n.category === "APPLICATION");
  const endpointNodes = nodes.filter(n => n.category === "ENDPOINT");
  const vulnNodes = nodes.filter(n => n.category === "VULNERABILITY");
  const privNodes = nodes.filter(n => n.category === "PRIVILEGE" || n.category === "ATTACK_PATH");

  return (
    <div className="space-y-4">
      {/* Graph Stats Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-background-subtle rounded-xl border border-border text-xs font-mono">
        <div className="flex items-center gap-4">
          <span className="text-slate-400">
            Graph Topology: <strong className="text-slate-200">{nodes.length}</strong> Nodes
          </span>
          <span className="text-slate-400">
            Attack Vectors: <strong className="text-slate-200">{edges.length}</strong> Relations
          </span>
          <span className="text-slate-400">
            Critical Ingress Paths:{" "}
            <strong className="text-red-400 font-bold">{stats?.criticalPaths || edges.filter(e => e.isCriticalPath).length}</strong>
          </span>
        </div>
        <div className="text-[11px] text-slate-500">
          Click any node to inspect raw properties & telemetry evidence
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Left 2 Cols: Interactive Graph Map */}
        <div className="lg:col-span-2 p-5 bg-background-card rounded-2xl border border-border min-h-[440px] flex flex-col justify-between overflow-x-auto">
          <div className="grid grid-cols-4 gap-3 min-w-[600px]">
            {/* Column 1: Perimeter & Assets */}
            <div className="space-y-2.5">
              <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider font-bold border-b border-border/50 pb-1 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-blue-500"></span>
                1. Ingress Perimeter
              </div>
              <div className="space-y-2">
                {targetNodes.map((node) => (
                  <button
                    key={node.id}
                    onClick={() => setSelectedNode(node)}
                    className={`w-full text-left p-2.5 rounded-xl border transition-all text-xs font-mono flex items-start gap-2 ${getNodeColor(
                      node.category,
                      node.severity
                    )} ${selectedNode?.id === node.id ? "ring-2 ring-cyber-teal" : "hover:scale-[1.02]"}`}
                  >
                    <div className="mt-0.5">{getNodeIcon(node.category)}</div>
                    <div className="truncate">
                      <div className="font-bold truncate">{node.label}</div>
                      <div className="text-[10px] opacity-75">{node.category}</div>
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Column 2: Exposed Services */}
            <div className="space-y-2.5">
              <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider font-bold border-b border-border/50 pb-1 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-purple-500"></span>
                2. Listeners & Gateways
              </div>
              <div className="space-y-2">
                {serviceNodes.map((node) => (
                  <button
                    key={node.id}
                    onClick={() => setSelectedNode(node)}
                    className={`w-full text-left p-2.5 rounded-xl border transition-all text-xs font-mono flex items-start gap-2 ${getNodeColor(
                      node.category,
                      node.severity
                    )} ${selectedNode?.id === node.id ? "ring-2 ring-cyber-teal" : "hover:scale-[1.02]"}`}
                  >
                    <div className="mt-0.5">{getNodeIcon(node.category)}</div>
                    <div className="truncate">
                      <div className="font-bold truncate">{node.label}</div>
                      <div className="text-[10px] opacity-75">{node.category}</div>
                    </div>
                  </button>
                ))}
                {serviceNodes.length === 0 && (
                  <div className="text-xs font-mono text-slate-500 p-2">No open services</div>
                )}
              </div>
            </div>

            {/* Column 3: Vulnerabilities */}
            <div className="space-y-2.5">
              <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider font-bold border-b border-border/50 pb-1 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-red-500"></span>
                3. Exploit Weaknesses
              </div>
              <div className="space-y-2">
                {vulnNodes.map((node) => (
                  <button
                    key={node.id}
                    onClick={() => setSelectedNode(node)}
                    className={`w-full text-left p-2.5 rounded-xl border transition-all text-xs font-mono flex items-start gap-2 ${getNodeColor(
                      node.category,
                      node.severity
                    )} ${selectedNode?.id === node.id ? "ring-2 ring-cyber-teal" : "hover:scale-[1.02]"}`}
                  >
                    <div className="mt-0.5">{getNodeIcon(node.category)}</div>
                    <div className="truncate">
                      <div className="font-bold truncate">{node.label}</div>
                      <div className="text-[10px] opacity-75 uppercase">{node.severity || "MEDIUM"}</div>
                    </div>
                  </button>
                ))}
                {vulnNodes.length === 0 && (
                  <div className="text-xs font-mono text-emerald-400 p-2 flex items-center gap-1">
                    <CheckCircleIcon className="w-3.5 h-3.5" /> No active flaws
                  </div>
                )}
              </div>
            </div>

            {/* Column 4: Privilege & Lateral Impact */}
            <div className="space-y-2.5">
              <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider font-bold border-b border-border/50 pb-1 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-fuchsia-500"></span>
                4. Impact & Privilege
              </div>
              <div className="space-y-2">
                {privNodes.map((node) => (
                  <button
                    key={node.id}
                    onClick={() => setSelectedNode(node)}
                    className={`w-full text-left p-2.5 rounded-xl border transition-all text-xs font-mono flex items-start gap-2 ${getNodeColor(
                      node.category,
                      node.severity
                    )} ${selectedNode?.id === node.id ? "ring-2 ring-cyber-teal" : "hover:scale-[1.02]"}`}
                  >
                    <div className="mt-0.5">{getNodeIcon(node.category)}</div>
                    <div className="truncate">
                      <div className="font-bold truncate">{node.label}</div>
                      <div className="text-[10px] opacity-75">PRIVILEGE</div>
                    </div>
                  </button>
                ))}
                {privNodes.length === 0 && (
                  <div className="text-xs font-mono text-slate-500 p-2">Perimeter bounded</div>
                )}
              </div>
            </div>
          </div>

          {/* Active Exploit Path Legend */}
          <div className="pt-4 border-t border-border/50 flex flex-wrap items-center gap-4 text-[11px] font-mono text-slate-400">
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-0.5 bg-red-500 animate-pulse"></span>
              Critical Attack Vector
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-0.5 bg-slate-600"></span>
              Discovery Boundary
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
              Deterministic Verification
            </span>
          </div>
        </div>

        {/* Right 1 Col: Selected Node Inspector */}
        <div className="p-5 bg-background-card rounded-2xl border border-border space-y-4">
          <div className="border-b border-border/60 pb-3 flex items-center justify-between">
            <div className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold flex items-center gap-2">
              <CommandLineIcon className="w-4 h-4 text-cyber-teal" />
              Node Inspector
            </div>
            {selectedNode && (
              <Badge variant="outline" className="text-[10px] font-mono border-cyber-teal text-cyber-teal">
                {selectedNode.category}
              </Badge>
            )}
          </div>

          {selectedNode ? (
            <div className="space-y-3 font-mono text-xs">
              <div>
                <span className="text-slate-500 text-[10px] uppercase">Node Label</span>
                <div className="text-slate-100 font-bold text-sm mt-0.5">{selectedNode.label}</div>
              </div>

              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div className="p-2 bg-background-subtle rounded-lg border border-border">
                  <span className="text-slate-500">Status</span>
                  <div className="text-slate-200 font-bold uppercase mt-0.5">{selectedNode.status}</div>
                </div>
                <div className="p-2 bg-background-subtle rounded-lg border border-border">
                  <span className="text-slate-500">Severity</span>
                  <div className="text-slate-200 font-bold uppercase mt-0.5">
                    {selectedNode.severity || "INFO"}
                  </div>
                </div>
              </div>

              {selectedNode.properties && (
                <div>
                  <span className="text-slate-500 text-[10px] uppercase">Telemetry Properties</span>
                  <pre className="mt-1 p-2.5 bg-slate-950/80 rounded-xl border border-border/80 text-[10px] text-slate-300 overflow-x-auto max-h-48 leading-relaxed">
                    {JSON.stringify(selectedNode.properties, null, 2)}
                  </pre>
                </div>
              )}

              {/* Related Edges for this node */}
              <div>
                <span className="text-slate-500 text-[10px] uppercase">Attack Graph Relations</span>
                <div className="space-y-1.5 mt-1">
                  {edges
                    .filter(e => e.source === selectedNode.id || e.target === selectedNode.id)
                    .map((e, idx) => (
                      <div
                        key={idx}
                        className={`p-2 rounded-lg border text-[10px] flex items-center justify-between ${
                          e.isCriticalPath
                            ? "bg-red-500/10 border-red-500/30 text-red-300"
                            : "bg-background-subtle border-border text-slate-300"
                        }`}
                      >
                        <span className="font-bold">{e.relation}</span>
                        <span className="opacity-75">{e.source === selectedNode.id ? "→ outgoing" : "← incoming"}</span>
                      </div>
                    ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="text-center py-12 text-slate-500 font-mono text-xs">
              Select any graph node on the left to inspect its telemetry and attack relationships.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
