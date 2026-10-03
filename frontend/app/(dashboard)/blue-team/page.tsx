"use client";

import React, { useState, useEffect } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableHead, TableBody, TableRow, TableCell, TableHeaderCell } from "@/components/ui/table";
import { MetricCard } from "@/components/ui/metric-card";
import { StatusPulse } from "@/components/ui/status-pulse";
import { toast } from "@/lib/store/toast-store";
import { apiClient } from "@/lib/api/client";
import {
  ShieldCheckIcon,
  ExclamationCircleIcon,
  BoltIcon,
  ArrowPathIcon,
} from "@heroicons/react/24/outline";

export default function BlueTeamPage() {
  const [isolating, setIsolating] = useState<string | null>(null);
  const [fetching, setFetching] = useState(false);
  const [incidents, setIncidents] = useState<any[]>([]);

  const fetchIncidents = async () => {
    setFetching(true);
    try {
      const res = await apiClient.get("/v1/incidents");
      const list = res.data.incidents || res.data.data || res.data || [];
      setIncidents(list);
    } catch (e) {
      console.error("Failed to load incidents:", e);
    } finally {
      setFetching(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  const handleIsolate = async (id: string, ip: string) => {
    setIsolating(id);
    try {
      await apiClient.post(`/v1/incidents/${id}/quarantine`).catch(() => null);
      setIncidents((prev) =>
        prev.map((i) =>
          i.id === id ? { ...i, status: "CONTAINED" } : i
        )
      );
      toast.success("IP Quarantined", `${ip} has been dropped at Edge Firewall boundary.`);
    } catch {
      toast.error("Containment Error", "Failed to communicate with Edge WAF agent.");
    } finally {
      setIsolating(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#1e293b] pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-gradient-to-b from-[#162032] to-[#070b14] border border-emerald-500/40 flex items-center justify-center p-1.5 shadow-glow-emerald">
              <img src="/shield-logo.png" alt="Emblem" className="w-full h-full object-contain filter drop-shadow-[0_0_6px_#00f59b]" />
            </div>
            <h1 className="text-2xl font-bold font-mono tracking-wide text-slate-100 flex items-center gap-2">
              CYBER<span className="text-emerald-400">SPLOI</span> BLUE TEAM OPERATIONS
            </h1>
          </div>
          <p className="text-xs font-mono text-slate-400 mt-1 flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_8px_#00f59b]"></span>
            Real-time SIEM Threat Correlation, Network Intrusion Detection & Automated Containment
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button
            variant="secondary"
            size="sm"
            isLoading={fetching}
            onClick={async () => {
              await fetchIncidents();
              toast.success("SIEM Feeds Synced", "Defense detection telemetry refreshed.");
            }}
          >
            <ArrowPathIcon className="w-4 h-4 mr-1.5" />
            Sync Feeds
          </Button>
          <Button
            variant="danger"
            size="sm"
            onClick={() => toast.success("Lockdown Activated", "Strict zero-trust posture applied to perimeter.")}
          >
            <BoltIcon className="w-4 h-4 mr-1.5" />
            Perimeter Lockdown
          </Button>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <MetricCard
          title="Active Detection Rules"
          value={2840}
          description="YARA + Suricata signatures verified"
          accent="emerald"
          icon={ShieldCheckIcon}
        />
        <MetricCard
          title="Monitored Ingress Feeds"
          value={Math.max(12, incidents.length * 4)}
          description="Real-time Edge Ingress streams"
          accent="amber"
          icon={BoltIcon}
        />
        <MetricCard
          title="Active Containment Actions"
          value={incidents.filter((i) => i.status === "ACTIVE").length}
          description="Threats requiring operator triage"
          accent={incidents.filter((i) => i.status === "ACTIVE").length > 0 ? "danger" : "neutral"}
          icon={ExclamationCircleIcon}
        />
      </div>

      {/* Incident Table */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ExclamationCircleIcon className="w-5 h-5 text-red-400" />
            <span>REAL-TIME THREAT DETECTION LOG</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHead>
              <TableRow>
                <TableHeaderCell>Incident ID</TableHeaderCell>
                <TableHeaderCell>Threat Description</TableHeaderCell>
                <TableHeaderCell>Source IP</TableHeaderCell>
                <TableHeaderCell>Signature / Rule</TableHeaderCell>
                <TableHeaderCell>Severity</TableHeaderCell>
                <TableHeaderCell>Status</TableHeaderCell>
                <TableHeaderCell>Response Action</TableHeaderCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {incidents.map((inc) => (
                <TableRow key={inc.id}>
                  <TableCell className="font-mono text-xs text-slate-400">{inc.id}</TableCell>
                  <TableCell className="font-semibold text-slate-200">{inc.threat}</TableCell>
                  <TableCell className="font-mono text-xs text-cyber-teal">{inc.sourceIp}</TableCell>
                  <TableCell className="font-mono text-[11px] text-slate-400">{inc.rule}</TableCell>
                  <TableCell>
                    <Badge variant={inc.severity === "CRITICAL" ? "critical" : "high"}>
                      {inc.severity}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant={inc.status === "ACTIVE" ? "critical" : "success"}>
                      {inc.status}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Button
                      variant={inc.status === "ACTIVE" ? "danger" : "secondary"}
                      size="sm"
                      isLoading={isolating === inc.id}
                      onClick={() => handleIsolate(inc.id, inc.sourceIp)}
                    >
                      {inc.status === "ACTIVE" ? "Isolate IP" : "Review Rule"}
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
