"use client";

import React, { useState, useEffect } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Modal } from "@/components/ui/modal";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { useAuthStore } from "@/lib/store/auth-store";
import { useToast } from "@/lib/store/toast-store";
import {
  Cog6ToothIcon,
  KeyIcon,
  UserGroupIcon,
  CreditCardIcon,
  ShieldCheckIcon,
  CheckCircleIcon,
  ClipboardDocumentIcon,
  TrashIcon,
  PlusIcon,
  BuildingOfficeIcon,
  ArrowPathIcon,
  BoltIcon,
  LockClosedIcon,
} from "@heroicons/react/24/outline";

interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  created: string;
  lastUsed: string;
}

interface TeamMember {
  id: string;
  name: string;
  email: string;
  role: "Owner" | "Admin" | "Security Analyst" | "Pentester" | "Auditor";
  mfaEnabled: boolean;
  status: "active" | "invited";
  lastLogin: string;
}

export default function SettingsPage() {
  const { user } = useAuthStore();
  const { addToast } = useToast();
  const [activeTab, setActiveTab] = useState("organization");

  // Organization state
  const [orgName, setOrgName] = useState("CYBERSPLOI Defense Mesh");
  const [contactEmail, setContactEmail] = useState("soc-lead@cybersploi.io");
  const [complianceRegion, setComplianceRegion] = useState("us-east-vault");
  const [isSavingOrg, setIsSavingOrg] = useState(false);

  // API Keys state
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([
    {
      id: "key-prod-01",
      name: "CI/CD Pipeline DAST Runner",
      prefix: "cs_live_9a7b...4f8e",
      scopes: ["scans:write", "scans:read", "reports:read"],
      created: "2024-03-15",
      lastUsed: "2 minutes ago",
    },
    {
      id: "key-prod-02",
      name: "Splunk SIEM Forwarder Token",
      prefix: "cs_live_3c2d...819a",
      scopes: ["vulnerabilities:read", "threats:read"],
      created: "2024-04-01",
      lastUsed: "Just now",
    },
    {
      id: "key-prod-03",
      name: "External BugBounty Scraper",
      prefix: "cs_live_1f4e...92bb",
      scopes: ["assets:read"],
      created: "2024-05-10",
      lastUsed: "3 days ago",
    },
  ]);
  const [isNewKeyModalOpen, setIsNewKeyModalOpen] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeyScope, setNewKeyScope] = useState("full_access");
  const [generatedKey, setGeneratedKey] = useState<string | null>(null);

  // Team state
  const [team, setTeam] = useState<TeamMember[]>([
    {
      id: "usr-01",
      name: user ? `${user.firstName} ${user.lastName}` : "Alex Mercer",
      email: user?.email || "alex.mercer@cybersploi.io",
      role: "Owner",
      mfaEnabled: true,
      status: "active",
      lastLogin: "Active now",
    },
    {
      id: "usr-02",
      name: "Elena Rostova",
      email: "e.rostova@cybersploi.io",
      role: "Admin",
      mfaEnabled: true,
      status: "active",
      lastLogin: "2 hours ago",
    },
    {
      id: "usr-03",
      name: "Darius Vance",
      email: "darius.v@cybersploi.io",
      role: "Pentester",
      mfaEnabled: true,
      status: "active",
      lastLogin: "Yesterday",
    },
    {
      id: "usr-04",
      name: "Clara Zhang",
      email: "clara.audit@cybersploi.io",
      role: "Auditor",
      mfaEnabled: false,
      status: "active",
      lastLogin: "5 days ago",
    },
  ]);
  const [isInviteModalOpen, setIsInviteModalOpen] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<TeamMember["role"]>("Security Analyst");

  // Webhook / SIEM forwarder state
  const [siemUrl, setSiemUrl] = useState("https://splunk-hec.internal.corp:8088/services/collector");
  const [siemToken, setSiemToken] = useState("••••••••••••••••••••••••••••••");
  const [testingWebhook, setTestingWebhook] = useState(false);

  useEffect(() => {
    if (user?.organization) {
      setOrgName(user.organization);
    }
    if (user?.email) {
      setContactEmail(user.email);
    }
  }, [user]);

  const handleSaveOrg = (e: React.FormEvent) => {
    e.preventDefault();
    setIsSavingOrg(true);
    setTimeout(() => {
      setIsSavingOrg(false);
      addToast("Organization profile updated successfully", "success");
    }, 600);
  };

  const handleGenerateKey = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newKeyName.trim()) {
      addToast("Key name is required", "warning");
      return;
    }
    const tokenSecret = `cs_live_${Math.random().toString(36).substring(2, 10)}_${Math.random().toString(36).substring(2, 12)}`;
    const newEntry: ApiKey = {
      id: `key-${Date.now().toString().slice(-4)}`,
      name: newKeyName,
      prefix: `${tokenSecret.slice(0, 12)}...${tokenSecret.slice(-4)}`,
      scopes: newKeyScope === "full_access" ? ["* (All scopes)"] : ["scans:read", "scans:write"],
      created: new Date().toISOString().split("T")[0],
      lastUsed: "Never",
    };
    setApiKeys([newEntry, ...apiKeys]);
    setGeneratedKey(tokenSecret);
    addToast(`API Key "${newKeyName}" generated successfully`, "success");
  };

  const handleRevokeKey = (id: string) => {
    setApiKeys(apiKeys.filter((k) => k.id !== id));
    addToast("API Key permanently revoked", "info");
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    addToast("Copied to clipboard", "success");
  };

  const handleInviteUser = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inviteEmail.trim()) return;
    const newMember: TeamMember = {
      id: `usr-${Date.now().toString().slice(-4)}`,
      name: inviteEmail.split("@")[0],
      email: inviteEmail,
      role: inviteRole,
      mfaEnabled: false,
      status: "invited",
      lastLogin: "Pending Invite",
    };
    setTeam([...team, newMember]);
    setInviteEmail("");
    setIsInviteModalOpen(false);
    addToast(`Invitation dispatched to ${inviteEmail}`, "success");
  };

  const handleTestWebhook = () => {
    setTestingWebhook(true);
    setTimeout(() => {
      setTestingWebhook(false);
      addToast("SIEM ping acknowledgment received [HTTP 200 OK]", "success");
    }, 900);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-[#1e293b] pb-5">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-xl bg-gradient-to-b from-[#162032] to-[#070b14] border border-cyber-cyan/40 flex items-center justify-center p-1.5 shadow-glow">
            <img src="/shield-logo.png" alt="Emblem" className="w-full h-full object-contain filter drop-shadow-[0_0_6px_#00d2ff]" />
          </div>
          <h1 className="text-2xl font-bold font-mono tracking-tight text-white flex items-center gap-2">
            CYBER<span className="text-cyber-cyan">SPLOI</span> SYSTEM & ENTERPRISE SETTINGS
          </h1>
        </div>
        <p className="text-xs font-mono text-slate-400 mt-1 flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-cyber-cyan animate-pulse shadow-[0_0_8px_#00d2ff]"></span>
          Manage tenant identity, programmatic API access, RBAC security roles, and telemetry streams.
        </p>
      </div>

      <Tabs defaultValue="organization" value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-cyber-surface border border-cyber-border mb-6">
          <TabsTrigger value="organization" className="flex items-center gap-2">
            <BuildingOfficeIcon className="w-4 h-4" />
            Organization
          </TabsTrigger>
          <TabsTrigger value="apikeys" className="flex items-center gap-2">
            <KeyIcon className="w-4 h-4" />
            API Keys & Integrations
          </TabsTrigger>
          <TabsTrigger value="team" className="flex items-center gap-2">
            <UserGroupIcon className="w-4 h-4" />
            RBAC & Team
          </TabsTrigger>
          <TabsTrigger value="subscription" className="flex items-center gap-2">
            <CreditCardIcon className="w-4 h-4" />
            Plan & Quotas
          </TabsTrigger>
        </TabsList>

        {/* 1. ORGANIZATION TAB */}
        <TabsContent value="organization">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2">
              <Card className="bg-cyber-surface border-cyber-border">
                <CardHeader className="border-b border-cyber-border/40 pb-4">
                  <CardTitle className="text-base text-cyber-text-primary">
                    Organization Profile
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-6">
                  <form onSubmit={handleSaveOrg} className="space-y-4">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-xs font-medium text-cyber-text-secondary mb-1">
                          Organization / Company Name
                        </label>
                        <Input
                          value={orgName}
                          onChange={(e) => setOrgName(e.target.value)}
                          className="bg-cyber-bg border-cyber-border"
                          required
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-cyber-text-secondary mb-1">
                          Security Contact / SOC Email
                        </label>
                        <Input
                          type="email"
                          value={contactEmail}
                          onChange={(e) => setContactEmail(e.target.value)}
                          className="bg-cyber-bg border-cyber-border"
                          required
                        />
                      </div>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-xs font-medium text-cyber-text-secondary mb-1">
                          Compliance Cloud Enclave
                        </label>
                        <Select
                          value={complianceRegion}
                          onChange={(e) => setComplianceRegion(e.target.value)}
                          options={[
                            { label: "US East (SOC 2 / FedRAMP Vault)", value: "us-east-vault" },
                            { label: "EU Central (GDPR / ISO 27001)", value: "eu-central-vault" },
                            { label: "AP South (APEC Cyber Mesh)", value: "ap-south-vault" },
                          ]}
                          className="bg-cyber-bg border-cyber-border"
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-cyber-text-secondary mb-1">
                          Tenant Cryptographic ID
                        </label>
                        <Input
                          value="ten_94a73e88-f14d-4b9a-8869"
                          disabled
                          className="bg-cyber-bg/50 border-cyber-border text-cyber-text-muted font-mono text-xs"
                        />
                      </div>
                    </div>

                    <div className="pt-4 border-t border-cyber-border/40 flex justify-end">
                      <Button
                        type="submit"
                        variant="primary"
                        size="sm"
                        disabled={isSavingOrg}
                        className="flex items-center gap-2"
                      >
                        {isSavingOrg ? (
                          <>
                            <ArrowPathIcon className="w-4 h-4 animate-spin" />
                            Updating...
                          </>
                        ) : (
                          "Save Changes"
                        )}
                      </Button>
                    </div>
                  </form>
                </CardContent>
              </Card>
            </div>

            {/* Right Security Guardrail Card */}
            <div>
              <Card className="bg-cyber-surface border-cyber-border">
                <CardHeader className="border-b border-cyber-border/40 pb-4">
                  <CardTitle className="text-sm font-semibold text-cyber-text-primary flex items-center gap-2">
                    <ShieldCheckIcon className="w-5 h-5 text-emerald-400" />
                    Enclave Posture
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-4 space-y-3 text-xs">
                  <div className="flex justify-between items-center py-1 border-b border-cyber-border/30">
                    <span className="text-cyber-text-secondary">Data Encryption:</span>
                    <span className="font-mono text-emerald-400">AES-256-GCM</span>
                  </div>
                  <div className="flex justify-between items-center py-1 border-b border-cyber-border/30">
                    <span className="text-cyber-text-secondary">Mandatory 2FA/MFA:</span>
                    <Badge variant="success" className="text-[10px]">Enforced</Badge>
                  </div>
                  <div className="flex justify-between items-center py-1 border-b border-cyber-border/30">
                    <span className="text-cyber-text-secondary">Audit Trail Retention:</span>
                    <span className="font-mono text-cyber-text-primary">365 Days</span>
                  </div>
                  <div className="flex justify-between items-center py-1">
                    <span className="text-cyber-text-secondary">API IP Allowlisting:</span>
                    <Badge variant="outline" className="text-[10px] text-amber-400 border-amber-500/40">Optional</Badge>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </TabsContent>

        {/* 2. API KEYS & INTEGRATIONS TAB */}
        <TabsContent value="apikeys">
          <div className="space-y-6">
            {/* Keys Table */}
            <Card className="bg-cyber-surface border-cyber-border">
              <CardHeader className="border-b border-cyber-border/40 pb-4 flex flex-row items-center justify-between">
                <div>
                  <CardTitle className="text-base text-cyber-text-primary flex items-center gap-2">
                    <KeyIcon className="w-5 h-5 text-cyber-accent" />
                    Programmatic API Keys
                  </CardTitle>
                  <p className="text-xs text-cyber-text-secondary mt-0.5">
                    Machine tokens for CI/CD pipeline automation and external orchestrators.
                  </p>
                </div>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => {
                    setGeneratedKey(null);
                    setNewKeyName("");
                    setIsNewKeyModalOpen(true);
                  }}
                  className="flex items-center gap-1.5"
                >
                  <PlusIcon className="w-4 h-4" />
                  Generate Key
                </Button>
              </CardHeader>
              <CardContent className="p-0">
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-cyber-bg/60 text-cyber-text-secondary border-b border-cyber-border/40 font-mono">
                      <tr>
                        <th className="py-3 px-4 font-medium">KEY NAME</th>
                        <th className="py-3 px-4 font-medium">TOKEN HASH</th>
                        <th className="py-3 px-4 font-medium">AUTHORIZED SCOPES</th>
                        <th className="py-3 px-4 font-medium">CREATED</th>
                        <th className="py-3 px-4 font-medium">LAST SEEN</th>
                        <th className="py-3 px-4 font-medium text-right">REVOKE</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-cyber-border/30">
                      {apiKeys.map((key) => (
                        <tr key={key.id} className="hover:bg-cyber-bg/40 transition-colors">
                          <td className="py-3 px-4 font-medium text-cyber-text-primary">{key.name}</td>
                          <td className="py-3 px-4 font-mono text-cyber-accent">{key.prefix}</td>
                          <td className="py-3 px-4">
                            <div className="flex flex-wrap gap-1">
                              {key.scopes.map((s) => (
                                <Badge key={s} variant="outline" className="text-[10px] bg-cyber-bg">
                                  {s}
                                </Badge>
                              ))}
                            </div>
                          </td>
                          <td className="py-3 px-4 text-cyber-text-secondary">{key.created}</td>
                          <td className="py-3 px-4 text-cyber-text-secondary">{key.lastUsed}</td>
                          <td className="py-3 px-4 text-right">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleRevokeKey(key.id)}
                              className="text-red-400 hover:text-red-300 h-7 px-2"
                            >
                              <TrashIcon className="w-4 h-4" />
                            </Button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>

            {/* SIEM Forwarder / Webhook Integration */}
            <Card className="bg-cyber-surface border-cyber-border">
              <CardHeader className="border-b border-cyber-border/40 pb-4">
                <CardTitle className="text-base text-cyber-text-primary flex items-center gap-2">
                  <BoltIcon className="w-5 h-5 text-amber-400" />
                  Real-Time SIEM & Telemetry Forwarder
                </CardTitle>
                <p className="text-xs text-cyber-text-secondary mt-0.5">
                  Stream high-severity pentest findings and vulnerability detections to your SOC SIEM.
                </p>
              </CardHeader>
              <CardContent className="p-6 space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-medium text-cyber-text-secondary mb-1">
                      SIEM Ingestion Endpoint (Splunk HEC / Elastic / Custom Webhook)
                    </label>
                    <Input
                      value={siemUrl}
                      onChange={(e) => setSiemUrl(e.target.value)}
                      className="bg-cyber-bg border-cyber-border font-mono text-xs"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-cyber-text-secondary mb-1">
                      HEC / Authorization Bearer Token
                    </label>
                    <Input
                      type="password"
                      value={siemToken}
                      onChange={(e) => setSiemToken(e.target.value)}
                      className="bg-cyber-bg border-cyber-border font-mono text-xs"
                    />
                  </div>
                </div>

                <div className="flex items-center justify-between pt-2">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                    <span className="text-xs text-cyber-text-secondary">Stream Active (TLS 1.3 Verified)</span>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={handleTestWebhook}
                      disabled={testingWebhook}
                      className="border-cyber-border text-xs"
                    >
                      {testingWebhook ? "Testing..." : "Send Test Telemetry Probe"}
                    </Button>
                    <Button
                      variant="primary"
                      size="sm"
                      onClick={() => addToast("SIEM endpoint configuration saved", "success")}
                      className="text-xs"
                    >
                      Save Stream
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* 3. RBAC & TEAM TAB */}
        <TabsContent value="team">
          <Card className="bg-cyber-surface border-cyber-border">
            <CardHeader className="border-b border-cyber-border/40 pb-4 flex flex-row items-center justify-between">
              <div>
                <CardTitle className="text-base text-cyber-text-primary flex items-center gap-2">
                  <UserGroupIcon className="w-5 h-5 text-cyber-accent" />
                  Role-Based Access Control (RBAC)
                </CardTitle>
                <p className="text-xs text-cyber-text-secondary mt-0.5">
                  Granular permissions matrix for SOC analysts, red teamers, and auditors.
                </p>
              </div>
              <Button
                variant="primary"
                size="sm"
                onClick={() => setIsInviteModalOpen(true)}
                className="flex items-center gap-1.5"
              >
                <PlusIcon className="w-4 h-4" />
                Invite Member
              </Button>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-cyber-bg/60 text-cyber-text-secondary border-b border-cyber-border/40 font-mono">
                    <tr>
                      <th className="py-3 px-4 font-medium">MEMBER</th>
                      <th className="py-3 px-4 font-medium">ASSIGNED ROLE</th>
                      <th className="py-3 px-4 font-medium">MFA STATUS</th>
                      <th className="py-3 px-4 font-medium">ACCOUNT STATUS</th>
                      <th className="py-3 px-4 font-medium">LAST ACTIVE</th>
                      <th className="py-3 px-4 font-medium text-right">MANAGE</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-cyber-border/30">
                    {team.map((member) => (
                      <tr key={member.id} className="hover:bg-cyber-bg/40 transition-colors">
                        <td className="py-3 px-4">
                          <div className="font-medium text-cyber-text-primary">{member.name}</div>
                          <div className="text-[11px] text-cyber-text-secondary">{member.email}</div>
                        </td>
                        <td className="py-3 px-4">
                          <Badge
                            variant={
                              member.role === "Owner"
                                ? "info"
                                : member.role === "Admin"
                                ? "default"
                                : member.role === "Pentester"
                                ? "warning"
                                : "outline"
                            }
                            className="text-[10px]"
                          >
                            {member.role}
                          </Badge>
                        </td>
                        <td className="py-3 px-4">
                          {member.mfaEnabled ? (
                            <span className="flex items-center gap-1 text-emerald-400 font-mono text-[11px]">
                              <CheckCircleIcon className="w-3.5 h-3.5" /> FIDO2 / TOTP
                            </span>
                          ) : (
                            <span className="text-amber-400 font-mono text-[11px]">Pending Setup</span>
                          )}
                        </td>
                        <td className="py-3 px-4">
                          <Badge
                            variant={member.status === "active" ? "success" : "warning"}
                            className="capitalize text-[10px]"
                          >
                            {member.status}
                          </Badge>
                        </td>
                        <td className="py-3 px-4 text-cyber-text-secondary">{member.lastLogin}</td>
                        <td className="py-3 px-4 text-right">
                          {member.role !== "Owner" && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                setTeam(team.filter((m) => m.id !== member.id));
                                addToast(`Member ${member.email} removed`, "info");
                              }}
                              className="text-red-400 hover:text-red-300 h-7 px-2"
                            >
                              <TrashIcon className="w-4 h-4" />
                            </Button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* 4. SUBSCRIPTION & QUOTAS TAB */}
        <TabsContent value="subscription">
          <div className="space-y-6">
            {/* Quota Progress Card */}
            <Card className="bg-cyber-surface border-cyber-border">
              <CardHeader className="border-b border-cyber-border/40 pb-4">
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-base text-cyber-text-primary">
                      Current Quota Consumption
                    </CardTitle>
                    <p className="text-xs text-cyber-text-secondary mt-0.5">
                      Usage resets on the 1st of each calendar month.
                    </p>
                  </div>
                  <Badge variant="success" className="text-xs">Active Subscription: Enterprise MSSP</Badge>
                </div>
              </CardHeader>
              <CardContent className="p-6">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div>
                    <div className="flex justify-between text-xs mb-1.5 font-mono">
                      <span className="text-cyber-text-secondary">Active Pen Scans</span>
                      <span className="text-cyber-accent font-bold">42 / 100</span>
                    </div>
                    <div className="w-full bg-cyber-bg rounded-full h-2 overflow-hidden border border-cyber-border">
                      <div className="bg-cyber-accent h-2 rounded-full" style={{ width: "42%" }} />
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between text-xs mb-1.5 font-mono">
                      <span className="text-cyber-text-secondary">Attack Surface Assets</span>
                      <span className="text-emerald-400 font-bold">8 / 25</span>
                    </div>
                    <div className="w-full bg-cyber-bg rounded-full h-2 overflow-hidden border border-cyber-border">
                      <div className="bg-emerald-400 h-2 rounded-full" style={{ width: "32%" }} />
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between text-xs mb-1.5 font-mono">
                      <span className="text-cyber-text-secondary">AI Neural Inference Tokens</span>
                      <span className="text-sky-400 font-bold">145k / 1,000k</span>
                    </div>
                    <div className="w-full bg-cyber-bg rounded-full h-2 overflow-hidden border border-cyber-border">
                      <div className="bg-sky-400 h-2 rounded-full" style={{ width: "14.5%" }} />
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Plan Tier Selection */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {/* Community Tier */}
              <div className="p-6 rounded-lg bg-cyber-surface border border-cyber-border flex flex-col justify-between">
                <div>
                  <h3 className="text-base font-bold text-cyber-text-primary">Community Scout</h3>
                  <p className="text-xs text-cyber-text-secondary mt-1">
                    Free for open-source contributors and individual researchers.
                  </p>
                  <div className="my-4">
                    <span className="text-3xl font-extrabold text-cyber-text-primary">$0</span>
                    <span className="text-xs text-cyber-text-muted"> / forever</span>
                  </div>
                  <ul className="space-y-2 text-xs text-cyber-text-secondary border-t border-cyber-border/40 pt-4">
                    <li className="flex items-center gap-2">
                      <CheckCircleIcon className="w-4 h-4 text-emerald-400 shrink-0" />
                      5 Recon Scans / month
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircleIcon className="w-4 h-4 text-emerald-400 shrink-0" />
                      1 Monitored Target Asset
                    </li>
                    <li className="flex items-center gap-2 text-cyber-text-muted">
                      No automated PDF exports
                    </li>
                  </ul>
                </div>
                <Button variant="outline" size="sm" className="mt-6 border-cyber-border text-xs" disabled>
                  Current Free Base
                </Button>
              </div>

              {/* Pro Tier */}
              <div className="p-6 rounded-lg bg-cyber-surface border border-cyber-border flex flex-col justify-between">
                <div>
                  <h3 className="text-base font-bold text-cyber-text-primary">Pro Red Teamer</h3>
                  <p className="text-xs text-cyber-text-secondary mt-1">
                    For boutique pentesting firms and independent security consultants.
                  </p>
                  <div className="my-4">
                    <span className="text-3xl font-extrabold text-cyber-text-primary">$299</span>
                    <span className="text-xs text-cyber-text-muted"> / month</span>
                  </div>
                  <ul className="space-y-2 text-xs text-cyber-text-secondary border-t border-cyber-border/40 pt-4">
                    <li className="flex items-center gap-2">
                      <CheckCircleIcon className="w-4 h-4 text-emerald-400 shrink-0" />
                      50 Full Port & Aggressive Scans
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircleIcon className="w-4 h-4 text-emerald-400 shrink-0" />
                      10 Monitored Attack Surfaces
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircleIcon className="w-4 h-4 text-emerald-400 shrink-0" />
                      Automated Executive PDF Reports
                    </li>
                  </ul>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => addToast("Plan selected", "info")}
                  className="mt-6 border-cyber-accent text-cyber-accent hover:bg-cyber-accent/10 text-xs"
                >
                  Switch to Pro
                </Button>
              </div>

              {/* Enterprise Tier */}
              <div className="p-6 rounded-lg bg-cyber-surface border-2 border-cyber-accent shadow-lg shadow-cyber-accent/10 flex flex-col justify-between relative overflow-hidden">
                <div className="absolute top-3 right-3">
                  <Badge variant="default" className="text-[10px] uppercase font-mono">Current Plan</Badge>
                </div>
                <div>
                  <h3 className="text-base font-bold text-cyber-text-primary">Enterprise MSSP</h3>
                  <p className="text-xs text-cyber-text-secondary mt-1">
                    Full AI neural engine, unlimited targets, and SOC 2 / SIEM forwarders.
                  </p>
                  <div className="my-4">
                    <span className="text-3xl font-extrabold text-cyber-accent">$1,499</span>
                    <span className="text-xs text-cyber-text-muted"> / month</span>
                  </div>
                  <ul className="space-y-2 text-xs text-cyber-text-secondary border-t border-cyber-border/40 pt-4">
                    <li className="flex items-center gap-2">
                      <CheckCircleIcon className="w-4 h-4 text-emerald-400 shrink-0" />
                      Unlimited Automated Scans & DAST
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircleIcon className="w-4 h-4 text-emerald-400 shrink-0" />
                      Real-time Splunk & SIEM Stream
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircleIcon className="w-4 h-4 text-emerald-400 shrink-0" />
                      Dedicated Red Team Advisor & 24/7 SLA
                    </li>
                  </ul>
                </div>
                <Button variant="primary" size="sm" className="mt-6 text-xs" disabled>
                  Active Subscription
                </Button>
              </div>
            </div>
          </div>
        </TabsContent>
      </Tabs>

      {/* Generate API Key Modal */}
      <Modal
        isOpen={isNewKeyModalOpen}
        onClose={() => setIsNewKeyModalOpen(false)}
        title={generatedKey ? "New API Key Created" : "Generate Programmatic API Key"}
      >
        {generatedKey ? (
          <div className="space-y-4 text-sm">
            <div className="p-3 bg-amber-950/40 border border-amber-500/30 rounded text-amber-200 text-xs">
              Make sure to copy your API key now. You will not be able to view this token again.
            </div>
            <div>
              <label className="block text-xs font-mono text-cyber-text-secondary mb-1">
                API TOKEN SECRET
              </label>
              <div className="flex items-center gap-2">
                <Input
                  value={generatedKey}
                  readOnly
                  className="font-mono text-xs bg-cyber-bg border-cyber-border text-cyber-accent select-all"
                />
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleCopy(generatedKey)}
                  className="shrink-0"
                >
                  <ClipboardDocumentIcon className="w-4 h-4" />
                </Button>
              </div>
            </div>
            <div className="flex justify-end pt-3 border-t border-cyber-border">
              <Button
                variant="primary"
                size="sm"
                onClick={() => setIsNewKeyModalOpen(false)}
              >
                Done
              </Button>
            </div>
          </div>
        ) : (
          <form onSubmit={handleGenerateKey} className="space-y-4 text-sm">
            <div>
              <label className="block text-xs font-medium text-cyber-text-secondary mb-1">
                Key Identifier / Label *
              </label>
              <Input
                placeholder="e.g. GitHub Actions Production Deployer"
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
                required
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-cyber-text-secondary mb-1">
                Scope Privilege Level
              </label>
              <Select
                value={newKeyScope}
                onChange={(e) => setNewKeyScope(e.target.value)}
                options={[
                  { label: "Full Enterprise Access (*)", value: "full_access" },
                  { label: "Scan Execution & Findings Read", value: "scans_only" },
                  { label: "Read-Only SIEM Exporter", value: "read_only" },
                ]}
              />
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-cyber-border">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setIsNewKeyModalOpen(false)}
              >
                Cancel
              </Button>
              <Button type="submit" variant="primary" size="sm">
                Generate Token
              </Button>
            </div>
          </form>
        )}
      </Modal>

      {/* Invite Member Modal */}
      <Modal
        isOpen={isInviteModalOpen}
        onClose={() => setIsInviteModalOpen(false)}
        title="Invite SOC Team Member"
      >
        <form onSubmit={handleInviteUser} className="space-y-4 text-sm">
          <div>
            <label className="block text-xs font-medium text-cyber-text-secondary mb-1">
              Work Email Address *
            </label>
            <Input
              type="email"
              placeholder="e.g. security.analyst@organization.com"
              value={inviteEmail}
              onChange={(e) => setInviteEmail(e.target.value)}
              required
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-cyber-text-secondary mb-1">
              Security Role
            </label>
            <Select
              value={inviteRole}
              onChange={(e) => setInviteRole(e.target.value as any)}
              options={[
                { label: "Security Analyst (Triage & Verify)", value: "Security Analyst" },
                { label: "Pentester (Execute Scans & DAST)", value: "Pentester" },
                { label: "Admin (Full System Config)", value: "Admin" },
                { label: "Auditor (Read-Only Attestation)", value: "Auditor" },
              ]}
            />
          </div>

          <div className="p-3 bg-cyber-bg rounded border border-cyber-border text-xs text-cyber-text-secondary flex items-start gap-2">
            <LockClosedIcon className="w-4 h-4 text-cyber-accent shrink-0 mt-0.5" />
            <span>
              Invited members will receive an encrypted verification email with instructions to configure hardware MFA before gaining access.
            </span>
          </div>

          <div className="flex justify-end gap-2 pt-3 border-t border-cyber-border">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setIsInviteModalOpen(false)}
            >
              Cancel
            </Button>
            <Button type="submit" variant="primary" size="sm">
              Send Secure Invitation
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
