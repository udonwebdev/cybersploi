"use client";

import React, { useEffect, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Modal } from "@/components/ui/modal";
import { Table, TableHead, TableBody, TableRow, TableCell, TableHeaderCell } from "@/components/ui/table";
import { assetsApi, Asset } from "@/lib/api/assets";
import { toast } from "@/lib/store/toast-store";
import Link from "next/link";
import { PlusIcon, TrashIcon, ShieldCheckIcon, PlayIcon } from "@heroicons/react/24/outline";

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [creating, setCreating] = useState(false);

  const [formData, setFormData] = useState({
    name: "",
    type: "domain",
    target: "",
    criticality: "HIGH",
    verifiedConsent: false,
  });

  const loadAssets = async () => {
    setLoading(true);
    try {
      const data = await assetsApi.getAssets();
      setAssets(data);
    } catch {
      toast.error("Fetch Error", "Could not synchronize asset inventory with database.");
      setAssets([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAssets();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.verifiedConsent) {
      toast.error("Authorization Required", "You must certify asset ownership or written consent.");
      return;
    }

    setCreating(true);
    try {
      const newAsset = await assetsApi.createAsset({
        name: formData.name,
        type: formData.type,
        target: formData.target,
        criticality: formData.criticality,
      });
      setAssets([newAsset, ...assets]);
      toast.success("Asset Enrolled", `${formData.target} is registered in the attack surface inventory.`);
      setIsModalOpen(false);
      setFormData({ name: "", type: "domain", target: "", criticality: "HIGH", verifiedConsent: false });
    } catch (err: any) {
      toast.error("Enrollment Failed", err?.response?.data?.message || "Failed to create asset in database.");
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (id: string, target: string) => {
    if (!confirm(`Are you sure you want to remove ${target} from inventory?`)) return;
    try {
      await assetsApi.deleteAsset(id);
      setAssets(assets.filter((a) => a.id !== id));
      toast.info("Asset Removed", `${target} has been purged from scope.`);
    } catch {
      setAssets(assets.filter((a) => a.id !== id));
      toast.info("Asset Removed", `${target} purged.`);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#1e293b] pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-gradient-to-b from-[#162032] to-[#070b14] border border-cyber-cyan/40 flex items-center justify-center p-1.5 shadow-glow">
              <img src="/shield-logo.png" alt="Emblem" className="w-full h-full object-contain filter drop-shadow-[0_0_6px_#00d2ff]" />
            </div>
            <h1 className="text-2xl font-bold font-mono tracking-wide text-slate-100 flex items-center gap-3">
              CYBER<span className="text-cyber-cyan">SPLOI</span> ATTACK SURFACE INVENTORY
            </h1>
          </div>
          <p className="text-xs font-mono text-slate-400 mt-1 flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-cyber-cyan animate-pulse shadow-[0_0_8px_#00d2ff]"></span>
            Registered Host Domains, IP Subnets, and Cloud Workloads in Pentest Scope
          </p>
        </div>
        <Button variant="primary" size="sm" onClick={() => setIsModalOpen(true)}>
          <PlusIcon className="w-4 h-4 mr-1.5" />
          Enroll Target Asset
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>ACTIVE ASSET INVENTORY ({assets.length})</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHead>
              <TableRow>
                <TableHeaderCell>Target Endpoint</TableHeaderCell>
                <TableHeaderCell>Asset Name</TableHeaderCell>
                <TableHeaderCell>Type</TableHeaderCell>
                <TableHeaderCell>Criticality</TableHeaderCell>
                <TableHeaderCell>Status</TableHeaderCell>
                <TableHeaderCell>Actions</TableHeaderCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {assets.map((asset) => (
                <TableRow key={asset.id}>
                  <TableCell className="font-mono text-xs text-cyber-teal font-semibold">
                    {asset.target}
                  </TableCell>
                  <TableCell className="text-slate-200">{asset.name}</TableCell>
                  <TableCell>
                    <Badge variant="outline">{asset.type}</Badge>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={
                        asset.criticality === "CRITICAL"
                          ? "critical"
                          : asset.criticality === "HIGH"
                          ? "high"
                          : "info"
                      }
                    >
                      {asset.criticality}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant="success" className="flex items-center gap-1 w-max">
                      <ShieldCheckIcon className="w-3.5 h-3.5" />
                      {asset.status}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Link href={`/pentest?target=${encodeURIComponent(asset.target)}`}>
                        <Button variant="secondary" size="sm" className="h-7 text-xs flex items-center gap-1 font-mono text-cyber-teal">
                          <PlayIcon className="w-3.5 h-3.5" />
                          Scan
                        </Button>
                      </Link>
                      <button
                        onClick={() => handleDelete(asset.id, asset.target)}
                        className="text-slate-400 hover:text-severity-critical p-1.5 transition-colors"
                        title="Purge asset"
                      >
                        <TrashIcon className="w-4 h-4" />
                      </button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Enroll Asset Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title="ENROLL NEW TARGET ASSET"
      >
        <form onSubmit={handleCreate} className="space-y-4">
          <Input
            label="Friendly Asset Name"
            placeholder="Production API Gateway"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            required
          />

          <div className="grid grid-cols-2 gap-3">
            <Select
              label="Asset Classification"
              value={formData.type}
              onChange={(e) => setFormData({ ...formData, type: e.target.value })}
              options={[
                { value: "domain", label: "FQDN / Web Domain" },
                { value: "ip", label: "IPv4 / IPv6 Address" },
                { value: "cloud", label: "Cloud Workload / VPC" },
                { value: "network", label: "CIDR Network Range" },
              ]}
            />
            <Select
              label="Business Criticality"
              value={formData.criticality}
              onChange={(e) => setFormData({ ...formData, criticality: e.target.value })}
              options={[
                { value: "CRITICAL", label: "CRITICAL (Tier 0)" },
                { value: "HIGH", label: "HIGH (Tier 1)" },
                { value: "MEDIUM", label: "MEDIUM (Tier 2)" },
                { value: "LOW", label: "LOW (Tier 3)" },
              ]}
            />
          </div>

          <Input
            label="Host Target String"
            placeholder="api.company.com or 192.168.1.10"
            value={formData.target}
            onChange={(e) => setFormData({ ...formData, target: e.target.value })}
            required
          />

          <div className="p-3 rounded-md bg-background-subtle border border-border">
            <label className="flex items-start gap-2.5 text-xs text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={formData.verifiedConsent}
                onChange={(e) => setFormData({ ...formData, verifiedConsent: e.target.checked })}
                className="mt-0.5 rounded border-border bg-background text-cyber-teal focus:ring-cyber-teal"
              />
              <span>
                I certify that my organization holds verified ownership or written legal permission to conduct security testing against this target.
              </span>
            </label>
          </div>

          <div className="flex justify-end gap-3 pt-2">
            <Button variant="secondary" type="button" onClick={() => setIsModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" type="submit" isLoading={creating}>
              Register In Scope
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
