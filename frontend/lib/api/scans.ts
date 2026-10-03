import { apiClient } from "./client";

export interface Scan {
  id: string;
  name: string;
  target: string;
  type: "RECON" | "VULNERABILITY" | "FULL_PORT" | "AGGRESSIVE";
  status: "pending" | "running" | "completed" | "failed";
  progress: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  findings: number;
  startedAt?: string;
  completedAt?: string;
  createdAt: string;
  logs?: string[];
  vulnerabilities?: any[];
  redTeamAssessment?: any;
  asset?: any;
  results?: any;
}

export const scansApi = {
  getScans: async (): Promise<Scan[]> => {
    const res = await apiClient.get("/v1/scans");
    const raw = res.data.data || res.data.scans || res.data;
    const list = Array.isArray(raw) ? raw : (raw?.scans || raw?.data || []);
    return Array.isArray(list) ? list : [];
  },

  getScanById: async (id: string): Promise<Scan> => {
    const res = await apiClient.get(`/v1/scans/${id}`);
    return res.data.data || res.data;
  },

  initiateScan: async (payload: {
    target: string;
    scanType: string;
    name?: string;
    profile?: string;
  }): Promise<Scan> => {
    const res = await apiClient.post("/v1/scans/initiate", payload);
    return res.data.data || res.data;
  },
};
