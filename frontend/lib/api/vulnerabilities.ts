import { apiClient } from "./client";

export interface Vulnerability {
  id: string;
  title: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  cvss: number;
  status: "OPEN" | "RESOLVED" | "FALSE_POSITIVE" | "IN_PROGRESS";
  target: string;
  remediation?: string;
  cve?: string;
  cwe?: string;
  createdAt: string;
  updatedAt?: string;
}

export const vulnerabilitiesApi = {
  getVulnerabilities: async (): Promise<Vulnerability[]> => {
    const res = await apiClient.get("/v1/vulnerabilities");
    const list = res.data.data || res.data.vulnerabilities || res.data || [];
    return Array.isArray(list) ? list : [];
  },

  getVulnerabilityById: async (id: string): Promise<Vulnerability> => {
    const res = await apiClient.get(`/v1/vulnerabilities/${id}`);
    return res.data.data || res.data.vulnerability || res.data;
  },

  updateStatus: async (id: string, status: string): Promise<Vulnerability> => {
    const res = await apiClient.patch(`/v1/vulnerabilities/${id}/status`, { status });
    return res.data.data || res.data;
  },
};
