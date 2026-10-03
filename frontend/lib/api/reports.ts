import { apiClient } from "./client";

export interface ReportItem {
  id: string;
  title: string;
  reportType: "executive_summary" | "detailed_findings" | "compliance" | "trend_analysis";
  format: "pdf" | "json" | "docx" | "html";
  status: "ready" | "processing" | "failed" | "archived";
  scansIncluded: number;
  vulnerabilitiesFound: number;
  criticalCount: number;
  highCount: number;
  targetAsset?: string;
  complianceStandard?: string;
  createdAt: string;
  downloadUrl?: string;
  fileSizeBytes?: number;
}

export interface CreateReportPayload {
  title: string;
  reportType: "executive_summary" | "detailed_findings" | "compliance" | "trend_analysis";
  format: "pdf" | "json" | "docx" | "html";
  scanIds: string[];
  includeRemediation: boolean;
  includeCweMapping: boolean;
  includeCvssScoring: boolean;
  targetAsset?: string;
}

export const reportsApi = {
  getReports: async (): Promise<ReportItem[]> => {
    const res = await apiClient.get("/v1/reports");
    const list = res.data.data || res.data.reports || res.data || [];
    return Array.isArray(list) ? list : [];
  },

  createReport: async (payload: CreateReportPayload): Promise<ReportItem> => {
    const res = await apiClient.post("/v1/reports", payload);
    return res.data.data || res.data.report || res.data;
  },

  deleteReport: async (id: string): Promise<void> => {
    await apiClient.delete(`/v1/reports/${id}`);
  },
};
