import { apiClient } from "./client";

export interface RiskPredictionResult {
  risk_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  confidence: number;
  score: number;
  model: string;
  recommendation?: string;
}

export interface MalwareAnalysisResult {
  classification: "MALICIOUS" | "BENIGN";
  confidence: number;
  malicious: boolean;
  model: string;
}

export interface CVSSScoreResult {
  cvss_score: number;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";
  model: string;
}

export const aiApi = {
  predictRisk: async (features: number[], target?: string): Promise<RiskPredictionResult> => {
    const res = await apiClient.post("/v1/predict-risk", { features, target });
    return res.data;
  },

  analyzeMalware: async (features: number[], fileHash?: string, fileName?: string): Promise<MalwareAnalysisResult> => {
    const res = await apiClient.post("/v1/analyze-malware", { features, file_hash: fileHash, file_name: fileName });
    return res.data;
  },

  calculateCVSS: async (features: number[], vulnerabilityId?: string): Promise<CVSSScoreResult> => {
    const res = await apiClient.post("/v1/cvss-score", { features, vulnerability_id: vulnerabilityId });
    return res.data;
  },
};
