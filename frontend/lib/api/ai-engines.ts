import { apiClient } from "./client";

export interface AIStatus {
  is_running: boolean;
  current_cycle: number;
  current_generation: number;
  timestamp: string;
}

export interface RedTeamAnalysisResult {
  analysis_type: string;
  analyzed_by: string;
  vulnerabilities_analyzed: number;
  attack_chains: Array<{
    target: string;
    initial_access: string;
    escalation_path: string[];
    final_objective: string;
  }>;
  timestamp: string;
}

export interface BlueTeamDefenseResult {
  analysis_type: string;
  analyzed_by: string;
  detection_strategies: Array<{
    vulnerability: string;
    detection_method: string;
    prevention_measures: string[];
    response_time: string;
  }>;
  timestamp: string;
}

export interface SecurityPosture {
  security_score: number;
  agent_adaptation: number;
  threats_detected_total: number;
  system_generation: number;
  timestamp: string;
}

export const aiEnginesApi = {
  startEvolution: async () => {
    const res = await apiClient.post("/v1/ai/evolution/start");
    return res.data;
  },

  getEvolutionStatus: async (): Promise<AIStatus> => {
    const res = await apiClient.get("/v1/ai/evolution/status");
    return res.data;
  },

  getAgentsStatus: async () => {
    const res = await apiClient.get("/v1/ai/agents/status");
    return res.data;
  },

  analyzeRedTeam: async (vulnerabilities: any[] = []): Promise<RedTeamAnalysisResult> => {
    const res = await apiClient.post("/v1/ai/red-team/analyze", { vulnerabilities });
    return res.data;
  },

  analyzeBlueTeam: async (vulnerabilities: any[] = []): Promise<BlueTeamDefenseResult> => {
    const res = await apiClient.post("/v1/ai/blue-team/analyze", { vulnerabilities });
    return res.data;
  },

  getSecurityPosture: async (): Promise<SecurityPosture> => {
    const res = await apiClient.get("/v1/ai/security/posture");
    return res.data;
  },

  scanYara: async (filename: string, content?: string) => {
    const res = await apiClient.post("/v1/malware/yara-scan", { filename, content });
    return res.data;
  },

  discoverSubdomains: async (domain: string) => {
    const res = await apiClient.post("/v1/recon/subdomains", { domain });
    return res.data;
  },
};
