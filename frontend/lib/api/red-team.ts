import { apiClient } from "./client";

export interface WellbeingPillar {
  id: string;
  name: string;
  weightPercent: number;
  score: number;
  status: "HEALTHY" | "WARNING" | "CRITICAL";
  deductions: string[];
}

export interface WellbeingScorecard {
  overallScore: number;
  letterGrade: string;
  threatIndex: string;
  summaryHeadline: string;
  pillars: WellbeingPillar[];
  strengths: string[];
  criticalExposures: any[];
  compliance?: {
    owaspTop10_2021: Record<string, string>;
    cisControlsV8: Record<string, string>;
  };
  generatedAt: string;
}

export interface TechStack {
  server: string | null;
  frameworks: string[];
  frontend: string[];
  cdn: string | null;
  detectedHeaders: string[];
}

export interface AssessmentBrain {
  createdAt: string;
  surfaceMatrix: Record<string, {
    status: "NOT_ASSESSED" | "PARTIALLY_ASSESSED" | "ASSESSED" | "VERIFIED";
    items: any[];
    assessedCount: number;
    verifiedCount: number;
    coveragePct: number;
  }>;
  questionQueue: Array<{
    id: string;
    target: string;
    question: string;
    securityProperty: string;
    assumption: string;
    provingEvidence: string;
    disprovingEvidence: string;
    derivedHypothesis: string;
    status: string;
  }>;
  authStateMachine: {
    states: string[];
    currentState: string;
    observedTransitions: any[];
    unexpectedTransitions: any[];
    sessionTokens: any[];
  };
  authorizationMatrix: Array<{
    identity: string;
    role: string;
    resource: string;
    action: string;
    expectedAccess: string;
    observedAccess: string;
    statusCode: number;
    inconsistent: boolean;
    evidenceQuality: string;
  }>;
  businessWorkflows: Array<{
    name: string;
    startState: string;
    requiredConditions: string[];
    targetPath: string;
    transitions: string[];
    authorization: string;
    finalState: string;
    invariantViolated: boolean;
    evidence?: string;
  }>;
  rootCauses: Array<{
    id: string;
    title: string;
    rootCause: string;
    category: string;
    severity: string;
    affectedComponents: string[];
    symptoms: any[];
  }>;
  attackPaths: Array<{
    source: string;
    target: string;
    relation: string;
    confidence: number;
    isConfirmed: boolean;
    evidenceStatus: string;
  }>;
  currentReasoning: {
    currentInvestigation: string;
    nextAction: string;
    why: string;
    updatedAt: string;
  };
  memoryStats: {
    totalAssets: number;
    totalServices: number;
    totalTechnologies: number;
    totalRoutes: number;
    totalEndpoints: number;
    decisionLogsCount: number;
  };
}

export interface RedTeamAssessment {
  id: string;
  scanId: string;
  phase: string;
  currentObjective: string;
  progress: number;
  status: string;
  startedAt: string;
  completedAt?: string;
  scope?: any;
  hypotheses?: any[];
  sessions?: any[];
  coverage?: any;
  events?: any[];
  scan?: any;
  wellbeingScorecard?: WellbeingScorecard;
  techStack?: TechStack;
  crawledPages?: any[];
  discoveredForms?: any[];
  discoveredApiRoutes?: any[];
  assessmentBrain?: AssessmentBrain;
}

export interface AttackGraphNode {
  id: string;
  label: string;
  category: "TARGET" | "ASSET" | "SERVICE" | "APPLICATION" | "ENDPOINT" | "VULNERABILITY" | "PRIVILEGE" | "ATTACK_PATH";
  severity?: string;
  status: string;
  properties?: Record<string, any>;
}

export interface AttackGraphEdge {
  source: string;
  target: string;
  relation: string;
  confidence: number;
  isCriticalPath: boolean;
}

export interface AttackGraphData {
  assessmentId: string;
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  stats: {
    totalNodes: number;
    totalEdges: number;
    criticalPaths: number;
  };
}

export interface LaunchAssessmentParams {
  target: string;
  scope?: {
    allowedDomains?: string[];
    allowedPorts?: number[];
    timeBudgetMinutes?: number;
    credentialTesting?: boolean;
    dataAccessPolicy?: string;
  };
  organizationId?: string;
}

export const redTeamApi = {
  launchAssessment: async (params: LaunchAssessmentParams): Promise<any> => {
    const res = await apiClient.post("/v1/red-team/assessments/launch", params);
    return res.data.data || res.data;
  },

  cancelAssessment: async (id: string, reason?: string): Promise<any> => {
    const res = await apiClient.post(`/v1/red-team/assessments/${id}/cancel`, { reason });
    return res.data.data || res.data;
  },

  getActiveAssessments: async (): Promise<any> => {
    try {
      const res = await apiClient.get("/v1/red-team/assessments/active");
      return res.data.data || res.data;
    } catch (e) {
      return { activeCount: 0, assessments: [] };
    }
  },

  getAssessment: async (id: string): Promise<RedTeamAssessment | null> => {
    try {
      const res = await apiClient.get(`/v1/red-team/assessments/${id}`);
      return res.data.data || res.data;
    } catch (e) {
      return null;
    }
  },

  getAttackGraph: async (id: string): Promise<AttackGraphData | null> => {
    try {
      const res = await apiClient.get(`/v1/red-team/assessments/${id}/graph`);
      return res.data.data || res.data;
    } catch (e) {
      return null;
    }
  },

  getEvents: async (id: string): Promise<any[]> => {
    try {
      const res = await apiClient.get(`/v1/red-team/assessments/${id}/events`);
      return res.data.data || res.data || [];
    } catch (e) {
      return [];
    }
  },

  getHypotheses: async (id: string): Promise<any> => {
    try {
      const res = await apiClient.get(`/v1/red-team/assessments/${id}/hypotheses`);
      return res.data.data || res.data;
    } catch (e) {
      return null;
    }
  },

  terminateSession: async (sessionId: string, reason?: string): Promise<any> => {
    const res = await apiClient.post(`/v1/red-team/sessions/${sessionId}/terminate`, { reason });
    return res.data.data || res.data;
  },

  requestVerificationSession: async (params: {
    assessmentId: string;
    target: string;
    findingId?: string;
    objective?: string;
    executionContext?: string;
    privilegeContext?: string;
    requestedActions?: string[];
    evidence?: any;
    ttlMinutes?: number;
  }): Promise<any> => {
    const res = await apiClient.post("/v1/red-team/sessions/request", params);
    return res.data.data || res.data;
  },

  authorizeVerificationSession: async (sessionId: string, params: {
    authorizedBy?: string;
    permittedActions?: string[];
    ttlMinutes?: number;
    authorizationNotes?: string;
  }): Promise<any> => {
    const res = await apiClient.post(`/v1/red-team/sessions/${sessionId}/authorize`, params);
    return res.data.data || res.data;
  },

  executeSessionAction: async (sessionId: string, params: {
    action: string;
    target?: string;
    findingId?: string;
    requestPayload?: any;
    expectedBehavior?: string;
    notes?: string;
  }): Promise<any> => {
    const res = await apiClient.post(`/v1/red-team/sessions/${sessionId}/execute-action`, params);
    return res.data.data || res.data;
  },

  getSessionDetails: async (sessionId: string): Promise<any> => {
    const res = await apiClient.get(`/v1/red-team/sessions/${sessionId}`);
    return res.data.data || res.data;
  },

  getProofObject: async (sessionId: string): Promise<ProofObject | null> => {
    const res = await apiClient.get(`/v1/red-team/sessions/${sessionId}/proof`);
    return res.data.data || res.data;
  },

  getProofMarkdownUrl: (sessionId: string): string => {
    return `/api/v1/red-team/sessions/${sessionId}/proof?format=markdown`;
  },

  getReport: async (id: string): Promise<any> => {
    const res = await apiClient.get(`/v1/red-team/assessments/${id}/report`);
    return res.data.data || res.data;
  },

  getReportMarkdownUrl: (id: string): string => {
    return `/api/v1/red-team/assessments/${id}/report/markdown`;
  },

  handoffToBlueTeam: async (id: string): Promise<any> => {
    const res = await apiClient.post(`/v1/red-team/assessments/${id}/handoff-blue-team`);
    return res.data.data || res.data;
  }
};

export interface EvidenceChainItem {
  id: string;
  timestamp: string;
  action: string;
  target: string;
  findingId?: string;
  request: any;
  response: any;
  expectedBehavior: string;
  observedBehavior: string;
  prevHash: string;
  hash: string;
}

export interface ProofObject {
  proofId: string;
  assessmentId: string;
  sessionToken: string;
  findingId: string;
  verificationStatus: string;
  target: string;
  objective: string;
  authorizedBy: string;
  authorizedAt: string;
  expiresAt: string;
  allowlist: string[];
  evidenceChain: EvidenceChainItem[];
  chainLength: number;
  tamperEvidentSignature: string;
  integrityVerified: boolean;
  baselineBehavior: {
    expected: string;
    policyEnforced: boolean;
  };
  observedBehavior: {
    confirmed: boolean;
    findingContext: string;
    telemetrySummary: string;
  };
  reproducibilitySteps: Array<{
    step: number;
    title: string;
    command: string;
    purpose: string;
  }>;
  generatedAt: string;
}

