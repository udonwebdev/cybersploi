import { apiClient } from "./client";

export interface Engagement {
  id: string;
  name: string;
  status: string;
  environment: string;
  currentPhase: string;
  startedAt: string;
  endedAt?: string;
  scope?: ScopeConfig;
  findings?: Finding[];
  transitions?: StateTransition[];
  attackPaths?: AttackPath[];
}

export interface ScopeConfig {
  id: string;
  engagementId: string;
  allowedTargets: string; // JSON array string
  allowedTestTypes: string; // JSON array string
  destructiveActionsAllowed: boolean;
  activePoCAllowed: boolean;
  rateLimit: number;
  concurrencyLimit: number;
  validFrom: string;
  validUntil: string;
  environment: string;
  approvedBy: string;
  approvalRecordUrl?: string;
}

export interface Finding {
  id: string;
  engagementId: string;
  title: string;
  description?: string;
  category: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  target: string;
  status: "SUSPECTED" | "TESTED" | "VALIDATED" | "PROVEN" | "DISPROVEN" | "INCONCLUSIVE";
  reproducible: boolean;
  hypothesisId?: string;
  evidence?: Evidence[];
  createdAt: string;
  updatedAt: string;
}

export interface Evidence {
  id: string;
  findingId: string;
  actionId: string;
  target: string;
  timestamp: string;
  requestMetadata: string;
  responseMetadata: string;
  responseBodyData?: string;
  observation: string;
  reproductionSteps?: string;
  authContext: string;
  workerResult?: string;
  hash: string;
  isImmutable: boolean;
  previousEvidenceId?: string;
  createdAt: string;
}

export interface AuthMatrixRecord {
  id: string;
  engagementId: string;
  assetId: string;
  operation: string;
  role: string;
  subjectIdentity?: string;
  objectIdentity?: string;
  expected: "ALLOWED" | "DENIED" | "UNKNOWN";
  observed: "ALLOWED" | "DENIED" | "UNKNOWN";
  result: "MATCH" | "DISCREPANCY" | "UNTESTED";
  evidenceId?: string;
  findingId?: string;
}

export interface AttackPath {
  id: string;
  engagementId: string;
  title: string;
  description?: string;
  status: "HYPOTHESIZED" | "INCOMPLETE" | "DEMONSTRATED";
  findingsOrder: string;
  transitions: {
    id: string;
    fromFinding: { id: string; title: string; severity: string };
    toFinding: { id: string; title: string; severity: string };
    evidence?: { id: string; hash: string };
    hasValidEvidence: boolean;
  }[];
}

export interface TelemetryEvent {
  id?: string;
  engagementId: string;
  TARGET: string;
  SESSION: string;
  ACTION: string;
  REQUEST?: any;
  RESPONSE?: any;
  OBSERVATION: string;
  DECISION: string;
  NEXT_TEST?: string;
  severity?: string;
  timestamp: string;
}

export interface StateTransition {
  id: string;
  previousState: string;
  newState: string;
  timestamp: string;
  actor: string;
  reason: string;
}

export interface GroundedFacts {
  observed: string[];
  inferred: string[];
  hypothesized: string[];
  confirmed: string[];
  unknown: string[];
}

export interface CopilotResponse {
  query: string;
  engagementId: string;
  summary: string;
  detailedAnalysis: string;
  groundedFacts: GroundedFacts;
  attackPathsSummary?: {
    totalPaths: number;
    demonstratedPaths: number;
    criticalCrownJewelPaths: string[];
  };
  remediationActionItems: Array<{
    findingId: string;
    title: string;
    severity: string;
    priority: string;
    patchGuidance: string;
    regressionCommand: string;
  }>;
  groundingCitations: Array<{
    type: string;
    id: string;
    reference: string;
  }>;
  timestamp: string;
}

export interface RemediationGuidance {
  findingId: string;
  title: string;
  severity: string;
  affectedComponent: string;
  rootCauseAnalysis: string;
  remediationRecommendation: string;
  secureConfigurationGuidance: string;
  developerGuidance: string;
  patchDiff: string;
  verificationProcedure: string;
  regressionTestCommand: string;
}

export interface Graph3DNode {
  id: string;
  nodeType: string;
  nodeKey: string;
  label: string;
  properties: Record<string, any>;
  x: number;
  y: number;
  z: number;
  color: string;
  size: number;
}

export interface Graph3DEdge {
  id: string;
  fromNodeId: string;
  toNodeId: string;
  edgeType: string;
  weight: number;
  evidenceId?: string;
  properties?: Record<string, any>;
  color: string;
}

export interface Graph3DResponse {
  engagementId: string;
  nodes: Graph3DNode[];
  edges: Graph3DEdge[];
  metrics: {
    totalNodes: number;
    totalEdges: number;
    vulnerabilityCount: number;
    evidenceCount: number;
    attackPathCount: number;
    demonstratedChains: number;
  };
}

export interface TelemetryStatusResponse {
  circuitBreakerState: "CLOSED" | "THROTTLED" | "OPEN";
  currentConcurrency: number;
  report: {
    timestamp: string;
    windowSize: number;
    error5xxRatePercent: number;
    p95LatencyMs: number;
    rateLimitEventsCount: number;
    circuitBreakerState: "CLOSED" | "THROTTLED" | "OPEN";
    suggestedConcurrency: number;
    anomaliesDetected: string[];
  };
}

export interface InvariantDefinition {
  id: string;
  title: string;
  status: "ENFORCED" | "TRIPPED";
  description: string;
}

export interface HarnessMetricsResponse {
  corpusSize: number;
  evaluationsRun: number;
  jailbreakResistanceRate: number;
  invariants: InvariantDefinition[];
}

export interface CanonicalFinding {
  id: string;
  title: string;
  category: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  status: string;
  target: string;
  reproducible: boolean;
  confidence: number;
  description: string;
  impact: string;
  rootCause?: string;
  remediation?: string;
  evidenceCount: number;
  evidenceChain: {
    evidenceId: string;
    actionId: string;
    timestamp: string;
    observation: string;
    reproductionSteps: string;
    hash: string;
  }[];
}

export interface CanonicalEngagementReport {
  schemaVersion: string;
  reportId: string;
  generatedAt: string;
  scope: "executive" | "technical" | "finding_level" | "forensic";
  format: "json" | "html" | "pdf" | "csv" | "markdown" | "sarif";
  redacted: boolean;
  engagement: {
    id: string;
    name: string;
    environment: string;
    currentPhase: string;
    startedAt: string;
    endedAt: string;
    organization: string;
  };
  authorization: {
    approvedBy: string;
    approvalRecordUrl?: string;
    allowedTargets: any[];
    allowedTestTypes: string[];
    rateLimit: number;
    destructiveActionsAllowed: boolean;
    activePoCAllowed: boolean;
  };
  executiveSummary: {
    title: string;
    overallPosture: "CRITICAL_RISK" | "HIGH_RISK" | "MEDIUM_RISK" | "CONTROLLED";
    totalFindings: number;
    provenVulnerabilities: number;
    validatedVulnerabilities: number;
    remediatedVulnerabilities: number;
    untestedHypotheses: number;
    crownJewelExposureCount: number;
    summary: string;
  };
  assets: {
    id: string;
    host: string;
    port?: number;
    protocol?: string;
    verificationStatus: string;
    trustZone?: string;
  }[];
  findings: CanonicalFinding[];
  attackPaths: {
    id: string;
    title: string;
    status: string;
    isDemonstrated: boolean;
    hopCount: number;
    transitions: {
      from: string;
      to: string;
      hasValidEvidence: boolean;
      evidenceHash?: string;
    }[];
  }[];
  crownJewels: {
    nodeKey: string;
    name: string;
    criticality: string;
    trustZone: string;
    reachablePathsCount: number;
  }[];
  remediations: {
    findingId: string;
    affectedComponent: string;
    patchDiff?: string;
    regressionCommand?: string;
    status: "PENDING" | "VERIFIED" | "REVALIDATED";
  }[];
  auditTrail: {
    action: string;
    decision: string;
    reason: string;
    timestamp: string;
  }[];
  integrity: {
    algorithm: "SHA-256";
    hash: string;
  };
  sections?: any;
}

export interface ReportDiffResult {
  baseReportId: string;
  targetReportId: string;
  timestamp: string;
  newFindings: { id: string; title: string; severity: string }[];
  resolvedFindings: { id: string; title: string }[];
  changedSeverity: { id: string; title: string; oldSeverity: string; newSeverity: string }[];
  netRiskScoreChange: number;
  summary: string;
}

export const offensiveEngineApi = {
  getEngagements: async (): Promise<Engagement[]> => {
    const res = await apiClient.get("/engagements");
    return res.data;
  },

  getEngagement: async (id: string): Promise<Engagement> => {
    const res = await apiClient.get(`/engagements/${id}`);
    return res.data;
  },

  createEngagement: async (data: {
    name: string;
    environment: string;
    scope: {
      allowedTargets: string[];
      allowedTestTypes: string[];
      rateLimit?: number;
      concurrencyLimit?: number;
      destructiveActionsAllowed?: boolean;
      activePoCAllowed?: boolean;
      validFrom: string;
      validUntil: string;
      approvedBy: string;
    };
  }): Promise<Engagement> => {
    const res = await apiClient.post("/engagements", data);
    return res.data;
  },

  transitionPhase: async (
    id: string,
    newState: string,
    reason: string,
    actor: string = "SecOps Lead"
  ): Promise<any> => {
    const res = await apiClient.post(`/engagements/${id}/transition`, {
      newState,
      reason,
      actor,
    });
    return res.data;
  },

  triggerGauntlet: async (
    id: string,
    hypothesis: {
      findingId?: string;
      title: string;
      target: string;
      testType: string;
      initialAction: string;
      initialRequest?: any;
      maxIterations?: number;
      timeoutMs?: number;
    }
  ): Promise<any> => {
    const res = await apiClient.post(`/engagements/${id}/gauntlet`, hypothesis);
    return res.data;
  },

  executeGauntlet: async (id: string, params: any): Promise<any> => {
    const res = await apiClient.post(`/engagements/${id}/gauntlet`, params);
    return res.data;
  },

  getFindings: async (id: string, status?: string): Promise<Finding[]> => {
    const res = await apiClient.get(`/engagements/${id}/findings`, {
      params: status ? { status } : undefined,
    });
    const data = res.data?.data !== undefined ? res.data.data : res.data;
    return Array.isArray(data) ? data : [];
  },

  getFindingEvidence: async (id: string, findingId?: string): Promise<Evidence[]> => {
    const res = await apiClient.get(`/engagements/${id}/evidence`, {
      params: findingId ? { findingId } : undefined,
    });
    const data = res.data?.data !== undefined ? res.data.data : res.data;
    return Array.isArray(data) ? data : [];
  },

  getAuthMatrix: async (id: string): Promise<AuthMatrixRecord[]> => {
    const res = await apiClient.get(`/engagements/${id}/auth-matrix`);
    const data = res.data?.data !== undefined ? res.data.data : res.data;
    return Array.isArray(data) ? data : [];
  },

  getAttackPaths: async (id: string): Promise<AttackPath[]> => {
    const res = await apiClient.get(`/engagements/${id}/attack-paths`);
    const data = res.data?.data !== undefined ? res.data.data : res.data;
    return Array.isArray(data) ? data : [];
  },

  getEvents: async (id: string): Promise<TelemetryEvent[]> => {
    const res = await apiClient.get(`/engagements/${id}/events`);
    const data = res.data?.data !== undefined ? res.data.data : res.data;
    return Array.isArray(data) ? data : [];
  },

  getReport: async (id: string, format: "json" | "html" = "json"): Promise<any> => {
    const res = await apiClient.get(`/engagements/${id}/report`, {
      params: { format },
    });
    return res.data;
  },

  queryCopilot: async (id: string, query: string): Promise<CopilotResponse> => {
    const res = await apiClient.post(`/engagements/${id}/copilot/query`, { query });
    return res.data;
  },

  getRemediation: async (id: string, findingId: string): Promise<{ success: boolean; remediation: RemediationGuidance }> => {
    const res = await apiClient.post(`/engagements/${id}/copilot/remediation`, { findingId });
    return res.data;
  },

  getGraph3D: async (id: string): Promise<Graph3DResponse> => {
    const res = await apiClient.get(`/engagements/${id}/graph/3d`);
    return res.data.graph;
  },

  getTelemetryStatus: async (id?: string): Promise<TelemetryStatusResponse> => {
    const url = id ? `/engagements/${id}/telemetry/status` : `/engagements/telemetry/status`;
    const res = await apiClient.get(url);
    return res.data;
  },

  resetCircuitBreaker: async (id?: string): Promise<any> => {
    const url = id ? `/engagements/${id}/telemetry/circuit-breaker/reset` : `/engagements/telemetry/circuit-breaker/reset`;
    const res = await apiClient.post(url);
    return res.data;
  },

  evaluateHarness: async (id: string, payload: string, category?: string): Promise<any> => {
    const res = await apiClient.post(`/engagements/${id}/harness/evaluate`, { payload, category });
    return res.data;
  },

  getHarnessMetrics: async (): Promise<HarnessMetricsResponse> => {
    const res = await apiClient.get(`/engagements/harness/metrics`);
    return res.data;
  },

  runHarnessTests: async (): Promise<any> => {
    const res = await apiClient.post(`/engagements/harness/run-tests`);
    return res.data;
  },

  solveAuthReachability: async (id: string, query: any, policies?: any[]): Promise<any> => {
    const res = await apiClient.post(`/engagements/${id}/auth-matrix/reachability`, { query, policies });
    return res.data;
  },

  // -------------------------------------------------------------
  // Phase 3: AIM OMEGA-X Autonomous Cognitive Architecture APIs
  // -------------------------------------------------------------
  runOmegaCycle: async (id: string, budget?: any): Promise<any> => {
    const res = await apiClient.post(`/engagements/${id}/omega/run`, budget || {});
    return res.data;
  },

  runFindingDebate: async (id: string, debateData: any): Promise<any> => {
    const res = await apiClient.post(`/engagements/${id}/omega/debate`, debateData);
    return res.data;
  },

  computeInfoGainPlan: async (id: string): Promise<any> => {
    const res = await apiClient.post(`/engagements/${id}/omega/plan`);
    return res.data;
  },

  runRedBlueArena: async (id: string, generations: number = 2, seeds: number = 4): Promise<any> => {
    const res = await apiClient.post(`/engagements/${id}/omega/arena/evolve`, { generations, seeds });
    return res.data;
  },

  runChaosTest: async (id?: string): Promise<any> => {
    const url = id ? `/engagements/${id}/omega/chaos/test` : `/chaos/test`;
    const res = await apiClient.post(url);
    return res.data;
  },

  // -------------------------------------------------------------
  // Phase 4: CYBERSPLOI ∞ Infinite Loop Architecture APIs
  // -------------------------------------------------------------
  getRepoIntelligence: async (): Promise<any> => {
    const res = await apiClient.get('/engagements/repo-intelligence');
    return res.data;
  },

  planTaskDecomposer: async (directive: string, context?: any): Promise<any> => {
    const res = await apiClient.post('/engagements/task-decomposer/plan', { directive, context });
    return res.data;
  },

  executeTaskDecomposer: async (dag: any): Promise<any> => {
    const res = await apiClient.post('/engagements/task-decomposer/execute', { dag });
    return res.data;
  },

  createGraphSnapshot: async (id: string): Promise<any> => {
    const res = await apiClient.post(`/engagements/${id}/graph/snapshot`);
    return res.data;
  },

  getGraphSnapshots: async (id: string): Promise<any> => {
    const res = await apiClient.get(`/engagements/${id}/graph/snapshots`);
    return res.data;
  },

  diffGraphSnapshots: async (id: string, baseSnapshotId: string, targetSnapshotId: string): Promise<any> => {
    const res = await apiClient.post(`/engagements/${id}/graph/diff`, { baseSnapshotId, targetSnapshotId });
    return res.data;
  },

  computeCrownJewelReachability: async (id: string, customJewels?: any[]): Promise<any> => {
    const res = await apiClient.post(`/engagements/${id}/crown-jewels/reachability`, { customJewels });
    return res.data;
  },

  emitFabricEvent: async (id: string, eventData: any): Promise<any> => {
    const res = await apiClient.post(`/engagements/${id}/event-fabric/emit`, eventData);
    return res.data;
  },

  getFabricTelemetry: async (id: string): Promise<any> => {
    const res = await apiClient.get(`/engagements/${id}/event-fabric/telemetry`);
    return res.data;
  },

  generateSelfRegression: async (id: string, regressionData: any): Promise<any> => {
    const res = await apiClient.post(`/engagements/${id}/self-regression/generate`, regressionData);
    return res.data;
  },

  getSelfRegressionFixtures: async (id: string): Promise<any> => {
    const res = await apiClient.get(`/engagements/${id}/self-regression/fixtures`);
    return res.data;
  },

  checkSyntheticTargets: async (id: string): Promise<any> => {
    const res = await apiClient.post(`/engagements/${id}/self-regression/check`);
    return res.data;
  },

  // -------------------------------------------------------------
  // Phase 5: Enterprise Reporting & Evidence APIs (Section 16)
  // -------------------------------------------------------------
  getCanonicalReport: async (id: string, scope: string = "technical", redact: boolean = true): Promise<CanonicalEngagementReport> => {
    const res = await apiClient.get(`/engagements/${id}/report/canonical?scope=${scope}&redact=${redact}`);
    return res.data.data;
  },

  exportReport: async (id: string, format: string = "json", scope: string = "technical", redact: boolean = true): Promise<any> => {
    const res = await apiClient.get(`/engagements/${id}/report/export?format=${format}&scope=${scope}&redact=${redact}`);
    return res.data;
  },

  getReportDownloadUrl: (id: string, format: string = "pdf", scope: string = "technical", redact: boolean = true): string => {
    return `/engagements/${id}/report/export?format=${format}&scope=${scope}&redact=${redact}&download=true`;
  },

  diffReports: async (id: string, baseReport?: any, targetReport?: any, previousReport?: any): Promise<ReportDiffResult> => {
    const res = await apiClient.post(`/engagements/${id}/report/diff`, { baseReport, targetReport, previousReport });
    return res.data.data;
  },

  // -------------------------------------------------------------
  // Autonomous Agent Coordinator Services (All Security Engines)
  // -------------------------------------------------------------
  getAgents: async (id: string): Promise<any> => {
    const res = await apiClient.get(`/engagements/${id}/agents`);
    return res.data;
  },

  runAgent: async (id: string, agentName: string, target?: string): Promise<any> => {
    const res = await apiClient.post(`/engagements/${id}/agents/run`, { agentName, target });
    return res.data;
  },
};



