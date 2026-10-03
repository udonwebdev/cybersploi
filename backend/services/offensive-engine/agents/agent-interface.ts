import { ScopeGuardService, ScopeAction } from '../../scope-guard/scope-guard.service';

export interface AgentContext {
  engagementId: string;
  target: string;
  scope: any;
  parameters?: Record<string, any>;
  authContext?: Record<string, any>;
}

export interface AgentResult {
  agentName: string;
  actionId: string;
  target: string;
  success: boolean;
  decision: string;
  observation: string;
  evidenceData?: any;
  discoveredNodes?: { type: string; key: string; label: string; properties?: any }[];
  discoveredEdges?: { from: string; to: string; type: string }[];
  reproductionSteps?: string;
  error?: string;
}

export interface SecurityAgent {
  name: string;
  version: string;
  role: string;
  capabilities: string[];
  requiredScopeTypes: string[];
  allowedTestTypes: string[];
  riskLevel: 'PASSIVE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

  /**
   * Execute agent workflow, strictly gated through ScopeGuard
   */
  run(context: AgentContext): Promise<AgentResult>;
}
