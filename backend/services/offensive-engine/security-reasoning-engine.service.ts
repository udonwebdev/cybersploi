import * as crypto from 'crypto';
import prisma from '../../config/database';
import { SecurityGraphService } from './security-graph.service';
import { AgentCoordinatorService } from './agents';
import { ScopeGuardService } from '../scope-guard/scope-guard.service';
import { FindingEvidenceService } from './finding-evidence.service';
import { SecurityKnowledgeBase } from './knowledge-base.service';

export type ReasoningStep =
  | 'DISCOVER'
  | 'MAP'
  | 'MODEL'
  | 'UNDERSTAND'
  | 'HYPOTHESIZE'
  | 'PRIORITIZE'
  | 'TEST'
  | 'OBSERVE'
  | 'CORRELATE'
  | 'VALIDATE'
  | 'VERIFY'
  | 'CHAIN'
  | 'EVIDENCE'
  | 'REPORT'
  | 'RETEST'
  | 'LEARN'
  | 'REASSESS';

export interface CandidateAction {
  id: string;
  step: ReasoningStep;
  target: string;
  testType: string;
  agentName: string;
  hypothesis: string;
  priorityScore: number;
  parameters?: Record<string, any>;
  riskLevel: string;
}

export interface ReasoningIterationResult {
  iterationId: string;
  engagementId: string;
  stepExecuted: ReasoningStep;
  candidateActions: CandidateAction[];
  executedAction?: CandidateAction;
  decision: string;
  observation?: string;
  newNodesDiscovered: number;
  newEdgesDiscovered: number;
  untestedSurfaceRemaining: number;
  timestamp: string;
}

export class SecurityReasoningEngine {
  /**
   * Evaluates the current Omniscient Security Graph and determines the next optimal action.
   * AI/heuristics propose -> Deterministic Orchestrator decides -> ScopeGuard authorizes -> Execution proceeds.
   */
  public static async executeReasoningStep(
    engagementId: string,
    forcedTarget?: string
  ): Promise<ReasoningIterationResult> {
    const iterationId = `reason-${crypto.randomBytes(4).toString('hex')}`;

    // 1. Synchronize & fetch current state of the Omniscient Graph
    const graphData = await SecurityGraphService.getOmniscientGraph3D(engagementId);
    const engagement = await prisma.engagement.findUnique({
      where: { id: engagementId },
      include: { scope: true }
    });

    if (!engagement || !engagement.scope) {
      throw new Error(`Engagement ${engagementId} with active scope not found`);
    }

    const allowedTargets: string[] = JSON.parse(engagement.scope.allowedTargets || '[]');
    const primaryTarget = forcedTarget || allowedTargets[0] || '127.0.0.1';

    // 2. Discover unknown surface & generate candidate hypotheses
    const candidateActions: CandidateAction[] = [];

    // Hypothesis A: Recon & DNS/Port enumeration if ports are unknown
    const portNodes = graphData.nodes.filter(n => n.nodeType === 'PORT');
    if (portNodes.length === 0) {
      candidateActions.push({
        id: `act-${crypto.randomBytes(3).toString('hex')}`,
        step: 'DISCOVER',
        target: primaryTarget,
        testType: 'RECON',
        agentName: 'ReconAgent',
        hypothesis: `Target ${primaryTarget} has unmapped network attack surface and open ports.`,
        priorityScore: 95,
        riskLevel: 'PASSIVE'
      });
    }

    // Hypothesis B: Web Application Endpoints if endpoints are unknown
    const endpointNodes = graphData.nodes.filter(n => n.nodeType === 'ENDPOINT');
    if (endpointNodes.length === 0) {
      candidateActions.push({
        id: `act-${crypto.randomBytes(3).toString('hex')}`,
        step: 'MAP',
        target: primaryTarget,
        testType: 'WEB_CRAWL',
        agentName: 'WebMappingAgent',
        hypothesis: `Target ${primaryTarget} hosts web endpoints that require route mapping.`,
        priorityScore: 85,
        riskLevel: 'LOW'
      });
    }

    // Hypothesis C: Multi-Role Authorization & IDOR on discovered or common endpoints
    const authRoles = graphData.nodes.filter(n => n.nodeType === 'ROLE');
    if (authRoles.length === 0) {
      candidateActions.push({
        id: `act-${crypto.randomBytes(3).toString('hex')}`,
        step: 'HYPOTHESIZE',
        target: primaryTarget,
        testType: 'AUTH_TEST',
        agentName: 'AuthMatrixAgent',
        hypothesis: `Administrative endpoints on ${primaryTarget} may be accessible to unauthenticated or guest identities.`,
        priorityScore: 90,
        parameters: { operation: 'GET /api/v1/users', role: 'GUEST' },
        riskLevel: 'MEDIUM'
      });
    }

    // Sort candidate actions by priority score
    candidateActions.sort((a, b) => b.priorityScore - a.priorityScore);

    // If no specific candidates remain, generate a continuous validation hypothesis
    if (candidateActions.length === 0) {
      candidateActions.push({
        id: `act-${crypto.randomBytes(3).toString('hex')}`,
        step: 'REASSESS',
        target: primaryTarget,
        testType: 'RECON',
        agentName: 'ReconAgent',
        hypothesis: `Periodic re-assessment of infrastructure stability on ${primaryTarget}.`,
        priorityScore: 50,
        riskLevel: 'PASSIVE'
      });
    }

    // 3. Deterministic Orchestrator selects top candidate action
    const selectedAction = candidateActions[0];

    // 4. ScopeGuard Authorization Gate
    const scopeCheck = await ScopeGuardService.check({
      engagementId,
      actionId: selectedAction.id,
      targetHost: selectedAction.target,
      requestedTestType: selectedAction.testType,
      isDestructive: false,
      isActivePoC: false
    });

    if (scopeCheck.decision !== 'ALLOWED') {
      return {
        iterationId,
        engagementId,
        stepExecuted: selectedAction.step,
        candidateActions,
        executedAction: selectedAction,
        decision: scopeCheck.decision,
        observation: `ScopeGuard blocked proposed action: ${scopeCheck.reason}`,
        newNodesDiscovered: 0,
        newEdgesDiscovered: 0,
        untestedSurfaceRemaining: candidateActions.length,
        timestamp: new Date().toISOString()
      };
    }

    // 5. Execute chosen Agent
    const agent = AgentCoordinatorService.getAgent(selectedAction.agentName);
    if (!agent) {
      return {
        iterationId,
        engagementId,
        stepExecuted: selectedAction.step,
        candidateActions,
        executedAction: selectedAction,
        decision: 'FAILED',
        observation: `Agent ${selectedAction.agentName} not found in AgentCoordinatorService`,
        newNodesDiscovered: 0,
        newEdgesDiscovered: 0,
        untestedSurfaceRemaining: candidateActions.length,
        timestamp: new Date().toISOString()
      };
    }

    const agentResult = await agent.run({
      engagementId,
      target: selectedAction.target,
      scope: engagement.scope,
      parameters: selectedAction.parameters
    });

    // 6. Ingest newly discovered nodes and edges into the Omniscient Graph
    let newNodes = 0;
    let newEdges = 0;

    if (agentResult.discoveredNodes) {
      for (const node of agentResult.discoveredNodes) {
        await SecurityGraphService.upsertNode(
          engagementId,
          node.type as any,
          node.key,
          node.label,
          node.properties || {}
        );
        newNodes++;
      }
    }

    if (agentResult.discoveredEdges) {
      for (const edge of agentResult.discoveredEdges) {
        const fromNode = await prisma.securityGraphNode.findFirst({
          where: { engagementId, nodeKey: edge.from }
        });
        const toNode = await prisma.securityGraphNode.findFirst({
          where: { engagementId, nodeKey: edge.to }
        });
        if (fromNode && toNode) {
          await SecurityGraphService.upsertEdge(
            engagementId,
            fromNode.id,
            toNode.id,
            edge.type as any
          );
          newEdges++;
        }
      }
    }

    return {
      iterationId,
      engagementId,
      stepExecuted: selectedAction.step,
      candidateActions,
      executedAction: selectedAction,
      decision: agentResult.decision,
      observation: agentResult.observation,
      newNodesDiscovered: newNodes,
      newEdgesDiscovered: newEdges,
      untestedSurfaceRemaining: Math.max(0, candidateActions.length - 1),
      timestamp: new Date().toISOString()
    };
  }
}
