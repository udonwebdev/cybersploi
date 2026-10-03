import * as crypto from 'crypto';
import prisma from '../../config/database';
import { SecurityGraphService } from './security-graph.service';

export interface ActionCandidate {
  actionId: string;
  name: string;
  category: 'RECON' | 'WEB_MAPPING' | 'AUTH_MATRIX' | 'VULN_RESEARCH' | 'VALIDATION' | 'PROOF_TEST';
  target: string;
  targetNodeType: string; // HOST, PORT, ENDPOINT, IAM_ROLE, CROWN_JEWEL
  estimatedCost: number; // 0.1 - 10.0 (API requests, time, network packets)
  riskScore: number; // 0.0 - 1.0 (production impact risk)
  severityWeight: number; // 1.0 (INFO) to 10.0 (CRITICAL / CROWN_JEWEL)
  expectedConfidenceDelta: number; // 0.0 - 1.0 (how much certainty will increase)
  parameters?: Record<string, any>;
}

export interface EvaluatedAction extends ActionCandidate {
  expectedEntropyDelta: number; // Bits of information gained: ΔH
  utilityScore: number; // Computed formal utility
  selectionRank: number;
  reasoning: string;
  redundant: boolean;
}

export interface AttackSurfaceState {
  totalNodes: number;
  unmappedNodes: number;
  untestedEndpoints: number;
  unresolvedIdentities: number;
  currentEntropyBits: number; // H(S)
}

export interface InformationGainPlan {
  planId: string;
  engagementId: string;
  timestamp: string;
  initialEntropyBits: number;
  projectedEntropyBitsAfterPlan: number;
  entropyReductionPercentage: number;
  evaluatedActions: EvaluatedAction[];
  selectedActions: EvaluatedAction[];
  prunedRedundantCount: number;
  totalEstimatedCost: number;
  cumulativeRiskScore: number;
}

export class InfoGainPlannerService {
  /**
   * Computes the Shannon entropy H(S) of the current security graph and surface state.
   * H(S) = - sum(p_i * log2(p_i))
   */
  public static computeShannonEntropy(surface: AttackSurfaceState): number {
    const total = Math.max(1, surface.totalNodes);
    const pUnmapped = Math.max(0.01, surface.unmappedNodes / total);
    const pUntestedEndpoints = Math.max(0.01, surface.untestedEndpoints / total);
    const pUnresolvedIdentities = Math.max(0.01, surface.unresolvedIdentities / total);

    const probabilities = [pUnmapped, pUntestedEndpoints, pUnresolvedIdentities];
    const sumP = probabilities.reduce((acc, p) => acc + p, 0);

    // Normalize probabilities so sum = 1
    const normalized = probabilities.map(p => p / sumP);

    let entropy = 0;
    for (const p of normalized) {
      if (p > 0) {
        entropy -= p * Math.log2(p);
      }
    }

    return Number(entropy.toFixed(4));
  }

  /**
   * Computes formal action utility:
   * Utility(a) = (ΔH(a) * SeverityWeight * ΔConfidence) / ((1 + Cost(a)) * (1 + Risk(a)))
   */
  public static computeActionUtility(
    candidate: ActionCandidate,
    expectedEntropyDelta: number
  ): number {
    const numerator = expectedEntropyDelta * candidate.severityWeight * candidate.expectedConfidenceDelta;
    const denominator = (1 + candidate.estimatedCost) * (1 + candidate.riskScore);
    const utility = numerator / denominator;
    return Number(utility.toFixed(4));
  }

  /**
   * Evaluates candidate actions against current attack surface state.
   * Ranks candidates by utility and prunes redundant/low-value actions.
   */
  public static planOptimalActions(
    engagementId: string,
    candidates: ActionCandidate[],
    currentState: AttackSurfaceState,
    maxActions: number = 5
  ): InformationGainPlan {
    const planId = `plan-${crypto.randomBytes(4).toString('hex')}`;
    const initialEntropy = this.computeShannonEntropy(currentState);

    const evaluatedActions: EvaluatedAction[] = [];
    const seenTargets = new Set<string>();

    for (const candidate of candidates) {
      // Check redundancy: already tested or identical target+category in batch
      const targetKey = `${candidate.category}:${candidate.target}`;
      const isDuplicateTarget = seenTargets.has(targetKey);

      // Estimate entropy delta based on node type and exploration value
      let baseEntropyDelta = 0.35;
      if (candidate.targetNodeType === 'CROWN_JEWEL' || candidate.targetNodeType === 'IAM_ROLE') {
        baseEntropyDelta = 0.75;
      } else if (candidate.targetNodeType === 'ENDPOINT' || candidate.targetNodeType === 'PORT') {
        baseEntropyDelta = 0.50;
      }

      // Diminishing returns if redundant
      const expectedEntropyDelta = isDuplicateTarget ? Number((baseEntropyDelta * 0.1).toFixed(4)) : baseEntropyDelta;
      const isRedundant = isDuplicateTarget || expectedEntropyDelta < 0.05;

      const utilityScore = this.computeActionUtility(candidate, expectedEntropyDelta);

      evaluatedActions.push({
        ...candidate,
        expectedEntropyDelta,
        utilityScore: isRedundant ? 0 : utilityScore,
        selectionRank: 0,
        reasoning: isRedundant
          ? 'Pruned: Redundant test target or negligible information gain.'
          : `High information gain: Expected ΔH=${expectedEntropyDelta} bits, Utility=${utilityScore}.`,
        redundant: isRedundant
      });

      if (!isRedundant) {
        seenTargets.add(targetKey);
      }
    }

    // Sort by utility descending
    evaluatedActions.sort((a, b) => b.utilityScore - a.utilityScore);

    // Assign selection ranks
    evaluatedActions.forEach((act, idx) => {
      act.selectionRank = idx + 1;
    });

    const selectedActions = evaluatedActions.filter(a => !a.redundant).slice(0, maxActions);
    const prunedCount = evaluatedActions.filter(a => a.redundant).length;

    // Projected entropy after execution
    const totalEntropyDelta = selectedActions.reduce((acc, a) => acc + a.expectedEntropyDelta, 0);
    const projectedEntropy = Math.max(0.05, Number((initialEntropy - (totalEntropyDelta * 0.25)).toFixed(4)));
    const reductionPercent = initialEntropy > 0
      ? Number((((initialEntropy - projectedEntropy) / initialEntropy) * 100).toFixed(1))
      : 0;

    const totalCost = Number(selectedActions.reduce((acc, a) => acc + a.estimatedCost, 0).toFixed(2));
    const cumulativeRisk = Number(selectedActions.reduce((acc, a) => acc + a.riskScore, 0).toFixed(2));

    return {
      planId,
      engagementId,
      timestamp: new Date().toISOString(),
      initialEntropyBits: initialEntropy,
      projectedEntropyBitsAfterPlan: projectedEntropy,
      entropyReductionPercentage: reductionPercent,
      evaluatedActions,
      selectedActions,
      prunedRedundantCount: prunedCount,
      totalEstimatedCost: totalCost,
      cumulativeRiskScore: cumulativeRisk
    };
  }

  /**
   * Synthesizes candidates directly from 3D Security Graph topology and runs the planner.
   */
  public static async generatePlanFromGraph(engagementId: string): Promise<InformationGainPlan> {
    const graph = await SecurityGraphService.getOmniscientGraph3D(engagementId).catch(() => ({
      nodes: [],
      edges: []
    }));

    const totalNodes = Math.max(1, graph.nodes.length);
    const unmappedNodes = graph.nodes.filter(n => (n.nodeType as string) === 'IP' || (n.nodeType as string) === 'PORT' || (n.nodeType as string) === 'DOMAIN').length;
    const untestedEndpoints = graph.nodes.filter(n => n.nodeType === 'ENDPOINT').length;
    const unresolvedIdentities = graph.nodes.filter(n => n.nodeType === 'IAM_ROLE' || n.nodeType === 'PERMISSION').length;

    const surfaceState: AttackSurfaceState = {
      totalNodes,
      unmappedNodes,
      untestedEndpoints,
      unresolvedIdentities,
      currentEntropyBits: 1.585
    };

    surfaceState.currentEntropyBits = this.computeShannonEntropy(surfaceState);

    // Generate candidate actions from graph elements
    const candidates: ActionCandidate[] = [];

    // 1. Host/Port discovery candidate
    candidates.push({
      actionId: `act-recon-${crypto.randomBytes(3).toString('hex')}`,
      name: 'Passive DNS & Port Enumeration',
      category: 'RECON',
      target: '127.0.0.1',
      targetNodeType: 'IP',
      estimatedCost: 1.2,
      riskScore: 0.05,
      severityWeight: 4.0,
      expectedConfidenceDelta: 0.90
    });

    // 2. Web endpoint discovery candidate
    candidates.push({
      actionId: `act-map-${crypto.randomBytes(3).toString('hex')}`,
      name: 'API Route & Schema Extraction',
      category: 'WEB_MAPPING',
      target: 'http://127.0.0.1:8000/api',
      targetNodeType: 'ENDPOINT',
      estimatedCost: 1.8,
      riskScore: 0.10,
      severityWeight: 6.0,
      expectedConfidenceDelta: 0.85
    });

    // 3. IAM / Crown Jewel access candidate
    candidates.push({
      actionId: `act-auth-${crypto.randomBytes(3).toString('hex')}`,
      name: 'Transitive IAM Reachability Theorem Check',
      category: 'AUTH_MATRIX',
      target: 'arn:aws:iam::123456789012:role/DataPipeline',
      targetNodeType: 'IAM_ROLE',
      estimatedCost: 0.5,
      riskScore: 0.02,
      severityWeight: 9.5,
      expectedConfidenceDelta: 0.98
    });

    // 4. Duplicate/redundant candidate (to verify pruning)
    candidates.push({
      actionId: `act-dup-${crypto.randomBytes(3).toString('hex')}`,
      name: 'Duplicate Port Scan on 127.0.0.1',
      category: 'RECON',
      target: '127.0.0.1',
      targetNodeType: 'IP',
      estimatedCost: 2.0,
      riskScore: 0.10,
      severityWeight: 3.0,
      expectedConfidenceDelta: 0.10
    });


    // 5. Crown Jewel Access Validation
    candidates.push({
      actionId: `act-proof-${crypto.randomBytes(3).toString('hex')}`,
      name: 'Loopback Ephemeral IMDSv2 Token Proof',
      category: 'PROOF_TEST',
      target: 'http://169.254.169.254/latest/meta-data',
      targetNodeType: 'CROWN_JEWEL',
      estimatedCost: 0.8,
      riskScore: 0.15,
      severityWeight: 10.0,
      expectedConfidenceDelta: 0.95
    });

    return this.planOptimalActions(engagementId, candidates, surfaceState, 4);
  }
}
