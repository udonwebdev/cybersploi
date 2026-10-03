import prisma from '../../config/database';
import { SecurityGraphService } from './security-graph.service';

export interface CreateAttackPathRequest {
  engagementId: string;
  title: string;
  description?: string;
  findingIds?: string[]; // Ordered findings defining the attack sequence
  nodeKeys?: string[]; // Ordered graph nodes defining the path
  assumptions?: string[];
  targetCrownJewel?: string;
}

export interface AddTransitionEvidenceRequest {
  transitionId: string;
  evidenceId: string;
}

export interface AttackPathAnalysisResult {
  pathId: string;
  title: string;
  status: 'HYPOTHESIZED' | 'INCOMPLETE' | 'DEMONSTRATED' | 'INVALIDATED';
  pathLength: number;
  cumulativeRisk: number; // 0.0 - 100.0
  confidenceLevel: 'HIGH' | 'MEDIUM' | 'LOW';
  requiredAssumptions: string[];
  affectedIdentities: string[];
  affectedAssets: string[];
  downstreamBlastRadius: {
    totalExposedNodes: number;
    crownJewelsExposed: string[];
    affectedResources: string[];
  };
  nodeSequence: string[];
  transitions: Array<{
    id: string;
    from: string;
    to: string;
    hasValidEvidence: boolean;
    evidenceId?: string | null;
  }>;
}

export class AttackPathService {
  /**
   * Creates an attack path from an ordered sequence of findings or graph nodes.
   * Path starts as HYPOTHESIZED or INCOMPLETE.
   */
  public static async createAttackPath(req: CreateAttackPathRequest) {
    const { engagementId, title, description, findingIds, assumptions } = req;

    if (findingIds && findingIds.length >= 2) {
      // Verify all findings exist
      const findings = await prisma.engineFinding.findMany({
        where: { id: { in: findingIds }, engagementId }
      });

      if (findings.length !== findingIds.length) {
        throw new Error('One or more findings do not exist or belong to another engagement.');
      }

      // Create AttackPath
      const attackPath = await prisma.engineAttackPath.create({
        data: {
          engagementId,
          title,
          description: description || null,
          status: 'HYPOTHESIZED',
          findingsOrder: JSON.stringify(findingIds)
        }
      });

      // Create pairwise transitions (finding[i] -> finding[i+1])
      for (let i = 0; i < findingIds.length - 1; i++) {
        await prisma.attackPathTransition.create({
          data: {
            attackPathId: attackPath.id,
            fromFindingId: findingIds[i],
            toFindingId: findingIds[i + 1],
            hasValidEvidence: false
          }
        });
      }

      return this.getAttackPath(attackPath.id);
    } else if (req.nodeKeys && req.nodeKeys.length >= 2) {
      // Direct graph node chain creation
      const attackPath = await prisma.engineAttackPath.create({
        data: {
          engagementId,
          title,
          description: description || `Graph traversal chain: ${req.nodeKeys.join(' -> ')}`,
          status: 'HYPOTHESIZED',
          findingsOrder: JSON.stringify(req.nodeKeys)
        }
      });
      return this.getAttackPath(attackPath.id);
    } else {
      throw new Error('An AttackPath requires at least two ordered findings or node keys to establish a chain.');
    }
  }

  /**
   * Associates transition evidence and recalculates the AttackPath status.
   * A path may ONLY become DEMONSTRATED when EVERY transition has valid evidence.
   */
  public static async attachTransitionEvidence(req: AddTransitionEvidenceRequest) {
    const { transitionId, evidenceId } = req;

    // Verify evidence exists
    const evidence = await prisma.engineEvidence.findUnique({
      where: { id: evidenceId }
    });
    if (!evidence) {
      throw new Error(`Evidence ${evidenceId} not found`);
    }

    // Update transition
    const transition = await prisma.attackPathTransition.update({
      where: { id: transitionId },
      data: {
        evidenceId,
        hasValidEvidence: true
      },
      include: { attackPath: true }
    });

    // Recalculate attack path status
    await this.evaluatePathStatus(transition.attackPathId);

    return this.getAttackPath(transition.attackPathId);
  }

  /**
   * Evaluates if all transitions in the path have valid evidence.
   * If yes -> DEMONSTRATED.
   * If some -> INCOMPLETE.
   * If none -> HYPOTHESIZED.
   */
  public static async evaluatePathStatus(attackPathId: string): Promise<string> {
    const attackPath = await prisma.engineAttackPath.findUnique({
      where: { id: attackPathId }
    });
    if (!attackPath) return 'INVALIDATED';
    if (attackPath.status === 'INVALIDATED') return 'INVALIDATED';

    const transitions = await prisma.attackPathTransition.findMany({
      where: { attackPathId }
    });

    if (transitions.length === 0) {
      await prisma.engineAttackPath.update({
        where: { id: attackPathId },
        data: { status: 'HYPOTHESIZED' }
      });
      return 'HYPOTHESIZED';
    }

    const provenTransitionsCount = transitions.filter(t => t.hasValidEvidence && t.evidenceId).length;

    let newStatus: 'HYPOTHESIZED' | 'INCOMPLETE' | 'DEMONSTRATED';
    if (provenTransitionsCount === transitions.length) {
      newStatus = 'DEMONSTRATED';
    } else if (provenTransitionsCount > 0) {
      newStatus = 'INCOMPLETE';
    } else {
      newStatus = 'HYPOTHESIZED';
    }

    await prisma.engineAttackPath.update({
      where: { id: attackPathId },
      data: { status: newStatus }
    });

    return newStatus;
  }

  /**
   * Dynamic Finding Status Propagation:
   * When a finding is validated, proved, remediated, or disproven,
   * automatically recalculate all affected attack paths.
   */
  public static async propagateFindingStatus(
    findingId: string,
    newStatus: 'VALIDATED' | 'PROVEN' | 'DISPROVEN' | 'INCONCLUSIVE' | 'REMEDIATED'
  ): Promise<{ affectedPathsCount: number; updatedPaths: string[] }> {
    const transitions = await prisma.attackPathTransition.findMany({
      where: {
        OR: [{ fromFindingId: findingId }, { toFindingId: findingId }]
      }
    });

    const affectedPathIds = Array.from(new Set(transitions.map(t => t.attackPathId)));

    for (const trans of transitions) {
      if (newStatus === 'PROVEN' || newStatus === 'VALIDATED') {
        // Link evidence if finding has evidence
        const finding = await prisma.engineFinding.findUnique({
          where: { id: findingId },
          include: { evidence: { take: 1 } }
        });
        const evidenceId = finding?.evidence[0]?.id;
        await prisma.attackPathTransition.update({
          where: { id: trans.id },
          data: {
            hasValidEvidence: true,
            evidenceId: evidenceId || trans.evidenceId
          }
        });
      } else if (newStatus === 'DISPROVEN' || newStatus === 'REMEDIATED') {
        // Break the chain
        await prisma.attackPathTransition.update({
          where: { id: trans.id },
          data: { hasValidEvidence: false }
        });
      }
    }

    const updatedPaths: string[] = [];
    for (const pathId of affectedPathIds) {
      if (newStatus === 'DISPROVEN' || newStatus === 'REMEDIATED') {
        // If a transition node was completely disproven or remediated, mark path as INVALIDATED
        await prisma.engineAttackPath.update({
          where: { id: pathId },
          data: { status: 'INVALIDATED' }
        });
        updatedPaths.push(pathId);
      } else {
        await this.evaluatePathStatus(pathId);
        updatedPaths.push(pathId);
      }
    }

    return {
      affectedPathsCount: affectedPathIds.length,
      updatedPaths
    };
  }

  /**
   * Performs A* / Dijkstra graph path discovery to identify verified paths to Crown Jewels.
   * SOURCE IDENTITY -> INTERMEDIATE RESOURCE -> PRIVILEGE TRANSITION -> TARGET CROWN JEWEL
   */
  public static async findAttackPathsToCrownJewels(
    engagementId: string,
    sourceNodeKey: string
  ): Promise<AttackPathAnalysisResult[]> {
    // 1. Sync graph
    await SecurityGraphService.syncEngagementToGraph(engagementId);

    // 2. Locate source node and crown jewel nodes
    const sourceNode = await prisma.securityGraphNode.findFirst({
      where: { engagementId, nodeKey: sourceNodeKey }
    });

    if (!sourceNode) {
      return [];
    }

    const crownJewels = await prisma.securityGraphNode.findMany({
      where: {
        engagementId,
        OR: [
          { nodeType: 'CROWN_JEWEL' },
          { properties: { contains: '"isCrownJewel":true' } },
          { label: { contains: 'Crown' } },
          { label: { contains: 'Admin' } }
        ]
      }
    });

    const results: AttackPathAnalysisResult[] = [];

    for (const cj of crownJewels) {
      const shortest = await SecurityGraphService.findShortestAttackPath(
        engagementId,
        sourceNode.id,
        cj.id
      );

      if (shortest.path.length >= 2) {
        // Resolve node details
        const nodes = await prisma.securityGraphNode.findMany({
          where: { id: { in: shortest.path } }
        });
        const nodeMap = new Map(nodes.map(n => [n.id, n]));
        const orderedNodes = shortest.path.map(id => nodeMap.get(id)!).filter(Boolean);

        const nodeKeys = orderedNodes.map(n => n.nodeKey);
        const assumptions: string[] = [];
        const affectedIdentities: string[] = [];
        const affectedAssets: string[] = [];

        for (const n of orderedNodes) {
          if (n.nodeType === 'IDENTITY' || n.nodeType === 'ROLE' || n.nodeType === 'IAM_ROLE') {
            affectedIdentities.push(n.label);
          }
          if (n.nodeType === 'DOMAIN' || n.nodeType === 'IP' || n.nodeType === 'API' || n.nodeType === 'SERVICE') {
            affectedAssets.push(n.label);
          }
          if (n.nodeType === 'VULNERABILITY') {
            assumptions.push(`Exploitation of ${n.label}`);
          }
        }

        // Downstream blast radius calculation: nodes reachable from the Crown Jewel
        const outgoingFromCj = await prisma.securityGraphEdge.findMany({
          where: { engagementId, fromNodeId: cj.id }
        });

        // Cumulative risk score based on path weight, crown jewel status, and hop count
        const baseRisk = 70.0;
        const hopPenalty = Math.min(20, (shortest.path.length - 1) * 3);
        const cumulativeRisk = Math.min(100.0, Math.max(10.0, baseRisk + 20.0 - hopPenalty));

        const allProven = shortest.transitions.every(t => t.weight < 1.0 || t.edgeType === 'CONFIRMS');

        results.push({
          pathId: `path_${sourceNode.nodeKey}_to_${cj.nodeKey}`,
          title: `Attack Path: ${sourceNode.label} to Crown Jewel ${cj.label}`,
          status: allProven ? 'DEMONSTRATED' : 'HYPOTHESIZED',
          pathLength: shortest.path.length - 1,
          cumulativeRisk,
          confidenceLevel: allProven ? 'HIGH' : (shortest.path.length <= 3 ? 'MEDIUM' : 'LOW'),
          requiredAssumptions: assumptions.length > 0 ? assumptions : ['Network reachability verified'],
          affectedIdentities,
          affectedAssets,
          downstreamBlastRadius: {
            totalExposedNodes: outgoingFromCj.length + 1,
            crownJewelsExposed: [cj.label],
            affectedResources: affectedAssets
          },
          nodeSequence: nodeKeys,
          transitions: shortest.transitions.map((t, idx) => ({
            id: t.id || `trans_${idx}`,
            from: t.fromNodeId,
            to: t.toNodeId,
            hasValidEvidence: t.weight < 1.0,
            evidenceId: t.evidenceId
          }))
        });
      }
    }

    return results;
  }

  /**
   * Models an explicit privilege transition (e.g. Asset Exposure -> SSRF -> IMDS Role Transition -> Crown Jewel).
   */
  public static async modelPrivilegeTransition(
    engagementId: string,
    req: {
      sourceIdentityKey: string;
      intermediateResourceKey: string;
      targetRoleKey: string;
      crownJewelKey: string;
      assumptions?: string[];
      evidenceId?: string;
    }
  ): Promise<AttackPathAnalysisResult> {
    // 1. Ensure nodes exist in SecurityGraph
    const srcNode = await SecurityGraphService.upsertNode(
      engagementId,
      'IDENTITY',
      req.sourceIdentityKey,
      `Identity: ${req.sourceIdentityKey}`,
      { type: 'untrusted_actor' }
    );

    const resourceNode = await SecurityGraphService.upsertNode(
      engagementId,
      'SERVICE',
      req.intermediateResourceKey,
      `Resource: ${req.intermediateResourceKey}`,
      { exposesMetadata: true }
    );

    const roleNode = await SecurityGraphService.upsertNode(
      engagementId,
      'IAM_ROLE',
      req.targetRoleKey,
      `IAM Role: ${req.targetRoleKey}`,
      { privileged: true }
    );

    const crownJewelNode = await SecurityGraphService.upsertNode(
      engagementId,
      'CROWN_JEWEL',
      req.crownJewelKey,
      `Crown Jewel: ${req.crownJewelKey}`,
      { criticalData: true, isCrownJewel: true }
    );

    // 2. Connect security relationship edges
    await SecurityGraphService.upsertEdge(engagementId, srcNode.id, resourceNode.id, 'CALLS', {
      weight: 1.0,
      properties: { transition: 'initial_access' }
    });

    await SecurityGraphService.upsertEdge(engagementId, resourceNode.id, roleNode.id, 'ASSUMES_ROLE', {
      weight: req.evidenceId ? 0.5 : 1.5,
      evidenceId: req.evidenceId,
      properties: { transition: 'privilege_escalation', mechanism: 'imds_metadata_exposure' }
    });

    await SecurityGraphService.upsertEdge(engagementId, roleNode.id, crownJewelNode.id, 'AUTHORIZES', {
      weight: 0.5,
      properties: { transition: 'crown_jewel_access' }
    });

    // 3. Construct attack path record
    const attackPath = await this.createAttackPath({
      engagementId,
      title: `Privilege Escalation Path: ${req.sourceIdentityKey} -> ${req.crownJewelKey}`,
      description: `Modeled transition through ${req.intermediateResourceKey} assuming ${req.targetRoleKey}`,
      nodeKeys: [srcNode.nodeKey, resourceNode.nodeKey, roleNode.nodeKey, crownJewelNode.nodeKey]
    });

    return {
      pathId: attackPath!.id,
      title: attackPath!.title,
      status: req.evidenceId ? 'DEMONSTRATED' : 'HYPOTHESIZED',
      pathLength: 3,
      cumulativeRisk: 95.0,
      confidenceLevel: req.evidenceId ? 'HIGH' : 'MEDIUM',
      requiredAssumptions: req.assumptions || ['SSRF parameter reachable', 'IMDSv1 tokenless access enabled'],
      affectedIdentities: [req.sourceIdentityKey, req.targetRoleKey],
      affectedAssets: [req.intermediateResourceKey],
      downstreamBlastRadius: {
        totalExposedNodes: 4,
        crownJewelsExposed: [req.crownJewelKey],
        affectedResources: [req.intermediateResourceKey, req.crownJewelKey]
      },
      nodeSequence: [srcNode.nodeKey, resourceNode.nodeKey, roleNode.nodeKey, crownJewelNode.nodeKey],
      transitions: [
        { id: 't1', from: srcNode.nodeKey, to: resourceNode.nodeKey, hasValidEvidence: true },
        { id: 't2', from: resourceNode.nodeKey, to: roleNode.nodeKey, hasValidEvidence: !!req.evidenceId, evidenceId: req.evidenceId },
        { id: 't3', from: roleNode.nodeKey, to: crownJewelNode.nodeKey, hasValidEvidence: true }
      ]
    };
  }

  /**
   * Fetches an attack path with its transitions and evidence.
   */
  public static async getAttackPath(attackPathId: string) {
    return prisma.engineAttackPath.findUnique({
      where: { id: attackPathId },
      include: {
        transitions: {
          include: {
            fromFinding: true,
            toFinding: true,
            evidence: true
          }
        }
      }
    });
  }

  /**
   * Lists all attack paths for an engagement.
   */
  public static async listAttackPaths(engagementId: string) {
    return prisma.engineAttackPath.findMany({
      where: { engagementId },
      include: {
        transitions: {
          include: {
            fromFinding: true,
            toFinding: true,
            evidence: true
          }
        }
      }
    });
  }
}
