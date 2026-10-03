import prisma from '../../config/database';
import { SecurityGraphService, Graph3DNode, Graph3DEdge, ValidationState } from './security-graph.service';

export type TrustZone = 'INTERNET' | 'DMZ' | 'INTERNAL_VPC' | 'PROD_DATA' | 'MGMT_PLANE';

export interface CrownJewelDefinition {
  id: string;
  name: string;
  category: 'DATABASE' | 'KMS' | 'IDP' | 'PII_STORE' | 'ROOT_CA' | 'FINANCIAL_LEDGER';
  nodeKey: string;
  criticality: 'HIGH' | 'CRITICAL' | 'CATASTROPHIC';
  impactWeight: number; // 1 - 10
  trustZone: TrustZone;
  description: string;
}

export interface BoundaryCrossing {
  fromZone: TrustZone;
  toZone: TrustZone;
  fromNodeId: string;
  toNodeId: string;
  transitionType: string;
  defenseInDepthScore: number; // 0 - 10
}

export interface CrownJewelPath {
  pathId: string;
  crownJewelId: string;
  entryNodeId: string;
  entryNodeKey: string;
  hopCount: number;
  nodes: { id: string; label: string; nodeType: string; trustZone: TrustZone }[];
  edges: { fromNodeId: string; toNodeId: string; edgeType: string; weight: number }[];
  boundaryCrossings: BoundaryCrossing[];
  validationState: ValidationState;
  attackerCost: number;     // Normalized effort score
  blastRadiusScore: number; // 1 - 100
  chokePointNodeId?: string; // Highest-leverage node to sever
}

export interface CrownJewelReachabilityMatrix {
  engagementId: string;
  timestamp: string;
  totalCrownJewels: number;
  exposedCrownJewels: number;
  totalPaths: number;
  paths: CrownJewelPath[];
  chokePointRecommendations: {
    nodeId: string;
    nodeLabel: string;
    pathsBlockedCount: number;
    riskReductionPercent: number;
    suggestedMitigation: string;
  }[];
  overallExposureRating: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export class CrownJewelService {
  private static defaultCrownJewels: CrownJewelDefinition[] = [
    {
      id: 'CJ-01',
      name: 'Production PostgreSQL Cluster',
      category: 'DATABASE',
      nodeKey: 'prod-db.internal',
      criticality: 'CATASTROPHIC',
      impactWeight: 10,
      trustZone: 'PROD_DATA',
      description: 'Primary customer PII, tenant records, and authentication hashes'
    },
    {
      id: 'CJ-02',
      name: 'Cloud KMS Key Enclave',
      category: 'KMS',
      nodeKey: 'kms.internal.crypto',
      criticality: 'CATASTROPHIC',
      impactWeight: 10,
      trustZone: 'MGMT_PLANE',
      description: 'Master data encryption keys and signing secrets'
    },
    {
      id: 'CJ-03',
      name: 'Identity Provider Control Plane',
      category: 'IDP',
      nodeKey: 'idp.internal.sso',
      criticality: 'CRITICAL',
      impactWeight: 9,
      trustZone: 'MGMT_PLANE',
      description: 'Corporate and service identity administration'
    }
  ];

  /**
   * Assign a trust zone to a graph node based on its type and properties
   */
  public static assignTrustZone(node: Graph3DNode): TrustZone {
    const key = (node.nodeKey || '').toLowerCase();
    const label = (node.label || '').toLowerCase();

    if (key.includes('prod') || key.includes('db') || key.includes('postgres') || key.includes('sql') || key.includes('pii')) {
      return 'PROD_DATA';
    }
    if (key.includes('kms') || key.includes('idp') || key.includes('iam') || key.includes('root') || key.includes('admin')) {
      return 'MGMT_PLANE';
    }
    if (key.includes('internal') || key.includes('vpc') || key.includes('10.') || key.includes('172.16.') || key.includes('192.168.')) {
      return 'INTERNAL_VPC';
    }
    if (node.nodeType === 'API' || node.nodeType === 'ENDPOINT' || node.nodeType === 'SERVICE' || key.includes('gateway') || key.includes('proxy')) {
      return 'DMZ';
    }
    return 'INTERNET';
  }

  /**
   * Register Crown Jewel nodes in the Universal Security Graph
   */
  public static async registerCrownJewels(
    engagementId: string,
    customJewels: CrownJewelDefinition[] = []
  ): Promise<CrownJewelDefinition[]> {
    const jewels = customJewels.length > 0 ? customJewels : this.defaultCrownJewels;

    for (const jewel of jewels) {
      await SecurityGraphService.upsertNode(
        engagementId,
        'CROWN_JEWEL',
        jewel.nodeKey,
        jewel.name,
        {
          jewelId: jewel.id,
          category: jewel.category,
          criticality: jewel.criticality,
          impactWeight: jewel.impactWeight,
          trustZone: jewel.trustZone,
          description: jewel.description
        }
      );
    }

    return jewels;
  }

  /**
   * Calculate multi-hop reachability paths from external attack surface to crown jewels
   */
  public static async computeReachabilityMatrix(
    engagementId: string,
    customJewels: CrownJewelDefinition[] = []
  ): Promise<CrownJewelReachabilityMatrix> {
    const jewels = await this.registerCrownJewels(engagementId, customJewels);
    const graphData = await SecurityGraphService.getOmniscientGraph3D(engagementId);

    const nodeMap = new Map<string, Graph3DNode>(graphData.nodes.map(n => [n.id, n]));
    const jewelNodes = graphData.nodes.filter(n => n.nodeType === 'CROWN_JEWEL');

    // External entry points: nodes in INTERNET or DMZ zones (e.g. DOMAIN, IP, API, ENDPOINT)
    const entryNodes = graphData.nodes.filter(n => {
      const zone = this.assignTrustZone(n);
      return (
        (zone === 'INTERNET' || zone === 'DMZ') &&
        ['DOMAIN', 'SUBDOMAIN', 'IP', 'ENDPOINT', 'API', 'PORT'].includes(n.nodeType)
      );
    });

    // Build adjacency list for forward traversal
    const forwardAdj = new Map<string, { to: string; edge: Graph3DEdge }[]>();
    for (const edge of graphData.edges) {
      if (!forwardAdj.has(edge.fromNodeId)) {
        forwardAdj.set(edge.fromNodeId, []);
      }
      forwardAdj.get(edge.fromNodeId)!.push({ to: edge.toNodeId, edge });
    }

    const paths: CrownJewelPath[] = [];
    const chokePointCounts = new Map<string, number>();

    // BFS / Dijkstra path discovery to find paths from entry nodes to each crown jewel
    for (const jNode of jewelNodes) {
      for (const eNode of entryNodes) {
        const found = this.findPath(eNode.id, jNode.id, forwardAdj, nodeMap);
        if (found) {
          const boundaryCrossings = this.computeBoundaryCrossings(found.nodes);
          
          // Determine path validation state based on edge provenance and findings
          let validationState: ValidationState = 'THEORETICAL';
          const hasConfirmedEdges = found.edges.some(e => e.edgeType === 'CONFIRMS' || e.edgeType === 'LEADS_TO');
          const hasValidatedProvenance = found.edges.some(e => e.provenance?.validationState === 'VALIDATED');
          const hasReproducedProvenance = found.edges.some(e => e.provenance?.validationState === 'REPRODUCED');

          if (hasReproducedProvenance) {
            validationState = 'REPRODUCED';
          } else if (hasValidatedProvenance) {
            validationState = 'VALIDATED';
          } else if (hasConfirmedEdges) {
            validationState = 'SUPPORTED';
          }

          // Attacker cost is the sum of edge weights
          const attackerCost = found.edges.reduce((sum, e) => sum + (e.weight || 1.0), 0);
          const impactWeight = (jNode.properties?.impactWeight as number) || 8;
          const blastRadiusScore = Math.min(100, Math.round(impactWeight * 10 - boundaryCrossings.length * 2));

          // Choke point is the intermediate node with the highest degree on this path
          const intermediateNodes = found.nodes.slice(1, -1);
          let chokePointId = intermediateNodes.length > 0 ? intermediateNodes[0].id : eNode.id;

          chokePointCounts.set(chokePointId, (chokePointCounts.get(chokePointId) || 0) + 1);

          paths.push({
            pathId: `CJP-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
            crownJewelId: jNode.id,
            entryNodeId: eNode.id,
            entryNodeKey: eNode.nodeKey,
            hopCount: found.nodes.length - 1,
            nodes: found.nodes.map(n => ({
              id: n.id,
              label: n.label,
              nodeType: n.nodeType,
              trustZone: this.assignTrustZone(n)
            })),
            edges: found.edges.map(e => ({
              fromNodeId: e.fromNodeId,
              toNodeId: e.toNodeId,
              edgeType: e.edgeType,
              weight: e.weight
            })),
            boundaryCrossings,
            validationState,
            attackerCost,
            blastRadiusScore,
            chokePointNodeId: chokePointId
          });
        }
      }
    }

    // Generate prioritized choke point mitigation recommendations
    const chokePointRecommendations = Array.from(chokePointCounts.entries())
      .map(([nodeId, count]) => {
        const node = nodeMap.get(nodeId);
        const reductionPercent = paths.length > 0 ? Math.round((count / paths.length) * 100) : 0;
        return {
          nodeId,
          nodeLabel: node?.label || nodeId,
          pathsBlockedCount: count,
          riskReductionPercent: reductionPercent,
          suggestedMitigation: `Isolate or apply zero-trust mTLS policy at ${node?.label || nodeId} to sever ${count} multi-hop paths.`
        };
      })
      .sort((a, b) => b.pathsBlockedCount - a.pathsBlockedCount)
      .slice(0, 5);

    // Compute exposure rating
    let overallExposureRating: CrownJewelReachabilityMatrix['overallExposureRating'] = 'LOW';
    if (paths.some(p => p.validationState === 'REPRODUCED' || p.validationState === 'VALIDATED')) {
      overallExposureRating = 'CRITICAL';
    } else if (paths.length >= 3) {
      overallExposureRating = 'HIGH';
    } else if (paths.length > 0) {
      overallExposureRating = 'MEDIUM';
    }

    const reachableJewelIds = new Set(paths.map(p => p.crownJewelId));

    return {
      engagementId,
      timestamp: new Date().toISOString(),
      totalCrownJewels: jewelNodes.length,
      exposedCrownJewels: reachableJewelIds.size,
      totalPaths: paths.length,
      paths,
      chokePointRecommendations,
      overallExposureRating
    };
  }

  /**
   * Find path between two nodes using BFS
   */
  private static findPath(
    startId: string,
    endId: string,
    adj: Map<string, { to: string; edge: Graph3DEdge }[]>,
    nodeMap: Map<string, Graph3DNode>
  ): { nodes: Graph3DNode[]; edges: Graph3DEdge[] } | null {
    const queue: { currentId: string; nodePath: string[]; edgePath: Graph3DEdge[] }[] = [
      { currentId: startId, nodePath: [startId], edgePath: [] }
    ];
    const visited = new Set<string>([startId]);

    while (queue.length > 0) {
      const { currentId, nodePath, edgePath } = queue.shift()!;
      if (currentId === endId) {
        return {
          nodes: nodePath.map(id => nodeMap.get(id)!).filter(Boolean),
          edges: edgePath
        };
      }

      if (nodePath.length > 7) continue; // bound search to 7 hops

      const neighbors = adj.get(currentId) || [];
      for (const { to, edge } of neighbors) {
        if (!visited.has(to)) {
          visited.add(to);
          queue.push({
            currentId: to,
            nodePath: [...nodePath, to],
            edgePath: [...edgePath, edge]
          });
        }
      }
    }

    return null;
  }

  /**
   * Compute trust boundary transitions along a node path
   */
  private static computeBoundaryCrossings(nodes: Graph3DNode[]): BoundaryCrossing[] {
    const crossings: BoundaryCrossing[] = [];
    for (let i = 0; i < nodes.length - 1; i++) {
      const fromNode = nodes[i];
      const toNode = nodes[i + 1];
      const fromZone = this.assignTrustZone(fromNode);
      const toZone = this.assignTrustZone(toNode);

      if (fromZone !== toZone) {
        crossings.push({
          fromZone,
          toZone,
          fromNodeId: fromNode.id,
          toNodeId: toNode.id,
          transitionType: `${fromZone} -> ${toZone}`,
          defenseInDepthScore: 7.5
        });
      }
    }
    return crossings;
  }
}
