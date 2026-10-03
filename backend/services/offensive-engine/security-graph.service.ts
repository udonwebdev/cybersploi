import crypto from 'crypto';
import prisma from '../../config/database';

export type NodeType =
  | 'ENGAGEMENT'
  | 'SCOPE'
  | 'DOMAIN'
  | 'SUBDOMAIN'
  | 'DNS_RECORD'
  | 'IP'
  | 'CIDR'
  | 'PORT'
  | 'SERVICE'
  | 'APPLICATION'
  | 'API'
  | 'ENDPOINT'
  | 'PARAMETER'
  | 'IDENTITY'
  | 'ROLE'
  | 'IAM_ROLE'
  | 'PERMISSION'
  | 'CREDENTIAL_REF'
  | 'CROWN_JEWEL'
  | 'VULNERABILITY'
  | 'EVIDENCE'
  | 'ATTACK_PATH'
  | 'REMEDIATION';

export type EdgeType =
  | 'HOSTS'
  | 'EXPOSES'
  | 'CALLS'
  | 'AUTHENTICATES'
  | 'AUTHORIZES'
  | 'ASSUMES_ROLE'
  | 'TRUSTS'
  | 'GRANTS'
  | 'CONTAINS'
  | 'DEPENDS_ON'
  | 'LEADS_TO'
  | 'CONFIRMS'
  | 'DISPROVES'
  | 'MITIGATES'
  | 'RETESTS';

export type ValidationState = 'THEORETICAL' | 'SUPPORTED' | 'VALIDATED' | 'REPRODUCED';

export interface EdgeProvenance {
  confidence: number; // 0.0 - 1.0
  source: string; // e.g. 'RECON_AGENT' | 'STATIC_AST' | 'ACTIVE_VERIFICATION' | 'DIALECTICAL_DEBATE'
  timestamp: string;
  evidenceHash?: string;
  validationState: ValidationState;
}

export interface Graph3DNode {
  id: string;
  nodeType: NodeType;
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
  edgeType: EdgeType;
  weight: number;
  evidenceId?: string | null;
  properties: Record<string, any>;
  provenance?: EdgeProvenance;
  color: string;
}

export interface GraphSnapshot {
  snapshotId: string;
  engagementId: string;
  timestamp: string;
  totalNodes: number;
  totalEdges: number;
  hash: string;
  nodes: Graph3DNode[];
  edges: Graph3DEdge[];
  metrics: OmniscientGraphData['metrics'];
}

export interface GraphDiff {
  engagementId: string;
  baseSnapshotId: string;
  targetSnapshotId: string;
  timestamp: string;
  addedNodes: Graph3DNode[];
  removedNodes: Graph3DNode[];
  modifiedNodes: {
    nodeId: string;
    before: Partial<Graph3DNode>;
    after: Partial<Graph3DNode>;
  }[];
  addedEdges: Graph3DEdge[];
  removedEdges: Graph3DEdge[];
  attackPathDeltas: {
    newPathsDiscovered: number;
    mitigatedPaths: number;
  };
  netRiskDelta: number;
}

export interface OmniscientGraphData {
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

export class SecurityGraphService {
  /**
   * Upsert a node in the Omniscient Security Graph
   */
  public static async upsertNode(
    engagementId: string,
    nodeType: NodeType,
    nodeKey: string,
    label: string,
    properties: Record<string, any> = {}
  ) {
    return prisma.securityGraphNode.upsert({
      where: {
        engagementId_nodeType_nodeKey: {
          engagementId,
          nodeType,
          nodeKey
        }
      },
      update: {
        label,
        properties: JSON.stringify(properties),
        updatedAt: new Date()
      },
      create: {
        engagementId,
        nodeType,
        nodeKey,
        label,
        properties: JSON.stringify(properties)
      }
    });
  }

  /**
   * Upsert a directed relationship edge in the Omniscient Security Graph
   */
  public static async upsertEdge(
    engagementId: string,
    fromNodeId: string,
    toNodeId: string,
    edgeType: EdgeType,
    options: {
      weight?: number;
      evidenceId?: string;
      properties?: Record<string, any>;
      provenance?: EdgeProvenance;
    } = {}
  ) {
    const combinedProperties = {
      ...(options.properties ?? {}),
      ...(options.provenance ? { provenance: options.provenance } : {})
    };

    return prisma.securityGraphEdge.upsert({
      where: {
        engagementId_fromNodeId_toNodeId_edgeType: {
          engagementId,
          fromNodeId,
          toNodeId,
          edgeType
        }
      },
      update: {
        weight: options.weight ?? 1.0,
        evidenceId: options.evidenceId ?? null,
        properties: JSON.stringify(combinedProperties)
      },
      create: {
        engagementId,
        fromNodeId,
        toNodeId,
        edgeType,
        weight: options.weight ?? 1.0,
        evidenceId: options.evidenceId ?? null,
        properties: JSON.stringify(combinedProperties)
      }
    });
  }

  /**
   * Synchronize the graph with all current Prisma models
   * (Engagement, Scope, Assets, Findings, Evidence, AttackPaths, AuthMatrix)
   */
  public static async syncEngagementToGraph(engagementId: string) {
    const engagement = await prisma.engagement.findUnique({
      where: { id: engagementId },
      include: {
        scope: true,
        assets: true,
        findings: {
          include: {
            evidence: true,
            fromTransitions: true,
            toTransitions: true
          }
        },
        attackPaths: {
          include: {
            transitions: true
          }
        },
        authMatrix: true
      }
    });

    if (!engagement) {
      throw new Error(`Engagement ${engagementId} not found`);
    }

    // 1. Root Engagement Node
    const engNode = await this.upsertNode(
      engagementId,
      'ENGAGEMENT',
      engagement.id,
      `Engagement: ${engagement.name}`,
      {
        status: engagement.status,
        phase: engagement.currentPhase,
        environment: engagement.environment
      }
    );

    // 2. Scope Node & Edge
    if (engagement.scope) {
      const scopeNode = await this.upsertNode(
        engagementId,
        'SCOPE',
        engagement.scope.id,
        `Scope: ${engagement.name}`,
        {
          activePoCAllowed: engagement.scope.activePoCAllowed,
          destructiveAllowed: engagement.scope.destructiveActionsAllowed,
          approvedBy: engagement.scope.approvedBy
        }
      );
      await this.upsertEdge(engagementId, engNode.id, scopeNode.id, 'AUTHORIZES');

      // Add target nodes from scope
      try {
        const targets: any[] = JSON.parse(engagement.scope.allowedTargets || '[]');
        for (const tgt of targets) {
          const targetStr = typeof tgt === 'string' ? tgt : (tgt.host || tgt.cidr || tgt.value || '');
          if (!targetStr) continue;
          const isCidr = targetStr.includes('/');
          const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(targetStr);
          const tgtType: NodeType = isCidr ? 'CIDR' : (isIp ? 'IP' : 'DOMAIN');

          const tgtNode = await this.upsertNode(
            engagementId,
            tgtType,
            targetStr,
            targetStr,
            { inScope: true }
          );
          await this.upsertEdge(engagementId, scopeNode.id, tgtNode.id, 'AUTHORIZES');
        }
      } catch (err) {
        console.warn('Failed parsing scope targets for graph sync', err);
      }
    }

    // 3. Asset Nodes & Edges
    for (const asset of engagement.assets) {
      const assetKey = asset.value || asset.host || asset.id;
      const assetType: NodeType = asset.type === 'ip' ? 'IP' : (asset.type === 'api' ? 'API' : 'DOMAIN');
      const aNode = await this.upsertNode(
        engagementId,
        assetType,
        assetKey,
        asset.description || assetKey,
        {
          host: asset.host,
          port: asset.port,
          protocol: asset.protocol,
          status: asset.verificationStatus
        }
      );
      await this.upsertEdge(engagementId, engNode.id, aNode.id, 'HOSTS');

      // Port/Service edge if port exists
      if (asset.port) {
        const portNode = await this.upsertNode(
          engagementId,
          'PORT',
          `${assetKey}:${asset.port}`,
          `Port ${asset.port}/${asset.protocol || 'tcp'}`,
          { port: asset.port, protocol: asset.protocol }
        );
        await this.upsertEdge(engagementId, aNode.id, portNode.id, 'EXPOSES');
      }
    }

    // 4. Finding & Evidence Nodes & Edges
    for (const finding of engagement.findings) {
      const fNode = await this.upsertNode(
        engagementId,
        'VULNERABILITY',
        finding.id,
        finding.title,
        {
          severity: finding.severity,
          status: finding.status,
          category: finding.category,
          target: finding.target,
          reproducible: finding.reproducible
        }
      );

      // Link target to finding
      const targetNode = await prisma.securityGraphNode.findFirst({
        where: {
          engagementId,
          nodeKey: finding.target
        }
      });
      if (targetNode) {
        await this.upsertEdge(engagementId, targetNode.id, fNode.id, 'EXPOSES');
      }

      // Evidence nodes
      for (const ev of finding.evidence) {
        const evNode = await this.upsertNode(
          engagementId,
          'EVIDENCE',
          ev.id,
          `Proof: ${ev.actionId}`,
          {
            hash: ev.hash,
            timestamp: ev.timestamp,
            observation: ev.observation,
            reproductionSteps: ev.reproductionSteps
          }
        );
        await this.upsertEdge(
          engagementId,
          evNode.id,
          fNode.id,
          finding.status === 'PROVEN' ? 'CONFIRMS' : 'LEADS_TO',
          { evidenceId: ev.id }
        );
      }
    }

    // 5. Attack Path Nodes & Edges
    for (const path of engagement.attackPaths) {
      const pathNode = await this.upsertNode(
        engagementId,
        'ATTACK_PATH',
        path.id,
        path.title,
        {
          status: path.status,
          description: path.description
        }
      );

      for (const trans of path.transitions) {
        const fromNode = await prisma.securityGraphNode.findFirst({
          where: { engagementId, nodeType: 'VULNERABILITY', nodeKey: trans.fromFindingId }
        });
        const toNode = await prisma.securityGraphNode.findFirst({
          where: { engagementId, nodeType: 'VULNERABILITY', nodeKey: trans.toFindingId }
        });

        if (fromNode && toNode) {
          await this.upsertEdge(
            engagementId,
            fromNode.id,
            toNode.id,
            'LEADS_TO',
            {
              weight: trans.hasValidEvidence ? 0.5 : 2.0,
              evidenceId: trans.evidenceId || undefined,
              properties: { hasValidEvidence: trans.hasValidEvidence }
            }
          );
          await this.upsertEdge(engagementId, pathNode.id, toNode.id, 'LEADS_TO');
        }
      }
    }

    // 6. Auth Matrix Identity & Role Nodes
    for (const record of engagement.authMatrix) {
      const roleNode = await this.upsertNode(
        engagementId,
        'ROLE',
        record.role,
        `Role: ${record.role}`,
        { role: record.role }
      );

      const opNode = await this.upsertNode(
        engagementId,
        'ENDPOINT',
        record.operation,
        record.operation,
        { operation: record.operation }
      );

      await this.upsertEdge(
        engagementId,
        roleNode.id,
        opNode.id,
        record.observed === 'ALLOWED' ? 'AUTHORIZES' : 'DISPROVES',
        {
          properties: {
            expected: record.expected,
            observed: record.observed,
            result: record.result
          }
        }
      );
    }
  }

  /**
   * Fetch graph data and compute 3D topology coordinates
   */
  public static async getOmniscientGraph3D(engagementId: string): Promise<OmniscientGraphData> {
    // Ensure graph is synchronized
    await this.syncEngagementToGraph(engagementId);

    const [nodes, edges] = await Promise.all([
      prisma.securityGraphNode.findMany({
        where: { engagementId }
      }),
      prisma.securityGraphEdge.findMany({
        where: { engagementId }
      })
    ]);

    // Color and size map per nodeType
    const styleMap: Record<NodeType, { color: string; size: number; layerY: number }> = {
      ENGAGEMENT: { color: '#38bdf8', size: 18, layerY: 200 },
      SCOPE: { color: '#06b6d4', size: 14, layerY: 150 },
      CIDR: { color: '#6366f1', size: 12, layerY: 100 },
      DOMAIN: { color: '#3b82f6', size: 12, layerY: 80 },
      SUBDOMAIN: { color: '#60a5fa', size: 10, layerY: 60 },
      IP: { color: '#0ea5e9', size: 10, layerY: 40 },
      PORT: { color: '#14b8a6', size: 8, layerY: 20 },
      SERVICE: { color: '#10b981', size: 9, layerY: 0 },
      APPLICATION: { color: '#2dd4bf', size: 10, layerY: -20 },
      API: { color: '#8b5cf6', size: 11, layerY: -40 },
      ENDPOINT: { color: '#a855f7', size: 9, layerY: -60 },
      PARAMETER: { color: '#c084fc', size: 7, layerY: -80 },
      ROLE: { color: '#f59e0b', size: 10, layerY: 50 },
      IAM_ROLE: { color: '#ea580c', size: 11, layerY: 45 },
      IDENTITY: { color: '#fbbf24', size: 8, layerY: 30 },
      PERMISSION: { color: '#ca8a04', size: 7, layerY: 25 },
      CREDENTIAL_REF: { color: '#eab308', size: 9, layerY: 10 },
      CROWN_JEWEL: { color: '#f43f5e', size: 20, layerY: -160 },
      DNS_RECORD: { color: '#38bdf8', size: 9, layerY: 70 },
      VULNERABILITY: { color: '#ef4444', size: 13, layerY: -100 },
      EVIDENCE: { color: '#10b981', size: 10, layerY: -140 },
      ATTACK_PATH: { color: '#f43f5e', size: 15, layerY: -180 },
      REMEDIATION: { color: '#22c55e', size: 10, layerY: -220 }
    };

    // Calculate deterministic 3D positions in cylindrical/spherical clusters
    const nodesCountByType: Record<string, number> = {};
    nodes.forEach(n => {
      nodesCountByType[n.nodeType] = (nodesCountByType[n.nodeType] || 0) + 1;
    });

    const currentIdxByType: Record<string, number> = {};

    const nodes3D: Graph3DNode[] = nodes.map(n => {
      const type = n.nodeType as NodeType;
      const style = styleMap[type] || { color: '#94a3b8', size: 8, layerY: 0 };
      const totalInType = nodesCountByType[type] || 1;
      const idx = currentIdxByType[type] || 0;
      currentIdxByType[type] = idx + 1;

      // Circular distribution on XZ plane at designated Y elevation
      const radius = Math.min(400, Math.max(80, totalInType * 25));
      const angle = (idx / totalInType) * 2 * Math.PI;

      // Small jitter for natural look
      const jitterX = Math.sin(idx * 7) * 15;
      const jitterZ = Math.cos(idx * 7) * 15;

      const x = Math.round(Math.cos(angle) * radius + jitterX);
      const z = Math.round(Math.sin(angle) * radius + jitterZ);
      const y = style.layerY;

      let parsedProps = {};
      try {
        parsedProps = JSON.parse(n.properties || '{}');
      } catch {}

      return {
        id: n.id,
        nodeType: type,
        nodeKey: n.nodeKey,
        label: n.label,
        properties: parsedProps,
        x,
        y,
        z,
        color: style.color,
        size: style.size
      };
    });

    const edgeColorMap: Record<EdgeType, string> = {
      HOSTS: '#38bdf8',
      EXPOSES: '#0ea5e9',
      CALLS: '#818cf8',
      AUTHENTICATES: '#f59e0b',
      AUTHORIZES: '#10b981',
      ASSUMES_ROLE: '#ea580c',
      TRUSTS: '#8b5cf6',
      GRANTS: '#ca8a04',
      CONTAINS: '#06b6d4',
      DEPENDS_ON: '#64748b',
      LEADS_TO: '#f43f5e',
      CONFIRMS: '#10b981',
      DISPROVES: '#94a3b8',
      MITIGATES: '#22c55e',
      RETESTS: '#06b6d4'
    };

    const edges3D: Graph3DEdge[] = edges.map(e => {
      const edgeType = e.edgeType as EdgeType;
      let parsedProps: Record<string, any> = {};
      try {
        parsedProps = JSON.parse(e.properties || '{}');
      } catch {}

      return {
        id: e.id,
        fromNodeId: e.fromNodeId,
        toNodeId: e.toNodeId,
        edgeType,
        weight: e.weight,
        evidenceId: e.evidenceId,
        properties: parsedProps,
        provenance: parsedProps.provenance,
        color: edgeColorMap[edgeType] || '#64748b'
      };
    });

    // Compute metrics
    const vulnerabilityCount = nodes.filter(n => n.nodeType === 'VULNERABILITY').length;
    const evidenceCount = nodes.filter(n => n.nodeType === 'EVIDENCE').length;
    const attackPathNodes = nodes.filter(n => n.nodeType === 'ATTACK_PATH');
    const demonstratedChains = attackPathNodes.filter(n => {
      try {
        const p = JSON.parse(n.properties || '{}');
        return p.status === 'DEMONSTRATED';
      } catch {
        return false;
      }
    }).length;

    return {
      engagementId,
      nodes: nodes3D,
      edges: edges3D,
      metrics: {
        totalNodes: nodes.length,
        totalEdges: edges.length,
        vulnerabilityCount,
        evidenceCount,
        attackPathCount: attackPathNodes.length,
        demonstratedChains
      }
    };
  }

  /**
   * Dijkstra shortest path traversal across attack vectors
   */
  public static async findShortestAttackPath(
    engagementId: string,
    startNodeId: string,
    endNodeId: string
  ): Promise<{ path: string[]; totalWeight: number; transitions: any[] }> {
    const edges = await prisma.securityGraphEdge.findMany({
      where: {
        engagementId,
        edgeType: { in: ['LEADS_TO', 'EXPOSES', 'CALLS', 'AUTHORIZES', 'ASSUMES_ROLE', 'TRUSTS', 'GRANTS'] }
      }
    });

    const adjacency: Record<string, { to: string; weight: number; edge: any }[]> = {};
    for (const e of edges) {
      if (!adjacency[e.fromNodeId]) adjacency[e.fromNodeId] = [];
      adjacency[e.fromNodeId].push({ to: e.toNodeId, weight: e.weight, edge: e });
    }

    const distances: Record<string, number> = {};
    const previous: Record<string, string | null> = {};
    const prevEdge: Record<string, any> = {};
    const unvisited = new Set<string>();

    const allNodeIds = new Set<string>();
    edges.forEach(e => {
      allNodeIds.add(e.fromNodeId);
      allNodeIds.add(e.toNodeId);
    });

    for (const id of allNodeIds) {
      distances[id] = Infinity;
      previous[id] = null;
      unvisited.add(id);
    }

    distances[startNodeId] = 0;

    while (unvisited.size > 0) {
      // Node with minimum distance
      let current: string | null = null;
      let minDistance = Infinity;
      for (const id of unvisited) {
        if (distances[id] < minDistance) {
          minDistance = distances[id];
          current = id;
        }
      }

      if (!current || minDistance === Infinity) break;
      if (current === endNodeId) break;

      unvisited.delete(current);

      const neighbors = adjacency[current] || [];
      for (const neighbor of neighbors) {
        if (!unvisited.has(neighbor.to)) continue;
        const alt = distances[current] + neighbor.weight;
        if (alt < distances[neighbor.to]) {
          distances[neighbor.to] = alt;
          previous[neighbor.to] = current;
          prevEdge[neighbor.to] = neighbor.edge;
        }
      }
    }

    if (distances[endNodeId] === Infinity) {
      return { path: [], totalWeight: Infinity, transitions: [] };
    }

    const path: string[] = [];
    const transitions: any[] = [];
    let curr: string | null = endNodeId;

    while (curr) {
      path.unshift(curr);
      if (prevEdge[curr]) {
        transitions.unshift(prevEdge[curr]);
      }
      curr = previous[curr];
    }

    return {
      path,
      totalWeight: distances[endNodeId],
      transitions
    };
  }

  // ============ GRAPH SNAPSHOTS & TEMPORAL DIFFING ============

  private static snapshotStore = new Map<string, GraphSnapshot>();
  private static engagementSnapshots = new Map<string, string[]>();

  /**
   * Captures an immutable point-in-time snapshot of the security graph
   */
  public static async createSnapshot(engagementId: string): Promise<GraphSnapshot> {
    const graphData = await this.getOmniscientGraph3D(engagementId);
    const snapshotId = `SNAP-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const serialized = JSON.stringify({ nodes: graphData.nodes, edges: graphData.edges });
    const hash = crypto.createHash('sha256').update(serialized).digest('hex');

    const snapshot: GraphSnapshot = {
      snapshotId,
      engagementId,
      timestamp: new Date().toISOString(),
      totalNodes: graphData.nodes.length,
      totalEdges: graphData.edges.length,
      hash,
      nodes: graphData.nodes,
      edges: graphData.edges,
      metrics: graphData.metrics
    };

    this.snapshotStore.set(snapshotId, snapshot);
    const engList = this.engagementSnapshots.get(engagementId) || [];
    engList.push(snapshotId);
    this.engagementSnapshots.set(engagementId, engList);

    return snapshot;
  }

  /**
   * List all snapshots for an engagement in chronological order
   */
  public static listSnapshots(engagementId: string): GraphSnapshot[] {
    const ids = this.engagementSnapshots.get(engagementId) || [];
    return ids.map(id => this.snapshotStore.get(id)!).filter(Boolean);
  }

  /**
   * Retrieve a specific snapshot by ID
   */
  public static getSnapshot(snapshotId: string): GraphSnapshot | undefined {
    return this.snapshotStore.get(snapshotId);
  }

  /**
   * Compute structural and risk diff between two graph snapshots
   */
  public static computeGraphDiff(baseSnapshotId: string, targetSnapshotId: string): GraphDiff {
    const base = this.snapshotStore.get(baseSnapshotId);
    const target = this.snapshotStore.get(targetSnapshotId);

    if (!base) {
      throw new Error(`Base snapshot not found: ${baseSnapshotId}`);
    }
    if (!target) {
      throw new Error(`Target snapshot not found: ${targetSnapshotId}`);
    }

    const baseNodeKeys = new Map(base.nodes.map(n => [`${n.nodeType}:${n.nodeKey}`, n]));
    const targetNodeKeys = new Map(target.nodes.map(n => [`${n.nodeType}:${n.nodeKey}`, n]));

    const addedNodes: Graph3DNode[] = [];
    const modifiedNodes: GraphDiff['modifiedNodes'] = [];

    for (const [key, tNode] of targetNodeKeys.entries()) {
      const bNode = baseNodeKeys.get(key);
      if (!bNode) {
        addedNodes.push(tNode);
      } else if (bNode.label !== tNode.label || JSON.stringify(bNode.properties) !== JSON.stringify(tNode.properties)) {
        modifiedNodes.push({
          nodeId: tNode.id,
          before: { label: bNode.label, properties: bNode.properties },
          after: { label: tNode.label, properties: tNode.properties }
        });
      }
    }

    const removedNodes: Graph3DNode[] = [];
    for (const [key, bNode] of baseNodeKeys.entries()) {
      if (!targetNodeKeys.has(key)) {
        removedNodes.push(bNode);
      }
    }

    const baseEdgeKeys = new Set(base.edges.map(e => `${e.fromNodeId}->${e.toNodeId}:${e.edgeType}`));
    const targetEdgeKeys = new Set(target.edges.map(e => `${e.fromNodeId}->${e.toNodeId}:${e.edgeType}`));

    const addedEdges = target.edges.filter(e => !baseEdgeKeys.has(`${e.fromNodeId}->${e.toNodeId}:${e.edgeType}`));
    const removedEdges = base.edges.filter(e => !targetEdgeKeys.has(`${e.fromNodeId}->${e.toNodeId}:${e.edgeType}`));

    // Attack path deltas
    const newPaths = target.metrics.attackPathCount - base.metrics.attackPathCount;
    const mitigated = base.metrics.vulnerabilityCount > target.metrics.vulnerabilityCount
      ? base.metrics.vulnerabilityCount - target.metrics.vulnerabilityCount
      : 0;

    // Risk delta formula
    const baseRisk = base.metrics.vulnerabilityCount * 10 + base.metrics.attackPathCount * 15;
    const targetRisk = target.metrics.vulnerabilityCount * 10 + target.metrics.attackPathCount * 15;
    const netRiskDelta = targetRisk - baseRisk;

    return {
      engagementId: target.engagementId,
      baseSnapshotId,
      targetSnapshotId,
      timestamp: new Date().toISOString(),
      addedNodes,
      removedNodes,
      modifiedNodes,
      addedEdges,
      removedEdges,
      attackPathDeltas: {
        newPathsDiscovered: Math.max(0, newPaths),
        mitigatedPaths: mitigated
      },
      netRiskDelta
    };
  }
}
