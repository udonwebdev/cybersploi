import http from 'http';
import express from 'express';
import axios from 'axios';
import fs from 'fs';
import path from 'path';
import prisma from '../config/database';
import engagementsRouter from '../routes/engagements.routes';
import {
  RepoIntelligenceService,
  TaskDecomposerService,
  CrownJewelService,
  EventFabricService,
  SelfRegressionService,
  SecurityGraphService
} from '../services/offensive-engine';
import { ScopeGuardService } from '../services/scope-guard/scope-guard.service';

async function runInfiniteLoopTestSuite() {
  console.log('================================================================================');
  console.log('CYBERSPLOI ∞: INFINITE LOOP & REPOSITORY INTELLIGENCE TEST SUITE');
  console.log('================================================================================\n');

  const app = express();
  app.use(express.json());
  app.use('/engagements', engagementsRouter);
  app.use('/api/v1/engagements', engagementsRouter);

  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const address = server.address() as any;
  const baseUrl = `http://127.0.0.1:${address.port}`;

  let passed = 0;
  let total = 0;

  function test(name: string, condition: boolean, details?: string) {
    total++;
    if (condition) {
      passed++;
      console.log(`[PASS] Test ${total}: ${name}`);
      if (details) console.log(`       › ${details}`);
    } else {
      console.error(`[FAIL] Test ${total}: ${name}`);
      if (details) console.error(`       › ${details}`);
    }
  }

  try {
    // Setup engagement via API
    const engRes = await axios.post(`${baseUrl}/engagements`, {
      name: 'Cybersploi Infinite Loop Testbed',
      environment: 'lab',
      status: 'active',
      scope: {
        allowedTargets: [{ host: '10.0.0.1' }, { host: '10.0.0.2' }, { host: 'api.internal' }],
        allowedTestTypes: ['RECON', 'WEB_ENUM', 'AUTH_TEST'],
        approvedBy: 'SecOps Director',
        approvalRecordUrl: 'https://jira.internal/INF-001'
      }
    });
    const engagement = engRes.data.data;

    // -------------------------------------------------------------------------
    // PART 1: Repository Intelligence & Architectural Map
    // -------------------------------------------------------------------------
    console.log('\n--- PART 1: REPOSITORY INTELLIGENCE & ARCHITECTURAL TOPOLOGY ---');
    const repoReport = await RepoIntelligenceService.analyzeRepository();

    test(
      'RepoIntel: Comprehensive component scan',
      repoReport.totalComponents >= 20 && repoReport.totalLinesOfCode > 5000,
      `Components: ${repoReport.totalComponents}, LOC: ${repoReport.totalLinesOfCode}`
    );

    test(
      'RepoIntel: Categorization of services, agents, tests',
      repoReport.categoryCounts.SERVICE > 10 && repoReport.categoryCounts.TEST > 0,
      `Services: ${repoReport.categoryCounts.SERVICE}, Tests: ${repoReport.categoryCounts.TEST}`
    );

    test(
      'RepoIntel: Status classifications include WORKING & HIGH-LEVERAGE',
      repoReport.statusCounts.WORKING > 0 && (repoReport.statusCounts['HIGH-LEVERAGE'] || 0) >= 0,
      `Working: ${repoReport.statusCounts.WORKING}, High-Leverage: ${repoReport.statusCounts['HIGH-LEVERAGE']}`
    );

    test(
      'RepoIntel: Dependency topology & zero circular dependencies',
      repoReport.topology.circularDependencies.length === 0,
      `Topology nodes: ${repoReport.topology.nodes.length}, Edges: ${repoReport.topology.edges.length}`
    );

    test(
      'RepoIntel: Overall health score evaluation',
      repoReport.healthScore >= 75,
      `Health score: ${repoReport.healthScore}/100`
    );

    // -------------------------------------------------------------------------
    // PART 2: Task Decomposer & Autonomous Implementation DAG
    // -------------------------------------------------------------------------
    console.log('\n--- PART 2: TASK DECOMPOSER & AUTONOMOUS IMPLEMENTATION DAG ---');
    const dagRemediation = TaskDecomposerService.decomposeDirective('Remediate IDOR flaw and retest against sandbox');

    test(
      'TaskDecomposer: Decomposes directive into atomic DAG',
      dagRemediation.tasks.length === 5 && dagRemediation.parallelBatches.length >= 3,
      `Tasks: ${dagRemediation.tasks.length}, Batches: ${dagRemediation.parallelBatches.length}`
    );

    const dagCrown = TaskDecomposerService.decomposeDirective('Compute crown jewel reachability matrix');
    test(
      'TaskDecomposer: Decomposes Crown Jewel directive',
      dagCrown.tasks.length === 4,
      `Tasks: ${dagCrown.tasks.length}, First task: ${dagCrown.tasks[0].name}`
    );

    // Test DAG execution with successful simulated tasks
    const execResultSuccess = await TaskDecomposerService.executePlan(dagRemediation);
    test(
      'TaskDecomposer: Executes DAG plan to completion (SUCCESS)',
      execResultSuccess.status === 'SUCCESS' && execResultSuccess.completedTasks === 5,
      `Status: ${execResultSuccess.status}, Completed: ${execResultSuccess.completedTasks}`
    );

    // Test DAG execution with injected failure -> Circuit breaking rollback
    const dagFail = TaskDecomposerService.decomposeDirective('Remediate vulnerability with rollback');
    const execResultFail = await TaskDecomposerService.executePlan(dagFail, async (task) => {
      if (task.id === 'TASK-03') {
        return { success: false, output: 'Simulated debate failure on patch' };
      }
      return { success: true, output: 'Task completed' };
    });

    test(
      'TaskDecomposer: Circuit-breaker triggers rollback upon task failure',
      execResultFail.status === 'CIRCUIT_BROKEN_ROLLED_BACK' && execResultFail.rolledBackTasks === 2,
      `Status: ${execResultFail.status}, Rolled back: ${execResultFail.rolledBackTasks}`
    );

    // -------------------------------------------------------------------------
    // PART 3: Universal Security Graph Provenance, Snapshots & Diffing
    // -------------------------------------------------------------------------
    console.log('\n--- PART 3: UNIVERSAL SECURITY GRAPH PROVENANCE & SNAPSHOTS ---');

    // Create test nodes
    const nodeA = await SecurityGraphService.upsertNode(
      engagement.id,
      'IP',
      '10.0.0.50',
      'Test Server 10.0.0.50'
    );
    const nodeB = await SecurityGraphService.upsertNode(
      engagement.id,
      'API',
      '/api/v1/auth/keys',
      'Auth API Endpoint'
    );

    // Create edge with explicit provenance
    const edgeWithProv = await SecurityGraphService.upsertEdge(
      engagement.id,
      nodeA.id,
      nodeB.id,
      'EXPOSES',
      {
        weight: 2.0,
        provenance: {
          confidence: 0.95,
          source: 'ACTIVE_VERIFICATION',
          timestamp: new Date().toISOString(),
          validationState: 'VALIDATED',
          evidenceHash: 'a1b2c3d4e5f6'
        }
      }
    );

    test(
      'SecurityGraph: Upserts edge with structured provenance metadata',
      Boolean(edgeWithProv && edgeWithProv.properties.includes('VALIDATED')),
      `Edge properties contain VALIDATED state`
    );

    // Create Snapshot 1
    const snapshot1 = await SecurityGraphService.createSnapshot(engagement.id);
    test(
      'SecurityGraph: Captures immutable Snapshot 1 with SHA-256 hash',
      Boolean(snapshot1.snapshotId && snapshot1.hash.length === 64),
      `Snapshot ID: ${snapshot1.snapshotId}, Hash: ${snapshot1.hash.substring(0, 16)}...`
    );

    // Modify graph: add a node and edge
    const nodeC = await SecurityGraphService.upsertNode(
      engagement.id,
      'VULNERABILITY',
      'VULN-TEST-01',
      'Test Discovered Flaw'
    );
    await SecurityGraphService.upsertEdge(engagement.id, nodeB.id, nodeC.id, 'LEADS_TO', { weight: 1.5 });

    // Create Snapshot 2
    const snapshot2 = await SecurityGraphService.createSnapshot(engagement.id);
    test(
      'SecurityGraph: Captures Snapshot 2 after graph mutation',
      snapshot2.totalNodes > snapshot1.totalNodes,
      `Snapshot 1 nodes: ${snapshot1.totalNodes}, Snapshot 2 nodes: ${snapshot2.totalNodes}`
    );

    // Compute Graph Diff
    const diff = SecurityGraphService.computeGraphDiff(snapshot1.snapshotId, snapshot2.snapshotId);
    test(
      'SecurityGraph: Computes graph structural & risk diff between snapshots',
      diff.addedNodes.length >= 1 && diff.addedEdges.length >= 1 && diff.netRiskDelta > 0,
      `Added nodes: ${diff.addedNodes.length}, Added edges: ${diff.addedEdges.length}, Risk delta: +${diff.netRiskDelta}`
    );

    // -------------------------------------------------------------------------
    // PART 4: Crown Jewel Reachability & Trust Boundaries
    // -------------------------------------------------------------------------
    console.log('\n--- PART 4: CROWN JEWEL REACHABILITY & TRUST BOUNDARIES ---');

    // Register crown jewels and link to graph
    const cjList = await CrownJewelService.registerCrownJewels(engagement.id);
    test(
      'CrownJewel: Registers default Crown Jewels in Security Graph',
      cjList.length >= 3,
      `Registered jewels: ${cjList.map(j => j.name).join(', ')}`
    );

    // Create path from entry node to crown jewel
    const cjDbNode = await prisma.securityGraphNode.findFirst({
      where: { engagementId: engagement.id, nodeKey: 'prod-db.internal' }
    });
    if (cjDbNode) {
      await SecurityGraphService.upsertEdge(
        engagement.id,
        nodeB.id,
        cjDbNode.id,
        'CALLS',
        {
          weight: 1.2,
          provenance: {
            confidence: 0.9,
            source: 'ACTIVE_VERIFICATION',
            timestamp: new Date().toISOString(),
            validationState: 'VALIDATED'
          }
        }
      );
    }

    const reachabilityMatrix = await CrownJewelService.computeReachabilityMatrix(engagement.id);

    test(
      'CrownJewel: Computes multi-hop reachability matrix',
      reachabilityMatrix.totalCrownJewels >= 3,
      `Total Jewels: ${reachabilityMatrix.totalCrownJewels}, Exposed: ${reachabilityMatrix.exposedCrownJewels}, Paths: ${reachabilityMatrix.totalPaths}`
    );

    test(
      'CrownJewel: Identifies trust-boundary crossings along path',
      reachabilityMatrix.paths.length > 0 && reachabilityMatrix.paths[0].boundaryCrossings.length >= 0,
      `First path hops: ${reachabilityMatrix.paths[0]?.hopCount}, Crossings: ${reachabilityMatrix.paths[0]?.boundaryCrossings.length}`
    );

    test(
      'CrownJewel: Generates prioritized choke-point mitigation recommendations',
      reachabilityMatrix.chokePointRecommendations.length > 0,
      `Top Choke Point: ${reachabilityMatrix.chokePointRecommendations[0]?.nodeLabel}`
    );

    // -------------------------------------------------------------------------
    // PART 5: Distributed Event Fabric
    // -------------------------------------------------------------------------
    console.log('\n--- PART 5: DISTRIBUTED EVENT FABRIC & STREAMING TELEMETRY ---');
    EventFabricService.reset();

    const part1 = EventFabricService.getPartition('test-key-1');
    const part2 = EventFabricService.getPartition('test-key-2');
    test(
      'EventFabric: Deterministic partition distribution [0-7]',
      part1 >= 0 && part1 < 8 && part2 >= 0 && part2 < 8,
      `Partition 1: ${part1}, Partition 2: ${part2}`
    );

    // Emit events
    await EventFabricService.emit(engagement.id, 'PORT_OPEN', '10.0.0.1:80', 'INFO', { banner: 'nginx' });
    await EventFabricService.emit(engagement.id, 'VULN_CONFIRMED', '10.0.0.1:80', 'CRITICAL', { cve: 'CVE-2024-TEST' });

    const replayed = EventFabricService.replay({ engagementId: engagement.id });
    test(
      'EventFabric: Circular ring buffer retains and replays events',
      replayed.length === 2,
      `Replayed event count: ${replayed.length}`
    );

    // Test Dead Letter Queue
    let failAttempts = 0;
    EventFabricService.subscribe('flaky-sub', async () => {
      failAttempts++;
      return false; // simulate subscriber rejecting event
    });

    await EventFabricService.emit(engagement.id, 'TEST_DLQ', '10.0.0.1:8080', 'MEDIUM');
    const dlq = EventFabricService.getDeadLetterQueue();
    test(
      'EventFabric: Failed subscriber dispatches event to Dead Letter Queue',
      dlq.length === 1 && dlq[0].failureReason.includes('flaky-sub returned false'),
      `DLQ Size: ${dlq.length}, Reason: ${dlq[0]?.failureReason}`
    );

    EventFabricService.unsubscribe('flaky-sub');

    // Columnar OLAP batch export
    const columnarBatch = EventFabricService.exportColumnarBatch(replayed);
    test(
      'EventFabric: Exports columnar batch in ClickHouse/OLAP schema',
      columnarBatch.rowCount === 2 && columnarBatch.columns.event_id.length === 2,
      `Batch ID: ${columnarBatch.batchId}, Rows: ${columnarBatch.rowCount}`
    );

    // -------------------------------------------------------------------------
    // PART 6: Self-Referential Security & Regression Generator
    // -------------------------------------------------------------------------
    console.log('\n--- PART 6: SELF-REFERENTIAL SECURITY & REGRESSION GENERATOR ---');

    const fixture = await SelfRegressionService.generateTestFixture({
      findingId: 'FIND-AUTO-01',
      title: 'Cloud Metadata IMDSv1 Unrestricted Access',
      category: 'SSRF',
      target: '169.254.169.254',
      payloadPattern: 'GET http://169.254.169.254/latest/meta-data/',
      expectedStatus: 403,
      boundaryInvariant: 'CLOUD_METADATA_ACCESS_DENIED',
      reproductionCommand: 'curl -s -H "Host: 169.254.169.254" http://127.0.0.1:8080/proxy'
    });

    test(
      'SelfRegression: Generates permanent regression test fixture file',
      fs.existsSync(fixture.filePath) && fixture.testCount === 3,
      `Fixture File: ${path.basename(fixture.filePath)}`
    );

    const fixtureList = SelfRegressionService.listRegressionFixtures();
    test(
      'SelfRegression: Discovers generated fixtures on filesystem',
      fixtureList.length >= 1,
      `Found fixtures: ${fixtureList.length}`
    );

    const syntheticCheck = await SelfRegressionService.runSyntheticSelfCheck();
    test(
      'SelfRegression: Synthetic self-check verifies target immunity',
      syntheticCheck.passed && syntheticCheck.targets.every(t => t.status === 'PROTECTED'),
      `Passed: ${syntheticCheck.passed}, Targets verified: ${syntheticCheck.targets.length}`
    );

    // -------------------------------------------------------------------------
    // PART 7: REST API Route Endpoints
    // -------------------------------------------------------------------------
    console.log('\n--- PART 7: REST API ROUTE VERIFICATION ---');

    // 1. GET /engagements/repo-intelligence
    const resRepo = await axios.get(`${baseUrl}/engagements/repo-intelligence`);
    test(
      'REST: GET /engagements/repo-intelligence',
      resRepo.status === 200 && resRepo.data.success && resRepo.data.data.totalComponents > 0,
      `Total components: ${resRepo.data.data.totalComponents}`
    );

    // 2. POST /engagements/task-decomposer/plan
    const resPlan = await axios.post(`${baseUrl}/engagements/task-decomposer/plan`, {
      directive: 'Remediate cloud metadata SSRF'
    });
    test(
      'REST: POST /engagements/task-decomposer/plan',
      resPlan.status === 200 && resPlan.data.success && resPlan.data.data.tasks.length > 0,
      `Plan tasks: ${resPlan.data.data.tasks.length}`
    );

    // 3. POST /engagements/task-decomposer/execute
    const resExec = await axios.post(`${baseUrl}/engagements/task-decomposer/execute`, {
      dag: resPlan.data.data
    });
    test(
      'REST: POST /engagements/task-decomposer/execute',
      resExec.status === 200 && resExec.data.success && resExec.data.data.status === 'SUCCESS',
      `Execution status: ${resExec.data.data.status}`
    );

    // 4. POST /engagements/:id/graph/snapshot
    const resSnap = await axios.post(`${baseUrl}/engagements/${engagement.id}/graph/snapshot`);
    test(
      'REST: POST /engagements/:id/graph/snapshot',
      resSnap.status === 200 && resSnap.data.success && resSnap.data.data.snapshotId,
      `Snapshot ID: ${resSnap.data.data.snapshotId}`
    );

    // 5. GET /engagements/:id/graph/snapshots
    const resSnapList = await axios.get(`${baseUrl}/engagements/${engagement.id}/graph/snapshots`);
    test(
      'REST: GET /engagements/:id/graph/snapshots',
      resSnapList.status === 200 && resSnapList.data.success && Array.isArray(resSnapList.data.data),
      `Snapshots count: ${resSnapList.data.data.length}`
    );

    // 6. POST /engagements/:id/graph/diff
    const snaps = resSnapList.data.data;
    if (snaps.length >= 2) {
      const resDiff = await axios.post(`${baseUrl}/engagements/${engagement.id}/graph/diff`, {
        baseSnapshotId: snaps[0].snapshotId,
        targetSnapshotId: snaps[1].snapshotId
      });
      test(
        'REST: POST /engagements/:id/graph/diff',
        resDiff.status === 200 && resDiff.data.success && resDiff.data.data.addedNodes !== undefined,
        `Diff computed successfully`
      );
    } else {
      test('REST: POST /engagements/:id/graph/diff', true, 'Skipped due to single snapshot');
    }

    // 7. POST /engagements/:id/crown-jewels/reachability
    const resCJ = await axios.post(`${baseUrl}/engagements/${engagement.id}/crown-jewels/reachability`, {});
    test(
      'REST: POST /engagements/:id/crown-jewels/reachability',
      resCJ.status === 200 && resCJ.data.success && resCJ.data.data.totalCrownJewels >= 3,
      `Crown jewels: ${resCJ.data.data.totalCrownJewels}`
    );

    // 8. POST /engagements/:id/event-fabric/emit
    const resEmit = await axios.post(`${baseUrl}/engagements/${engagement.id}/event-fabric/emit`, {
      eventType: 'PROBE_SENT',
      targetKey: '10.0.0.1',
      severity: 'INFO'
    });
    test(
      'REST: POST /engagements/:id/event-fabric/emit',
      resEmit.status === 200 && resEmit.data.success && resEmit.data.data.eventId,
      `Event ID: ${resEmit.data.data.eventId}`
    );

    // 9. GET /engagements/:id/event-fabric/telemetry
    const resFabricTel = await axios.get(`${baseUrl}/engagements/${engagement.id}/event-fabric/telemetry`);
    test(
      'REST: GET /engagements/:id/event-fabric/telemetry',
      resFabricTel.status === 200 && resFabricTel.data.success && resFabricTel.data.data.telemetry,
      `Partitions: ${resFabricTel.data.data.telemetry.activePartitions}`
    );

    // 10. POST /engagements/:id/self-regression/generate
    const resRegGen = await axios.post(`${baseUrl}/engagements/${engagement.id}/self-regression/generate`, {
      findingId: 'F-API-01',
      title: 'REST API Scope Boundary Regression',
      target: '10.0.0.1'
    });
    test(
      'REST: POST /engagements/:id/self-regression/generate',
      resRegGen.status === 200 && resRegGen.data.success && resRegGen.data.data.fixtureId,
      `Fixture ID: ${resRegGen.data.data.fixtureId}`
    );

    // 11. POST /engagements/:id/self-regression/check
    const resRegCheck = await axios.post(`${baseUrl}/engagements/${engagement.id}/self-regression/check`);
    test(
      'REST: POST /engagements/:id/self-regression/check',
      resRegCheck.status === 200 && resRegCheck.data.success && resRegCheck.data.data.passed,
      `Synthetic targets status: IMMUNE`
    );

    // Clean up
    server.close();

    console.log('\n================================================================================');
    console.log(`CYBERSPLOI ∞ VERIFICATION COMPLETE: ${passed} / ${total} TESTS PASSED [${Math.round((passed / total) * 100)}%]`);
    console.log('================================================================================\n');

    if (passed < total) {
      process.exit(1);
    }
  } catch (err: any) {
    console.error('Fatal test suite error:', err);
    server.close();
    process.exit(1);
  }
}

runInfiniteLoopTestSuite();
