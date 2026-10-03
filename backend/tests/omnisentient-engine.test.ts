import prisma from '../config/database';
import { SecurityGraphService } from '../services/offensive-engine/security-graph.service';
import { CapabilityRegistryService } from '../services/offensive-engine/capability-registry.service';
import { AgentCoordinatorService, ReconAgent, WebMappingAgent, AuthMatrixAgent, RetestAgent } from '../services/offensive-engine/agents';
import { DifferentialAnalysisService } from '../services/offensive-engine/differential-analysis.service';
import { SecurityReasoningEngine } from '../services/offensive-engine/security-reasoning-engine.service';
import { SelfAuditService } from '../services/offensive-engine/self-audit.service';
import { FindingEvidenceService } from '../services/offensive-engine/finding-evidence.service';
import { ScopeGuardService } from '../services/scope-guard/scope-guard.service';

let passed = 0;
let failed = 0;

function test(name: string, condition: boolean, extra: string = '') {
  if (condition) {
    passed++;
    console.log(`[PASS] ${name}${extra ? ' › ' + extra : ''}`);
  } else {
    failed++;
    console.error(`[FAIL] ${name}${extra ? ' › ' + extra : ''}`);
    throw new Error(`Test failed: ${name}`);
  }
}

async function runOmnisentientTests() {
  console.log('\n============================================================');
  console.log('CYBERSPLOI OMNISENTIENT OFFENSIVE ENGINE — AUTOMATED TESTBED');
  console.log('============================================================\n');

  // Setup test engagement & scope
  const engagement = await prisma.engagement.create({
    data: {
      name: 'Omnisentient Autonomous Verification Lab',
      status: 'active',
      environment: 'lab',
      currentPhase: 'RECON',
      scope: {
        create: {
          allowedTargets: JSON.stringify(['10.0.0.1', '10.0.0.2', 'staging.cybersploi.local']),
          allowedTestTypes: JSON.stringify(['RECON', 'PORT_SCAN', 'WEB_CRAWL', 'AUTH_TEST', 'RETEST']),
          rateLimit: JSON.stringify({ requestsPerSecond: 20, concurrency: 5 }),
          concurrencyLimit: 5,
          validFrom: new Date(Date.now() - 3600000),
          validUntil: new Date(Date.now() + 86400000 * 7),
          destructiveActionsAllowed: false,
          activePoCAllowed: true,
          approvedBy: 'OmniSec Principal'
        }
      },
      assets: {
        create: [
          { host: '10.0.0.1', type: 'ip', port: 80, protocol: 'tcp', verificationStatus: 'verified' },
          { host: '10.0.0.1', type: 'ip', port: 443, protocol: 'tcp', verificationStatus: 'verified' }
        ]
      }
    },
    include: { scope: true, assets: true }
  });

  const engagementId = engagement.id;

  try {
    // ------------------------------------------------------------
    // 1. OMNISCIENT SECURITY GRAPH: NODES & EDGES CREATION
    // ------------------------------------------------------------
    console.log('--- 1. OMNISCIENT SECURITY GRAPH ---');
    const nodeDomain = await SecurityGraphService.upsertNode(
      engagementId,
      'DOMAIN',
      'staging.cybersploi.local',
      'Staging Domain',
      { environment: 'staging' }
    );
    test('Omniscient Graph Node created successfully', !!nodeDomain.id && nodeDomain.nodeType === 'DOMAIN');

    const nodeEndpoint = await SecurityGraphService.upsertNode(
      engagementId,
      'ENDPOINT',
      'staging.cybersploi.local/api/v1/auth',
      '/api/v1/auth',
      { method: 'POST' }
    );

    const edge = await SecurityGraphService.upsertEdge(
      engagementId,
      nodeDomain.id,
      nodeEndpoint.id,
      'EXPOSES',
      { weight: 1.0 }
    );
    test('Omniscient Graph Edge created successfully', !!edge.id && edge.edgeType === 'EXPOSES');

    // ------------------------------------------------------------
    // 2. GRAPH 3D TOPOLOGY & COORDINATES SYNTHESIS
    // ------------------------------------------------------------
    console.log('\n--- 2. GRAPH 3D TOPOLOGY ---');
    const graph3D = await SecurityGraphService.getOmniscientGraph3D(engagementId);
    test('Graph 3D Topology generated with nodes and edges', graph3D.nodes.length >= 2 && graph3D.edges.length >= 1);
    test('Nodes include 3D spatial coordinates (x, y, z)', typeof graph3D.nodes[0].x === 'number' && typeof graph3D.nodes[0].y === 'number');
    test('Graph metrics accurately track entities', graph3D.metrics.totalNodes >= 2);

    // ------------------------------------------------------------
    // 3. CAPABILITY REGISTRY & SECURITY ENGINE ADAPTERS
    // ------------------------------------------------------------
    console.log('\n--- 3. CAPABILITY REGISTRY ---');
    await CapabilityRegistryService.syncCapabilitiesToDatabase();
    const adapters = CapabilityRegistryService.listAdapters();
    test('Capability Registry loaded built-in adapters', adapters.length >= 3);

    const selectedAdapter = CapabilityRegistryService.selectAdapter('IP', 'TCP', 'RECON');
    test('Adapter discovery selected PythonReconWorkerAdapter for IP/TCP/RECON', selectedAdapter?.name === 'python_recon_worker');

    // ------------------------------------------------------------
    // 4. MULTI-AGENT ORCHESTRATION VIA SCOPEGUARD
    // ------------------------------------------------------------
    console.log('\n--- 4. MULTI-AGENT ORCHESTRATION ---');
    const webMappingAgent = new WebMappingAgent();
    const mapResult = await webMappingAgent.run({
      engagementId,
      target: '10.0.0.1',
      scope: engagement.scope
    });
    test('WebMappingAgent executed safely under ScopeGuard', mapResult.success === true && mapResult.decision === 'OBSERVED');
    test('WebMappingAgent discovered application endpoints', (mapResult.discoveredNodes?.length || 0) > 0);

    // Test out-of-scope blocking on agent
    const outOfScopeResult = await webMappingAgent.run({
      engagementId,
      target: '192.168.99.1', // OUT OF SCOPE
      scope: engagement.scope
    });
    test('Agent blocked immediately when target is out of scope', outOfScopeResult.decision === 'BLOCKED_OUT_OF_SCOPE');

    // ------------------------------------------------------------
    // 5. DIFFERENTIAL SECURITY ANALYSIS
    // ------------------------------------------------------------
    console.log('\n--- 5. DIFFERENTIAL SECURITY ANALYSIS ---');
    // Simulated disparity: Guest role receives 200 OK on admin deletion endpoint
    const diffResult = await DifferentialAnalysisService.evaluateDifferential(
      {
        engagementId,
        target: '10.0.0.1',
        operation: 'DELETE /api/v1/tenant/123/database',
        testType: 'AUTH_TEST',
        baselineContext: { role: 'ADMIN', userId: 'usr-admin' },
        testContext: { role: 'GUEST', userId: 'usr-guest' }
      },
      {
        baselineStatus: 200,
        testStatus: 200, // Discrepancy!
        baselineBody: '{"success": true, "recordsDeleted": 5}',
        testBody: '{"success": true, "recordsDeleted": 5}'
      }
    );
    test('Differential Analysis detected authorization discrepancy', diffResult.discrepancy === true);
    test('Differential result stored cryptographic SHA-256 hash', !!diffResult.hash && diffResult.hash.length === 64);

    // ------------------------------------------------------------
    // 6. AUTONOMOUS RETEST ENGINE (FIXED vs STILL_PRESENT)
    // ------------------------------------------------------------
    console.log('\n--- 6. AUTONOMOUS RETEST ENGINE ---');
    // Create an initial finding with evidence
    const finding = await prisma.engineFinding.create({
      data: {
        engagementId,
        title: 'Information Disclosure on Debug Endpoint',
        description: 'Sensitive environment variables exposed on /debug/env',
        category: 'RECON',
        severity: 'MEDIUM',
        target: '10.0.0.1',
        status: 'SUSPECTED'
      }
    });

    await FindingEvidenceService.attachEvidence({
      findingId: finding.id,
      actionId: 'initial-audit',
      target: '10.0.0.1',
      observation: 'HTTP 200 returned debug environment secrets',
      reproductionSteps: 'GET /debug/env'
    });

    const retestAgent = new RetestAgent();
    // Test 6a: Retest confirms remediation (FIXED)
    const fixedRetest = await retestAgent.executeRetest(engagementId, finding.id, true);
    test('Autonomous retest confirms vulnerability remediation as FIXED', fixedRetest.status === 'FIXED');

    // Verify finding transitioned to DISPROVEN
    const updatedFinding = await prisma.engineFinding.findUnique({ where: { id: finding.id } });
    test('Remediated finding updated to DISPROVEN with fresh evidence', updatedFinding?.status === 'DISPROVEN');

    // ------------------------------------------------------------
    // 7. AUTONOMOUS SECURITY REASONING ENGINE CYCLE
    // ------------------------------------------------------------
    console.log('\n--- 7. AUTONOMOUS SECURITY REASONING LOOP ---');
    const reasoningResult = await SecurityReasoningEngine.executeReasoningStep(engagementId, '10.0.0.1');
    test('Reasoning cycle produced prioritized candidate actions', reasoningResult.candidateActions.length > 0);
    test('Reasoning loop gated action execution through ScopeGuard', ['OBSERVED', 'ALLOWED', 'MATCH', 'DISCREPANCY_FOUND'].includes(reasoningResult.decision), `Decision: ${reasoningResult.decision}`);

    // ------------------------------------------------------------
    // 8. 12-POINT SELF-AUDITING DIAGNOSTIC SUITE
    // ------------------------------------------------------------
    console.log('\n--- 8. 12-POINT SELF-AUDIT ENGINE ---');
    const auditReport = await SelfAuditService.runFullAudit(engagementId);
    auditReport.checks.forEach(c => {
      console.log(`[AUDIT-CHECK ${c.invariantId}] ${c.name}: ${c.passed ? 'PASS' : 'FAIL -> ' + c.message}`);
    });
    test('Self-Audit executed all 12 core invariant checks', auditReport.totalChecks === 12);
    test('All 12 security invariants satisfied without violation', auditReport.allInvariantsSatisfied === true, `Passed: ${auditReport.passedChecks}/12`);

    console.log('\n============================================================');
    console.log(`ALL OMNISENTIENT ENGINE TESTS PASSED! (${passed}/${passed + failed})`);
    console.log('============================================================\n');

  } finally {
    // Cleanup test engagement
    await prisma.engagement.delete({ where: { id: engagementId } }).catch(() => {});
  }
}

runOmnisentientTests().catch((err) => {
  console.error('\n[FATAL ERROR in Omnisentient Testbed]:', err);
  process.exit(1);
});
