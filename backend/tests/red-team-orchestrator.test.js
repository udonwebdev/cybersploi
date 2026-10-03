/**
 * CYBERSPLOI AI Red Team Simulation - Comprehensive Integration Test Suite
 * Validates Scope authorization, 14-phase state transitions, real telemetry,
 * hypothesis lifecycle & false-positive elimination, attack graph, and verification console.
 */

const assert = require('assert');
const axios = require('axios');
const prisma = require('../config/database');
const ScopeAuthorizationService = require('../services/red-team/scope-authorization.service');
const ReconCartographyService = require('../services/red-team/recon-cartography.service');
const HypothesisEngineService = require('../services/red-team/hypothesis-engine.service');
const AttackGraphService = require('../services/red-team/attack-graph.service');
const CoverageBlindSpotService = require('../services/red-team/coverage-blindspot.service');
const VerificationSessionService = require('../services/red-team/verification-session.service');

const API_BASE = 'http://localhost:8000';

async function runTests() {
  console.log('============================================================');
  console.log('CYBERSPLOI AI RED TEAM ENGINE - INTEGRATION TEST SUITE');
  console.log('============================================================\n');

  let passedTests = 0;
  let totalTests = 0;

  function record(name, passed, details = '') {
    totalTests++;
    if (passed) {
      passedTests++;
      console.log(`[PASS] Test ${totalTests}: ${name}`);
      if (details) console.log(`       › ${details}`);
    } else {
      console.error(`[FAIL] Test ${totalTests}: ${name}`);
      if (details) console.error(`       › ${details}`);
    }
  }

  // ------------------------------------------------------------
  // 1. SCOPE AUTHORIZATION ENGINE TESTS
  // ------------------------------------------------------------
  console.log('--- 1. Scope & Authorization Policy Evaluation ---');
  const scopeConfig = {
    allowedDomains: ['example.test', 'api.example.test'],
    allowedIps: ['192.168.1.50'],
    allowedPorts: [80, 443, 22],
    allowedProtocols: ['http', 'https', 'tcp'],
    excludedAssets: ['admin.example.test'],
    excludedPaths: ['/internal/admin']
  };
  const parsedScope = ScopeAuthorizationService.parseScope(scopeConfig, 'example.test');

  const probeInScope = ScopeAuthorizationService.validateProbe({
    host: 'example.test',
    port: 443,
    protocol: 'https',
    path: '/api/v1/health'
  }, parsedScope);
  record('In-scope host, port, protocol & path validation', probeInScope.allowed === true);

  const probeExcludedAsset = ScopeAuthorizationService.validateProbe({
    host: 'admin.example.test',
    port: 443
  }, parsedScope);
  record('Excluded asset rule enforcement', probeExcludedAsset.allowed === false && probeExcludedAsset.reason.includes('matches excluded asset'));

  const probeOutOfScopeHost = ScopeAuthorizationService.validateProbe({
    host: 'unauthorized-external-cdn.net',
    port: 443
  }, parsedScope);
  record('Out-of-scope host rejection (no auto-expansion)', probeOutOfScopeHost.allowed === false && probeOutOfScopeHost.isOutOfScopeDiscovery === true);

  const probeBlockedPort = ScopeAuthorizationService.validateProbe({
    host: 'example.test',
    port: 9999
  }, parsedScope);
  record('Unauthorized port probe rejection', probeBlockedPort.allowed === false && probeBlockedPort.reason.includes('not authorized'));

  // ------------------------------------------------------------
  // 2. REAL LOCAL SOCKET PROBING (PORTS 8000, 8001, 3000)
  // ------------------------------------------------------------
  console.log('\n--- 2. Real TCP Socket & Service Discovery ---');
  const localSweep = await ReconCartographyService.executePortSweep('127.0.0.1', {
    allowedPorts: [8000, 8001, 3000, 9991],
    allowedProtocols: ['tcp'],
    allowedDomains: ['127.0.0.1'],
    allowedIps: ['127.0.0.1'],
    concurrencyLimit: 4
  });

  const discoveredOpenPorts = localSweep.openPorts.map(p => p.port);
  const foundBackend = discoveredOpenPorts.includes(8000);
  const foundAiOrFrontend = discoveredOpenPorts.includes(8001) || discoveredOpenPorts.includes(3000);
  record('Real socket sweep detects active local services (8000 Express / 8001 FastAPI / 3000 Next)', foundBackend && foundAiOrFrontend, `Discovered: ${discoveredOpenPorts.join(', ')}`);

  // ------------------------------------------------------------
  // 3. HYPOTHESIS GENERATION & COUNTER-EVIDENCE REJECTION
  // ------------------------------------------------------------
  console.log('\n--- 3. Hypothesis Engine & False-Positive Elimination ---');
  const testHypotheses = HypothesisEngineService.generateHypotheses({
    host: '127.0.0.1',
    dnsData: { records: { txt: ['v=spf1 include:_spf.google.com ~all'] } },
    portData: { openPorts: [{ port: 8000, service: 'HTTP Dev / API' }] },
    tlsData: { supported: false },
    appData: {
      baseUrl: 'http://127.0.0.1:8000',
      statusCode: 200,
      securityHeaders: { hsts: false, csp: false, xFrameOptions: false },
      cors: { isReflectiveOrigin: false }
    }
  });

  record('Hypothesis generation formulated testable hypotheses', testHypotheses.length >= 2, `Generated ${testHypotheses.length} hypotheses`);

  // Evaluate SPF hypothesis where counter-evidence (valid SPF string) exists
  const spfHypo = testHypotheses.find(h => h.title.includes('Missing SPF'));
  let spfResult = null;
  if (spfHypo) {
    spfResult = await HypothesisEngineService.evaluateHypothesis(spfHypo, { host: '127.0.0.1', scope: parsedScope });
    record('Counter-evidence rejects false positive (SPF valid string present)', spfResult.status === 'REJECTED' && spfResult.rejectionReason.includes('Counter-evidence verified'));
  }

  // ------------------------------------------------------------
  // 4. ATTACK GRAPH & CHAINING GENERATION
  // ------------------------------------------------------------
  console.log('\n--- 4. Attack Graph & Chaining Topology ---');
  const graph = AttackGraphService.generateAttackGraph({
    host: '127.0.0.1',
    dnsData: { records: { a: ['127.0.0.1'] } },
    portData: { openPorts: [{ port: 8000, service: 'API-Gateway' }] },
    tlsData: { supported: false },
    appData: { baseUrl: 'http://127.0.0.1:8000', webServer: 'Express-Node', statusCode: 200 },
    verifiedFindings: [
      {
        title: 'Missing or Permissive Content Security Policy (CSP)',
        severity: 'MEDIUM',
        cvss: '6.1',
        cve: 'VULN-CSP',
        cwe: 'CWE-1021',
        endpoint: '127.0.0.1:8000'
      }
    ]
  });

  const hasTargetNode = graph.nodes.some(n => n.category === 'TARGET');
  const hasServiceNode = graph.nodes.some(n => n.category === 'SERVICE');
  const hasVulnNode = graph.nodes.some(n => n.category === 'VULNERABILITY');
  const hasEdges = graph.edges.length >= 2;
  record('Attack graph nodes & relations generated from telemetry', hasTargetNode && hasServiceNode && hasVulnNode && hasEdges, `${graph.nodes.length} nodes, ${graph.edges.length} edges`);

  // ------------------------------------------------------------
  // 5. CONTROLLED VERIFICATION SESSION & KILL-SWITCH
  // ------------------------------------------------------------
  console.log('\n--- 5. Controlled Verification Session & Operator Kill-Switch ---');
  // Create a temporary test assessment to link session using existing organization
  let existingOrg = await prisma.organization.findFirst();
  if (!existingOrg) {
    const user = await prisma.user.findFirst() || await prisma.user.create({
      data: { email: 'admin@test.com', password: 'hash', firstName: 'Admin', lastName: 'User', username: 'admin' }
    });
    existingOrg = await prisma.organization.create({
      data: { name: 'CyberSploi Test Org', ownerId: user.id }
    });
  }
  let existingAsset = await prisma.asset.findFirst({ where: { organizationId: existingOrg.id } });
  if (!existingAsset) {
    existingAsset = await prisma.asset.create({
      data: { organizationId: existingOrg.id, type: 'ip', value: '127.0.0.1' }
    });
  }

  const dummyScan = await prisma.scan.create({
    data: {
      organizationId: existingOrg.id,
      assetId: existingAsset.id,
      type: 'aggressive',
      status: 'running',
      progress: 50
    }
  });

  const dummyAssessment = await prisma.redTeamAssessment.create({
    data: {
      scanId: dummyScan.id,
      phase: 'FINAL_VERIFICATION',
      progress: 95
    }
  });

  const session = await VerificationSessionService.createSession({
    assessmentId: dummyAssessment.id,
    target: '127.0.0.1',
    findingId: 'VULN-TEST-MGMT',
    objective: 'Bounded Port Verification Test',
    ttlMinutes: 15
  });

  record('Bounded verification session created with unique token', session.sessionToken.startsWith('RT-SESS-') && session.status === 'ACTIVE');

  // Terminate session with operator kill-switch
  const terminated = await VerificationSessionService.terminateSession(session.id, 'Integration test termination');
  record('Verification session immediately revoked via operator kill-switch', terminated.status === 'TERMINATED' && terminated.terminationReason.includes('Integration test'));

  // Clean up dummy test records
  await prisma.verificationSession.deleteMany({ where: { assessmentId: dummyAssessment.id } });
  await prisma.redTeamAssessment.delete({ where: { id: dummyAssessment.id } });
  await prisma.scan.delete({ where: { id: dummyScan.id } });

  // ------------------------------------------------------------
  // 6. FULL RED TEAM ASSESSMENT END-TO-END EXECUTION VIA API
  // ------------------------------------------------------------
  console.log('\n--- 6. Full Autonomous Red Team Assessment End-to-End ---');
  try {
    const launchRes = await axios.post(`${API_BASE}/api/v1/scans/initiate`, {
      target: '127.0.0.1',
      scanType: 'AGGRESSIVE',
      profile: 'ai_red_team_autonomous'
    });

    const initiatedScan = launchRes.data.data || launchRes.data;
    record('API accepted AGGRESSIVE scan and dispatched Red Team Orchestrator', !!initiatedScan.id, `Scan ID: ${initiatedScan.id}`);

    // Poll assessment status until COMPLETED or timeout
    console.log('       › Awaiting autonomous 14-phase state transitions in background...');
    let pollCount = 0;
    let completedAssessment = null;

    while (pollCount < 20) {
      await new Promise(r => setTimeout(r, 2000));
      pollCount++;

      const checkRes = await axios.get(`${API_BASE}/api/v1/scans/${initiatedScan.id}`);
      const currentScan = checkRes.data.data || checkRes.data;

      if (currentScan.status === 'completed' || currentScan.progress === 100) {
        completedAssessment = currentScan.redTeamAssessment;
        break;
      }
    }

    record('Autonomous assessment reached COMPLETED terminal state', !!completedAssessment && completedAssessment.status === 'COMPLETED', `Completed in ${pollCount * 2} seconds`);

    if (completedAssessment) {
      // Check Attack Graph endpoint
      const graphRes = await axios.get(`${API_BASE}/api/v1/red-team/assessments/${initiatedScan.id}/graph`);
      const graphData = graphRes.data.data;
      record('Attack graph API served verified graph data', graphData.nodes?.length > 0 && graphData.edges?.length > 0, `${graphData.nodes?.length} nodes, ${graphData.edges?.length} edges`);

      // Check Hypotheses endpoint
      const hypoRes = await axios.get(`${API_BASE}/api/v1/red-team/assessments/${initiatedScan.id}/hypotheses`);
      const hypoData = hypoRes.data.data;
      record('Hypotheses API returned verified and rejected hypotheses', Array.isArray(hypoData.verified) && Array.isArray(hypoData.rejected), `Verified: ${hypoData.verified?.length}, Rejected: ${hypoData.rejected?.length}`);

      // Check Report endpoint
      const reportRes = await axios.get(`${API_BASE}/api/v1/red-team/assessments/${initiatedScan.id}/report`);
      const reportData = reportRes.data.data;
      record('Executive audit report generated with all required sections', !!reportData.executiveSummary && !!reportData.blindSpots && !!reportData.timeline, `Methodology: ${reportData.methodology?.substring(0, 40)}...`);
    }
  } catch (err) {
    record('Full Red Team Assessment API execution', false, err.message);
  }

  // ------------------------------------------------------------
  // SUMMARY
  // ------------------------------------------------------------
  console.log('\n============================================================');
  console.log(`TEST RESULTS: ${passedTests} / ${totalTests} PASSED (${Math.round((passedTests / totalTests) * 100)}%)`);
  console.log('============================================================\n');

  if (passedTests === totalTests) {
    console.log('All Red Team Engine modules, policies, and API endpoints verified successfully with 0 errors.');
    process.exit(0);
  } else {
    console.error('Some tests failed.');
    process.exit(1);
  }
}

runTests().catch((e) => {
  console.error('Fatal test runner error:', e);
  process.exit(1);
});
