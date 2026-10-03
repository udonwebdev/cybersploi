import http from 'http';
import express from 'express';
import axios from 'axios';
import prisma from '../config/database';
import engagementsRouter from '../routes/engagements.routes';
import {
  OmegaOrchestratorService,
  DebateEngineService,
  InfoGainPlannerService,
  RedBlueArenaService,
  ChaosEngineService,
  BoundaryInvariantsService,
  AdversarialHarnessService,
  TelemetryPipelineService
} from '../services/offensive-engine';
import { ScopeGuardService } from '../services/scope-guard/scope-guard.service';

async function runOmegaTestSuite() {
  console.log('================================================================================');
  console.log('CYBERSPLOI AIM OMEGA-X: AUTONOMOUS COGNITIVE ARCHITECTURE TEST SUITE');
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
      console.log(`[PASS] Omega Test ${total}: ${name}`);
      if (details) console.log(`       › ${details}`);
    } else {
      console.error(`[FAIL] Omega Test ${total}: ${name}`);
      if (details) console.error(`       › Details: ${details}`);
      throw new Error(`Omega test failed: ${name}`);
    }
  }

  try {
    // ------------------------------------------------------------
    // 0. Setup Engagement for Cognitive Testing
    // ------------------------------------------------------------
    console.log('--- 0. Setup Test Engagement ---');
    const postRes = await axios.post(`${baseUrl}/engagements`, {
      name: 'AIM OMEGA-X Cognitive Test Engagement',
      environment: 'lab',
      status: 'active',
      scope: {
        allowedTargets: [{ host: '127.0.0.1', ports: [80, 443] }, { host: '169.254.169.254', ports: [80] }],
        allowedTestTypes: ['RECON', 'WEB_ENUM', 'PORT_SCAN', 'AUTH_TEST', 'INJECTION_TEST'],
        approvedBy: 'Principal Cognitive Architect',
        approvalRecordUrl: 'https://jira.internal/OMEGA-AIM-001'
      }
    });
    const engagement = postRes.data.data;

    test(
      'Test Engagement & Scope Provisioning',
      !!engagement.id && !!engagement.scope,
      `Engagement ID: ${engagement.id}`
    );


    // ------------------------------------------------------------
    // 1. Omega Cognitive Agent Schemas & Registration
    // ------------------------------------------------------------
    console.log('\n--- 1. Cognitive Agent Registry & Schemas ---');
    const schemas = OmegaOrchestratorService.listAgentSchemas();
    test(
      'Registered 11 Specialized Cognitive Agents',
      schemas.length === 11,
      `Registered count: ${schemas.length} (Expected: 11)`
    );

    const strategicPlanner = OmegaOrchestratorService.getAgentSchema('STRATEGIC_PLANNER');
    test(
      'Strategic Planner Schema Validated',
      strategicPlanner !== undefined && strategicPlanner.maxBudgetMs > 0,
      `Role: ${strategicPlanner?.role}, Budget: ${strategicPlanner?.maxBudgetMs}ms`
    );

    const vulnResearch = OmegaOrchestratorService.getAgentSchema('VULN_RESEARCH');
    test(
      'Vuln Research Agent Schema Validated',
      vulnResearch !== undefined && vulnResearch.allowedScopeActions.includes('INJECTION_TEST'),
      `Role: ${vulnResearch?.role}`
    );

    // ------------------------------------------------------------
    // 2. Information-Gain Action Planner (Shannon Entropy & Utility)
    // ------------------------------------------------------------
    console.log('\n--- 2. Information-Gain Planner (Entropy Optimization) ---');
    const surfaceState = {
      totalNodes: 10,
      unmappedNodes: 4,
      untestedEndpoints: 3,
      unresolvedIdentities: 2,
      currentEntropyBits: 0
    };
    const initialEntropy = InfoGainPlannerService.computeShannonEntropy(surfaceState);
    test(
      'Shannon Entropy Computation H(S)',
      initialEntropy > 1.0,
      `Initial surface entropy: ${initialEntropy} bits`
    );

    const candidates = [
      {
        actionId: 'act-1',
        name: 'Discover API Endpoints',
        category: 'WEB_MAPPING' as const,
        target: 'http://127.0.0.1:8080/api',
        targetNodeType: 'ENDPOINT',
        estimatedCost: 1.0,
        riskScore: 0.05,
        severityWeight: 6.0,
        expectedConfidenceDelta: 0.85
      },
      {
        actionId: 'act-2',
        name: 'Transitive IAM Role Reachability',
        category: 'AUTH_MATRIX' as const,
        target: 'arn:aws:iam::role/Admin',
        targetNodeType: 'IAM_ROLE',
        estimatedCost: 0.5,
        riskScore: 0.02,
        severityWeight: 9.5,
        expectedConfidenceDelta: 0.95
      },
      {
        actionId: 'act-3',
        name: 'Duplicate Action on 127.0.0.1',
        category: 'WEB_MAPPING' as const,
        target: 'http://127.0.0.1:8080/api',
        targetNodeType: 'ENDPOINT',
        estimatedCost: 1.0,
        riskScore: 0.05,
        severityWeight: 6.0,
        expectedConfidenceDelta: 0.10
      }
    ];

    const plan = InfoGainPlannerService.planOptimalActions(engagement.id, candidates, surfaceState, 2);
    test(
      'Information-Gain Plan Synthesized with Utility Ranking',
      plan.selectedActions.length === 2 && plan.selectedActions[0].selectionRank === 1,
      `Top action: ${plan.selectedActions[0].name} (Utility: ${plan.selectedActions[0].utilityScore})`
    );

    test(
      'Pruning Redundant Low-Gain Actions',
      plan.prunedRedundantCount === 1,
      `Pruned redundant count: ${plan.prunedRedundantCount}`
    );

    test(
      'Projected Entropy Reduction',
      plan.entropyReductionPercentage > 0 && plan.projectedEntropyBitsAfterPlan < plan.initialEntropyBits,
      `Entropy reduced by: ${plan.entropyReductionPercentage}% (${plan.initialEntropyBits} -> ${plan.projectedEntropyBitsAfterPlan} bits)`
    );

    // ------------------------------------------------------------
    // 3. Multi-Agent Dialectical Debate Engine
    // ------------------------------------------------------------
    console.log('\n--- 3. Multi-Agent Dialectical Debate Engine ---');
    // Test 3A: Legitimate Finding Resisting Falsification
    const confirmedDebate = await DebateEngineService.evaluateFindingDebate({
      engagementId: engagement.id,
      findingTitle: 'Verified IMDSv1 Unauthenticated Token Exposure',
      category: 'CLOUD_METADATA_EXPOSURE',
      target: 'http://169.254.169.254/latest/meta-data/',
      observedData: {
        requestPath: '/latest/meta-data/iam/security-credentials/LabRole',
        statusCode: 200,
        responseBody: '{"Role":"LabRole","AccessKeyId":"ASIA-MOCK-VALID"}',
        reproductionSteps: 'curl -s -f http://169.254.169.254/latest/meta-data/iam/security-credentials/LabRole',
        latencyMs: 120,
        evidenceHash: 'sha256-verified-evidence-hash-mock'
      }
    });

    test(
      'Debate Consensus: Legitimate Finding Confirmed',
      confirmedDebate.finalVerdict === 'CONFIRMED' && confirmedDebate.consensusConfidence >= 0.70,
      `Verdict: ${confirmedDebate.finalVerdict}, Confidence: ${(confirmedDebate.consensusConfidence * 100).toFixed(1)}%`
    );

    test(
      'Debate: 5 Agent Contributions Captured',
      confirmedDebate.contributions.length === 5,
      `Contributions: ${confirmedDebate.contributions.map(c => c.agentRole).join(' -> ')}`
    );

    test(
      'Debate: Challenger Passed All Falsification Checks',
      confirmedDebate.contributions.find(c => c.agentRole === 'ADVERSARIAL_CHALLENGER')?.falsificationChecks?.every(c => c.passed) === true,
      'WAF, Cache, Honeypot, Network falsification checks passed'
    );

    // Test 3B: Falsification - WAF Interception Triggering Refutation & Dissent
    const refutedDebate = await DebateEngineService.evaluateFindingDebate({
      engagementId: engagement.id,
      findingTitle: 'WAF Intercepted False Positive Finding',
      category: 'SQL_INJECTION',
      target: 'https://example.internal/login',
      observedData: {
        requestPath: '/login?id=1',
        statusCode: 403,
        responseBody: '<html><head><title>Cloudflare Block Page</title></head></html>',
        responseHeaders: { server: 'cloudflare' },
        reproductionSteps: 'curl https://example.internal/login?id=1'
      },
      simulatedAnomalies: {
        isWafBlock: true
      }
    });

    test(
      'Debate Consensus: WAF False Positive Refuted',
      refutedDebate.finalVerdict === 'REFUTED',
      `Verdict: ${refutedDebate.finalVerdict}`
    );

    test(
      'Debate Minority Dissent Captured on Refutation',
      !!refutedDebate.minorityDissent,
      `Dissent by: ${refutedDebate.minorityDissent?.agent}`
    );

    // ------------------------------------------------------------
    // 4. Adversarial Evolution Arena ("Attack Itself")
    // ------------------------------------------------------------
    console.log('\n--- 4. Adversarial Evolution Arena (Attack Itself) ---');
    const arenaReport = await RedBlueArenaService.runEvolutionaryArena(2, 6);
    test(
      'Adversarial Evolution Arena Executed Multi-Generation Rounds',
      arenaReport.totalGenerations === 2 && arenaReport.totalCandidatesEvaluated === 12,
      `Evaluated ${arenaReport.totalCandidatesEvaluated} mutations across ${arenaReport.totalGenerations} generations`
    );

    test(
      'Blue Agent 100% Invariant Defense Rate Maintained',
      arenaReport.defenseRatePercent === 100,
      `Defense Rate: ${arenaReport.defenseRatePercent}% (Compromised: ${arenaReport.compromisedCount})`
    );

    test(
      'Mutation Strategies Spanned All Attack Vectors',
      arenaReport.rounds.some(r => r.candidate.strategy === 'INSTRUCTION_INVERSION') &&
      arenaReport.rounds.some(r => r.candidate.strategy === 'PERSONA_ESCALATION') &&
      arenaReport.rounds.some(r => r.candidate.strategy === 'ENCODED_EVASION') &&
      arenaReport.rounds.some(r => r.candidate.strategy === 'CONTEXT_POISONING'),
      'Verified strategies: INSTRUCTION_INVERSION, PERSONA_ESCALATION, ENCODED_EVASION, CONTEXT_POISONING'
    );

    // ------------------------------------------------------------
    // 5. Chaos & Resilience Engine (Fault Injection)
    // ------------------------------------------------------------
    console.log('\n--- 5. Chaos & Resilience Engine ---');
    const chaosReport = await ChaosEngineService.runResilienceSuite();
    test(
      'Chaos Resilience Suite Executed 5 Fault Scenarios',
      chaosReport.totalFaultsInjected === 5,
      `Faults injected: ${chaosReport.totalFaultsInjected}`
    );

    test(
      'Zero Unauthorized Actions Permitted Under Chaos',
      chaosReport.zeroUnauthorizedActions === true,
      'Strict zero-trust scope maintained across all fault injections'
    );

    test(
      'High Resilience Index Achieved',
      chaosReport.resilienceIndex >= 0.80,
      `Resilience Index: ${(chaosReport.resilienceIndex * 100).toFixed(1)}% (${chaosReport.passedFaultCount}/${chaosReport.totalFaultsInjected} survived)`
    );

    // ------------------------------------------------------------
    // 6. Omega Hierarchical Orchestrator (16-Step Loop)
    // ------------------------------------------------------------
    console.log('\n--- 6. Omega Hierarchical 16-Step Autonomous Cycle ---');
    const cycleReport = await OmegaOrchestratorService.executeAutonomousCycle(engagement.id, {
      maxDurationMs: 60000,
      enableAttackItself: true
    });

    test(
      'Autonomous Cycle Status COMPLETED',
      cycleReport.status === 'COMPLETED',
      `Cycle ID: ${cycleReport.cycleId}, Duration: ${cycleReport.durationMs}ms`
    );

    test(
      'All 16 Prime Directive Steps Executed',
      cycleReport.stepsExecuted.length >= 15 &&
      cycleReport.stepsExecuted.includes('PERCEIVE') &&
      cycleReport.stepsExecuted.includes('MODEL') &&
      cycleReport.stepsExecuted.includes('PLAN') &&
      cycleReport.stepsExecuted.includes('SELECT') &&
      cycleReport.stepsExecuted.includes('EXECUTE') &&
      cycleReport.stepsExecuted.includes('OBSERVE') &&
      cycleReport.stepsExecuted.includes('CORRELATE') &&
      cycleReport.stepsExecuted.includes('HYPOTHESIZE') &&
      cycleReport.stepsExecuted.includes('VALIDATE') &&
      cycleReport.stepsExecuted.includes('PROVE') &&
      cycleReport.stepsExecuted.includes('REMEDIATE') &&
      cycleReport.stepsExecuted.includes('RETEST') &&
      cycleReport.stepsExecuted.includes('LEARN') &&
      cycleReport.stepsExecuted.includes('OPTIMIZE') &&
      cycleReport.stepsExecuted.includes('ATTACK_ITSELF') &&
      cycleReport.stepsExecuted.includes('REPEAT'),
      `Steps executed: ${cycleReport.stepsExecuted.length}`
    );

    test(
      'Verified and Proven Findings Generated with SHA-256 Evidence',
      cycleReport.verifiedFindingsCount > 0 && cycleReport.provenFindingsCount > 0,
      `Verified: ${cycleReport.verifiedFindingsCount}, Proven: ${cycleReport.provenFindingsCount}`
    );

    // ------------------------------------------------------------
    // 7. REST API Endpoints Verification
    // ------------------------------------------------------------
    console.log('\n--- 7. REST API Integration Endpoints ---');

    // 7A: POST /engagements/:id/omega/plan
    const planRes = await axios.post(`${baseUrl}/engagements/${engagement.id}/omega/plan`);
    test(
      'REST: POST /engagements/:id/omega/plan',
      planRes.status === 200 && planRes.data.success && planRes.data.data.selectedActions.length > 0,
      `Selected actions: ${planRes.data.data.selectedActions.length}`
    );

    // 7B: POST /engagements/:id/omega/debate
    const debateRes = await axios.post(`${baseUrl}/engagements/${engagement.id}/omega/debate`, {
      findingTitle: 'API Route Logic Bypass Test',
      category: 'AUTH_BYPASS',
      target: 'http://127.0.0.1/api/admin',
      observedData: {
        requestPath: '/api/admin',
        statusCode: 200,
        responseBody: '{"admin": true}',
        reproductionSteps: 'curl http://127.0.0.1/api/admin'
      }
    });
    test(
      'REST: POST /engagements/:id/omega/debate',
      debateRes.status === 200 && debateRes.data.success && !!debateRes.data.data.finalVerdict,
      `Debate verdict: ${debateRes.data.data.finalVerdict}`
    );

    // 7C: POST /engagements/:id/omega/arena/evolve
    const arenaRes = await axios.post(`${baseUrl}/engagements/${engagement.id}/omega/arena/evolve`, {
      generations: 1,
      seeds: 3
    });
    test(
      'REST: POST /engagements/:id/omega/arena/evolve',
      arenaRes.status === 200 && arenaRes.data.success && arenaRes.data.data.defenseRatePercent === 100,
      `Arena defense rate: ${arenaRes.data.data.defenseRatePercent}%`
    );

    // 7D: POST /engagements/:id/omega/chaos/test
    const chaosRes = await axios.post(`${baseUrl}/engagements/${engagement.id}/omega/chaos/test`);
    test(
      'REST: POST /engagements/:id/omega/chaos/test',
      chaosRes.status === 200 && chaosRes.data.success && chaosRes.data.data.resilienceIndex >= 0.8,
      `Resilience index: ${chaosRes.data.data.resilienceIndex}`
    );


    // 7E: POST /engagements/:id/omega/run
    const cycleRes = await axios.post(`${baseUrl}/engagements/${engagement.id}/omega/run`, {
      maxDurationMs: 30000,
      enableAttackItself: true
    });
    test(
      'REST: POST /engagements/:id/omega/run',
      cycleRes.status === 200 && cycleRes.data.success && cycleRes.data.data.status === 'COMPLETED',
      `Cycle status: ${cycleRes.data.data.status}, Steps: ${cycleRes.data.data.stepsExecuted.length}`
    );

    console.log('\n================================================================================');
    console.log(`AIM OMEGA-X VERIFICATION COMPLETE: ${passed} / ${total} TESTS PASSED [100%]`);
    console.log('================================================================================\n');

  } finally {
    server.close();
  }
}

runOmegaTestSuite().catch((err) => {
  console.error('\n[FATAL] Omega test suite failed:', err);
  process.exit(1);
});
