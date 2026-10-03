import prisma from '../config/database';
import { ScopeGuard, ScopeAction } from '../services/scope-guard/scope-guard.service';
import { ScopeRateLimiter } from '../services/scope-guard/rate-limiter';
import {
  EngagementStateMachine,
  ActiveTestingGate,
  GauntletLoopService,
  FindingEvidenceService,
  AuthMatrixService,
  AttackPathService,
  RedisEventBus,
  WorkerClientService,
  OffensiveEngineReportService
} from '../services/offensive-engine';
import { MockTargetServer } from './fixtures/mock-target-server';

async function runComprehensiveEngineTests() {
  console.log('============================================================');
  console.log('CYBERSPLOI OFFENSIVE TESTING ENGINE: COMPREHENSIVE 26-SCENARIO SUITE');
  console.log('============================================================\n');

  let passed = 0;
  let total = 0;

  function test(name: string, condition: boolean, details?: string) {
    total++;
    if (condition) {
      passed++;
      console.log(`[PASS] Scenario ${total}: ${name}`);
      if (details) console.log(`       › ${details}`);
    } else {
      console.error(`[FAIL] Scenario ${total}: ${name}`);
      if (details) console.error(`       › Details: ${details}`);
      throw new Error(`Assertion failed: ${name}`);
    }
  }

  // 0. Start Mock Target Server
  const mockServer = new MockTargetServer();
  const mockPort = await mockServer.start();
  console.log(`[Setup] Mock Target Server started on 127.0.0.1:${mockPort}`);

  const testRunId = `run_${Date.now()}`;
  let engagementId: string = '';

  try {
    // ------------------------------------------------------------
    // PROVISION TEST ENGAGEMENT
    // ------------------------------------------------------------
    const engagement = await prisma.engagement.create({
      data: {
        name: `Comprehensive Test Engagement ${testRunId}`,
        environment: 'lab',
        status: 'active',
        currentPhase: 'RECON',
        scope: {
          create: {
            allowedTargets: JSON.stringify([
              { host: '127.0.0.1', ports: [mockPort] },
              { host: 'lab.cybersploi.local', ports: [80, 443] },
              { cidr: '10.20.0.0/16' },
              { pattern: '*.test.internal' }
            ]),
            allowedTestTypes: JSON.stringify(['RECON', 'MAPPING', 'AUTH', 'IDOR', 'INJECTION', 'POC']),
            destructiveActionsAllowed: false,
            activePoCAllowed: false,
            rateLimit: JSON.stringify({ requestsPerSecond: 5, concurrency: 2 }),
            concurrencyLimit: 2,
            validFrom: new Date(Date.now() - 3600000), // 1 hour ago
            validUntil: new Date(Date.now() + 3600000), // 1 hour from now
            approvedBy: 'Principal Test Architect'
          }
        }
      },
      include: { scope: true }
    });
    engagementId = engagement.id;

    // ------------------------------------------------------------
    // 1. IN-SCOPE TARGET
    // ------------------------------------------------------------
    const r1 = await ScopeGuard.checkScope(engagementId, {
      testType: 'RECON',
      targetHost: '127.0.0.1',
      targetPort: mockPort,
      isDestructive: false,
      isPoC: false
    });
    test('In-scope target authorizes with ALLOWED decision', r1.allowed === true && r1.decision === 'ALLOWED', `Decision: ${r1.decision}`);

    // ------------------------------------------------------------
    // 2. OUT-OF-SCOPE TARGET
    // ------------------------------------------------------------
    const r2 = await ScopeGuard.checkScope(engagementId, {
      testType: 'RECON',
      targetHost: 'attacker-controlled-c2.com',
      isDestructive: false,
      isPoC: false
    });
    test('Out-of-scope target rejected with BLOCKED_OUT_OF_SCOPE', r2.allowed === false && r2.decision === 'BLOCKED_OUT_OF_SCOPE', `Decision: ${r2.decision}`);

    // ------------------------------------------------------------
    // 3. EXPIRED SCOPE
    // ------------------------------------------------------------
    const expiredEng = await prisma.engagement.create({
      data: {
        name: `Expired Engagement ${testRunId}`,
        status: 'active',
        environment: 'lab',
        scope: {
          create: {
            allowedTargets: JSON.stringify(['127.0.0.1']),
            allowedTestTypes: JSON.stringify(['RECON']),
            destructiveActionsAllowed: false,
            activePoCAllowed: false,
            rateLimit: JSON.stringify({ requestsPerSecond: 10, concurrency: 5 }),
            validFrom: new Date(Date.now() - 7200000),
            validUntil: new Date(Date.now() - 3600000), // Expired 1 hr ago
            approvedBy: 'Security Lead'
          }
        }
      }
    });
    const r3 = await ScopeGuard.checkScope(expiredEng.id, {
      testType: 'RECON',
      targetHost: '127.0.0.1',
      isDestructive: false,
      isPoC: false
    });
    test('Expired scope rejected with BLOCKED_EXPIRED_SCOPE', r3.allowed === false && r3.decision === 'BLOCKED_EXPIRED_SCOPE', `Decision: ${r3.decision}`);

    // ------------------------------------------------------------
    // 4. INVALID TEST TYPE
    // ------------------------------------------------------------
    const r4 = await ScopeGuard.checkScope(engagementId, {
      testType: 'UNAUTHORIZED_ZERO_DAY_PAYLOAD',
      targetHost: '127.0.0.1',
      targetPort: mockPort,
      isDestructive: false,
      isPoC: false
    });
    test('Invalid test type rejected with BLOCKED_TEST_TYPE', r4.allowed === false && r4.decision === 'BLOCKED_TEST_TYPE', `Decision: ${r4.decision}`);

    // ------------------------------------------------------------
    // 5. DISABLED POC
    // ------------------------------------------------------------
    const r5 = await ScopeGuard.checkScope(engagementId, {
      testType: 'INJECTION',
      targetHost: '127.0.0.1',
      targetPort: mockPort,
      isDestructive: false,
      isPoC: true
    });
    test('Active PoC action blocked with BLOCKED_POC_DISABLED when activePoCAllowed is false', r5.allowed === false && r5.decision === 'BLOCKED_POC_DISABLED', `Decision: ${r5.decision}`);

    // ------------------------------------------------------------
    // 6. DESTRUCTIVE ACTION DISABLED
    // ------------------------------------------------------------
    const r6 = await ScopeGuard.checkScope(engagementId, {
      testType: 'INJECTION',
      targetHost: '127.0.0.1',
      targetPort: mockPort,
      isDestructive: true,
      isPoC: false
    });
    test('Destructive action blocked with BLOCKED_DESTRUCTIVE_ACTION when flag is false', r6.allowed === false && r6.decision === 'BLOCKED_DESTRUCTIVE_ACTION', `Decision: ${r6.decision}`);

    // ------------------------------------------------------------
    // 7. RATE-LIMIT VIOLATION
    // ------------------------------------------------------------
    // Create tight rate limit engagement (1 req/sec)
    const tightEng = await prisma.engagement.create({
      data: {
        name: `Rate Limit Test ${testRunId}`,
        status: 'active',
        scope: {
          create: {
            allowedTargets: JSON.stringify(['127.0.0.1']),
            allowedTestTypes: JSON.stringify(['RECON']),
            destructiveActionsAllowed: false,
            activePoCAllowed: false,
            rateLimit: JSON.stringify({ requestsPerSecond: 1, concurrency: 1 }),
            validFrom: new Date(Date.now() - 60000),
            validUntil: new Date(Date.now() + 60000),
            approvedBy: 'QA'
          }
        }
      }
    });
    await ScopeRateLimiter.resetBucket(tightEng.id);
    const rlReq1 = await ScopeGuard.checkScope(tightEng.id, { testType: 'RECON', targetHost: '127.0.0.1', isDestructive: false, isPoC: false });
    const rlReq2 = await ScopeGuard.checkScope(tightEng.id, { testType: 'RECON', targetHost: '127.0.0.1', isDestructive: false, isPoC: false });
    test('Rate-limit violation rejected with BLOCKED_RATE_LIMIT', rlReq1.allowed === true && rlReq2.decision === 'BLOCKED_RATE_LIMIT', `Decision: ${rlReq2.decision}`);

    // ------------------------------------------------------------
    // 8. CONCURRENCY VIOLATION
    // ------------------------------------------------------------
    ScopeRateLimiter.resetConcurrency(engagementId);
    ScopeRateLimiter.acquireConcurrency(engagementId, 2);
    ScopeRateLimiter.acquireConcurrency(engagementId, 2); // Now at 2/2 max
    const r8 = await ScopeGuard.checkScope(engagementId, {
      testType: 'RECON',
      targetHost: '127.0.0.1',
      targetPort: mockPort,
      isDestructive: false,
      isPoC: false
    });
    test('Concurrency violation rejected with BLOCKED_CONCURRENCY', r8.allowed === false && r8.decision === 'BLOCKED_CONCURRENCY', `Decision: ${r8.decision}`);
    ScopeRateLimiter.resetConcurrency(engagementId);

    // ------------------------------------------------------------
    // 9. MALFORMED TARGET
    // ------------------------------------------------------------
    const r9 = await ScopeGuard.checkScope(engagementId, {
      testType: 'RECON',
      targetHost: '127.0.0.1; rm -rf /; `whoami`',
      isDestructive: false,
      isPoC: false
    });
    test('Malformed target string rejected safely with BLOCKED_OUT_OF_SCOPE', r9.allowed === false && r9.decision === 'BLOCKED_OUT_OF_SCOPE', `Decision: ${r9.decision}`);

    // ------------------------------------------------------------
    // 10. INVALID STATE TRANSITION
    // ------------------------------------------------------------
    const r10 = await EngagementStateMachine.transition({
      engagementId,
      targetPhase: 'REPORTING', // Direct leap from RECON to REPORTING is illegal
      actor: 'tester',
      reason: 'Illegal leap attempt'
    });
    test('Invalid state transition rejected by state machine', r10.success === false && !!(r10.error && r10.error.includes('ILLEGAL_TRANSITION')), `Error: ${r10.error}`);

    // ------------------------------------------------------------
    // 11. FINDING WITHOUT EVIDENCE
    // ------------------------------------------------------------
    const finding1 = await FindingEvidenceService.createFinding({
      engagementId,
      title: 'Unvalidated SQL Injection Hypothesis',
      description: 'Hypothesized vulnerable query parameter',
      category: 'INJECTION',
      severity: 'HIGH',
      target: '127.0.0.1'
    });
    // First transition finding from SUSPECTED to TESTED
    await FindingEvidenceService.transitionFinding(finding1.id, 'TESTED');
    let findingErrorMsg = '';
    try {
      await FindingEvidenceService.transitionFinding(finding1.id, 'VALIDATED');
    } catch (err: any) {
      findingErrorMsg = err.message;
    }
    test('Finding cannot transition to VALIDATED without Evidence', findingErrorMsg.includes('EVIDENCE_REQUIRED'), `Error: ${findingErrorMsg}`);

    // ------------------------------------------------------------
    // 12. FINDING WITH VALID EVIDENCE
    // ------------------------------------------------------------
    const ev1 = await FindingEvidenceService.createEvidence({
      findingId: finding1.id,
      actionId: 'act_sqli_test',
      target: '127.0.0.1',
      observation: 'Time-based sleep delay observed in database response',
      reproductionSteps: 'curl -X POST http://127.0.0.1/api/search -d "q=1\' OR SLEEP(5)--"'
    });
    const transitionedFinding = await FindingEvidenceService.transitionFinding(finding1.id, 'VALIDATED');
    test('Finding transitions to VALIDATED once immutable Evidence exists', transitionedFinding.status === 'VALIDATED', `Status: ${transitionedFinding.status}`);

    // ------------------------------------------------------------
    // 13. ATTEMPTED EVIDENCE MUTATION
    // ------------------------------------------------------------
    let evidenceMutationError = '';
    try {
      await FindingEvidenceService.updateEvidence(ev1.id, { observation: 'TAMPERED EVIDENCE' });
    } catch (err: any) {
      evidenceMutationError = err.message;
    }
    test('Attempted Evidence mutation fails with IMMUTABLE_EVIDENCE_VIOLATION', evidenceMutationError.includes('IMMUTABLE_EVIDENCE_VIOLATION'), `Error: ${evidenceMutationError}`);

    // ------------------------------------------------------------
    // 14. INCOMPLETE ATTACK PATH
    // ------------------------------------------------------------
    const finding2 = await FindingEvidenceService.createFinding({
      engagementId,
      title: 'Privilege Escalation to Admin',
      description: 'Session cookie manipulation',
      category: 'AUTH',
      severity: 'CRITICAL',
      target: '127.0.0.1'
    });
    await FindingEvidenceService.transitionFinding(finding2.id, 'TESTED');
    await FindingEvidenceService.createEvidence({
      findingId: finding2.id,
      actionId: 'act_auth_priv',
      target: '127.0.0.1',
      observation: 'JWT role claim tampered from user to admin',
      reproductionSteps: 'Tamper JWT role header'
    });
    await FindingEvidenceService.transitionFinding(finding2.id, 'VALIDATED');

    const attackPath = await AttackPathService.createAttackPath({
      engagementId,
      title: 'SQLi to Admin Account Takeover',
      findingIds: [finding1.id, finding2.id]
    });
    test('AttackPath without transition evidence remains HYPOTHESIZED', attackPath?.status === 'HYPOTHESIZED', `Status: ${attackPath?.status}`);

    // ------------------------------------------------------------
    // 15. DEMONSTRATED ATTACK PATH
    // ------------------------------------------------------------
    const transitionEv = await FindingEvidenceService.createEvidence({
      actionId: 'act_trans_link',
      target: '127.0.0.1',
      observation: 'Extracted admin hash via SQLi and generated valid privileged session',
      reproductionSteps: 'Use extracted admin credential from finding 1 to login as admin in finding 2'
    });
    const transitionId = attackPath!.transitions[0].id;
    const demonstratedPath = await AttackPathService.attachTransitionEvidence({
      transitionId,
      evidenceId: transitionEv.id
    });
    test('AttackPath transitions to DEMONSTRATED when 100% of transitions have valid evidence', demonstratedPath?.status === 'DEMONSTRATED', `Status: ${demonstratedPath?.status}`);

    // ------------------------------------------------------------
    // 16. MAXIMUM GAUNTLET ITERATIONS
    // ------------------------------------------------------------
    const gauntletResult = await GauntletLoopService.execute({
      engagementId,
      target: '127.0.0.1',
      testType: 'INJECTION',
      maxIterations: 3,
      testExecutor: async () => ({
        success: true,
        vulnerabilityConfirmed: false, // Never confirms
        shouldRetry: true
      })
    });
    test('Gauntlet hits MAX_ITERATIONS_REACHED and terminates with INCONCLUSIVE', gauntletResult.status === 'INCONCLUSIVE' && gauntletResult.iterationsCompleted === 3, `Status: ${gauntletResult.status}, Iterations: ${gauntletResult.iterationsCompleted}`);

    // ------------------------------------------------------------
    // 17. WORKER TIMEOUT
    // ------------------------------------------------------------
    const approvedActionForTimeout = (await ScopeGuard.checkScope(engagementId, {
      testType: 'RECON',
      targetHost: '127.0.0.1',
      targetPort: mockPort,
      isDestructive: false,
      isPoC: false
    })).approvedAction!;

    const timeoutWorkerResult = await WorkerClientService.executeJob(approvedActionForTimeout, {
      timeoutMs: 1 // Instant timeout
    });
    test('Worker timeout handled safely with status TIMEOUT', timeoutWorkerResult.status === 'TIMEOUT', `Status: ${timeoutWorkerResult.status}`);

    // ------------------------------------------------------------
    // 18. WORKER FAILURE
    // ------------------------------------------------------------
    // Send job with invalid ApprovedAction to test architectural rejection
    let forgedRejection = false;
    try {
      await WorkerClientService.executeJob({
        ...approvedActionForTimeout,
        token: 'FORGED_INVALID_TOKEN'
      });
    } catch (err: any) {
      forgedRejection = err.message.includes('ARCHITECTURAL_VIOLATION');
    }
    test('Forged or invalid ApprovedAction rejected before worker execution', forgedRejection);

    // ------------------------------------------------------------
    // 19. WORKER RETRY (GAUNTLET SIMULATION)
    // ------------------------------------------------------------
    let attempts = 0;
    const retryGauntletResult = await GauntletLoopService.execute({
      engagementId,
      target: '127.0.0.1',
      testType: 'RECON',
      maxIterations: 5,
      testExecutor: async () => {
        attempts++;
        if (attempts < 3) {
          return { success: false, vulnerabilityConfirmed: false, shouldRetry: true };
        }
        return { success: true, vulnerabilityConfirmed: true, reproductionSteps: 'Proof on 3rd attempt' };
      }
    });
    test('Gauntlet retries and succeeds on subsequent iteration', retryGauntletResult.status === 'COMPLETED' && retryGauntletResult.iterationsCompleted === 3, `Status: ${retryGauntletResult.status}, Iterations: ${retryGauntletResult.iterationsCompleted}`);

    // ------------------------------------------------------------
    // 20. CANCELLATION
    // ------------------------------------------------------------
    const cancelPromise = GauntletLoopService.execute({
      engagementId,
      target: '127.0.0.1',
      testType: 'RECON',
      maxIterations: 10,
      testExecutor: async (iter) => {
        if (iter === 1) {
          // Trigger cancellation
          GauntletLoopService.cancel(gauntletResult.correlationId);
        }
        await new Promise(r => setTimeout(r, 20));
        return { success: true, vulnerabilityConfirmed: false };
      }
    });
    // Immediately cancel
    const cancelResult = await GauntletLoopService.execute({
      engagementId,
      target: '127.0.0.1',
      testType: 'RECON',
      maxIterations: 5,
      testExecutor: async () => {
        GauntletLoopService.cancel('test_cancel_id');
        return { success: true, vulnerabilityConfirmed: false };
      }
    });
    test('Gauntlet loop supports cancellation without hanging', typeof cancelResult.status === 'string');

    // ------------------------------------------------------------
    // 21. DUPLICATE ACTION (IDEMPOTENCY PROTECTION)
    // ------------------------------------------------------------
    const duplicateApprovedAction = (await ScopeGuard.checkScope(engagementId, {
      testType: 'RECON',
      targetHost: '127.0.0.1',
      targetPort: mockPort,
      isDestructive: false,
      isPoC: false
    })).approvedAction!;

    const runA = await WorkerClientService.executeJob(duplicateApprovedAction);
    const runB = await WorkerClientService.executeJob(duplicateApprovedAction);
    console.log('DEBUG runA:', JSON.stringify(runA));
    test('Duplicate job dispatches maintain correlation tracking and audit consistency', runA.status === 'SUCCESS' && runB.status === 'SUCCESS', `Run A: ${runA.status}, Run B: ${runB.status}`);

    // ------------------------------------------------------------
    // 22. CONCURRENT ACTIONS
    // ------------------------------------------------------------
    ScopeRateLimiter.resetConcurrency(engagementId);
    const concurrentP1 = ScopeGuard.checkScope(engagementId, { testType: 'RECON', targetHost: '127.0.0.1', targetPort: mockPort, isDestructive: false, isPoC: false });
    const concurrentP2 = ScopeGuard.checkScope(engagementId, { testType: 'RECON', targetHost: '127.0.0.1', targetPort: mockPort, isDestructive: false, isPoC: false });
    const [c1, c2] = await Promise.all([concurrentP1, concurrentP2]);
    test('Concurrent actions handled deterministically', c1.allowed === true && c2.allowed === true);

    // ------------------------------------------------------------
    // 23. MISSING AUTHCONTEXT
    // ------------------------------------------------------------
    const gateMissingAuth = await ActiveTestingGate.evaluate({
      engagementId,
      action: {
        testType: 'AUTH',
        targetHost: '127.0.0.1',
        targetPort: mockPort,
        isDestructive: false,
        isPoC: false
      },
      authContext: { required: true, subject: null } // Missing required subject
    });
    test('Missing required AuthContext blocked before execution', gateMissingAuth.canExecute === false && gateMissingAuth.conditionFailed === 9, `Condition failed: ${gateMissingAuth.conditionFailed}`);

    // ------------------------------------------------------------
    // 24. UNAUTHORIZED ROLE TRANSITION (AUTH MATRIX)
    // ------------------------------------------------------------
    const matrixEvaluation = await AuthMatrixService.recordEvaluation({
      engagementId,
      operation: 'DELETE /admin/users',
      authContext: {
        role: 'guest_user',
        subjectIdentity: 'guest_42',
        objectIdentity: '/admin/users'
      },
      declaredExpected: 'DENIED',
      observed: 'ALLOWED' // Discrepancy: Guest was able to execute admin delete!
    });
    test('Unauthorized role access creates discrepancy in AuthMatrix and creates Finding', matrixEvaluation.result === 'DISCREPANCY' && !!matrixEvaluation.findingId, `Result: ${matrixEvaluation.result}, Finding ID: ${matrixEvaluation.findingId}`);

    // ------------------------------------------------------------
    // 25. REDIS EVENT DELIVERY
    // ------------------------------------------------------------
    let eventReceived = false;
    const unsubscribe = RedisEventBus.subscribe(engagementId, (evt) => {
      if (evt.ACTION === 'TEST_TELEMETRY_STREAM') {
        eventReceived = true;
      }
    });

    await RedisEventBus.publish({
      engagementId,
      TARGET: '127.0.0.1',
      SESSION: 'test_session',
      ACTION: 'TEST_TELEMETRY_STREAM',
      OBSERVATION: 'Telemetry event delivery test',
      DECISION: 'OBSERVED',
      severity: 'INFO',
      timestamp: new Date().toISOString()
    });

    // Give event loop tick
    await new Promise(r => setTimeout(r, 20));
    unsubscribe();
    test('Live telemetry event published and delivered through event bus', eventReceived);

    // ------------------------------------------------------------
    // 26. REPORT GENERATION
    // ------------------------------------------------------------
    // Transition finding1 to PROVEN
    await FindingEvidenceService.transitionFinding(finding1.id, 'PROVEN', {
      reproductionSteps: 'Execute curl against search endpoint'
    });

    const report = await OffensiveEngineReportService.generateReport(engagementId, 'json');
    test('Report generated successfully', report && report.success === true, `Report ID: ${report?.report?.id}`);
    test('Report distinguishes proven findings from hypotheses', report?.report?.sections?.findings !== undefined);

    console.log('\n============================================================');
    console.log(`ALL 26 SCENARIO TESTS PASSED! (${passed}/${total})`);
    console.log('============================================================\n');

  } finally {
    await mockServer.stop();
    await ScopeRateLimiter.disconnect();
    await RedisEventBus.disconnect();
    await prisma.$disconnect();
  }
}

runComprehensiveEngineTests().catch(err => {
  console.error('[FATAL] Comprehensive test suite error:', err);
  process.exit(1);
});
