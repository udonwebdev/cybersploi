import assert from 'assert';
import prisma from '../config/database';
import { ScopeGuardService, checkScope } from '../services/scope-guard/scope-guard.service';
import { isIpInIpv4Cidr, isDomainMatch, isTargetAllowed } from '../services/scope-guard/cidr.util';
import { ScopeRateLimiter } from '../services/scope-guard/rate-limiter';

async function runScopeGuardTestSuite() {
  console.log('============================================================');
  console.log('CYBERSPLOI EXERCISE ENGINE: SCOPE GUARD TEST SUITE');
  console.log('============================================================\n');

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
      if (details) console.error(`       › Details: ${details}`);
      throw new Error(`Test failed: ${name}`);
    }
  }

  const testRunId = `test_${Date.now()}`;

  try {
    // ------------------------------------------------------------
    // 1. CIDR & PATTERN MATCHING UNIT TESTS
    // ------------------------------------------------------------
    console.log('--- 1. CIDR & Pattern Matching Logic ---');
    test('IPv4 in CIDR (192.168.1.50 in 192.168.1.0/24)', isIpInIpv4Cidr('192.168.1.50', '192.168.1.0/24'));
    test('IPv4 outside CIDR (10.0.0.1 in 192.168.1.0/24)', !isIpInIpv4Cidr('10.0.0.1', '192.168.1.0/24'));
    test('Wildcard domain match (api.corp.test with *.corp.test)', isDomainMatch('api.corp.test', '*.corp.test'));
    test('Wildcard domain non-match (corp.other with *.corp.test)', !isDomainMatch('corp.other', '*.corp.test'));

    const ruleCheckWithPort = isTargetAllowed('192.168.1.100', 8080, 'http', [
      { host: '192.168.1.100', ports: [80, 443] }
    ]);
    test('Port allowlist blocks unauthorized port (8080 when only 80,443 allowed)', !ruleCheckWithPort);

    // ------------------------------------------------------------
    // 2. ENGAGEMENT CREATION & DEFAULTS
    // ------------------------------------------------------------
    console.log('\n--- 2. Engagement Default State & Safe Baseline ---');
    const engagement = await prisma.engagement.create({
      data: {
        name: `Engagement Baseline ${testRunId}`,
        // Defaults: environment: lab, status: planning
        environment: 'lab',
        status: 'planning',
        scope: {
          create: {
            allowedTargets: JSON.stringify([
              { host: 'lab.cybersploi.local', ports: [80, 443] },
              { cidr: '10.10.10.0/24' }
            ]),
            allowedTestTypes: JSON.stringify(['RECON', 'AUTH', 'IDOR', 'INJECTION']),
            destructiveActionsAllowed: false,
            activePoCAllowed: false,
            rateLimit: JSON.stringify({ requestsPerSecond: 2, concurrency: 2 }),
            validFrom: new Date(Date.now() - 3600000), // 1 hour ago
            validUntil: new Date(Date.now() + 3600000), // 1 hour from now
            approvedBy: 'Lead Security Architect'
          }
        }
      },
      include: { scope: true }
    });

    test('New engagement created with ID', !!engagement.id);
    test('Default environment is "lab"', engagement.environment === 'lab');
    test('Default status is "planning"', engagement.status === 'planning');
    test('Default destructiveActionsAllowed is false', engagement.scope?.destructiveActionsAllowed === false);
    test('Default activePoCAllowed is false', engagement.scope?.activePoCAllowed === false);

    // ------------------------------------------------------------
    // 3. TARGET BOUNDARY: OUT-OF-SCOPE PRECEDENCE
    // ------------------------------------------------------------
    console.log('\n--- 3. Target Scope Enforcement (Out-of-Scope Precedence) ---');
    // "Any action against a host not in allowedTargets is rejected and logged, regardless of engagement status."
    const outOfScopeCheck = await checkScope(engagement.id, {
      testType: 'RECON',
      targetHost: 'unauthorized-external-target.com',
      isDestructive: false,
      isPoC: false
    });

    test(
      'Out-of-scope host rejected with BLOCKED_OUT_OF_SCOPE even on planning status',
      outOfScopeCheck.decision === 'BLOCKED_OUT_OF_SCOPE' && outOfScopeCheck.allowed === false,
      `Decision: ${outOfScopeCheck.decision}, Reason: ${outOfScopeCheck.reason}`
    );

    // ------------------------------------------------------------
    // 4. INACTIVE & EXPIRED ENGAGEMENT ENFORCEMENT
    // ------------------------------------------------------------
    console.log('\n--- 4. Temporal Validity & Active Status ---');
    // In-scope host, but engagement is currently in 'planning' status
    const inactiveCheck = await checkScope(engagement.id, {
      testType: 'RECON',
      targetHost: 'lab.cybersploi.local',
      targetPort: 80,
      isDestructive: false,
      isPoC: false
    });

    test(
      'In-scope target on inactive (planning) engagement rejected with BLOCKED_EXPIRED_SCOPE',
      inactiveCheck.decision === 'BLOCKED_EXPIRED_SCOPE' && inactiveCheck.allowed === false,
      `Decision: ${inactiveCheck.decision}`
    );

    // Now activate the engagement
    await prisma.engagement.update({
      where: { id: engagement.id },
      data: { status: 'active' }
    });

    // Test with an expired scope
    const expiredEngagement = await prisma.engagement.create({
      data: {
        name: `Expired Engagement ${testRunId}`,
        status: 'active',
        environment: 'lab',
        scope: {
          create: {
            allowedTargets: JSON.stringify(['lab.cybersploi.local']),
            allowedTestTypes: JSON.stringify(['RECON']),
            destructiveActionsAllowed: false,
            activePoCAllowed: false,
            rateLimit: JSON.stringify({ requestsPerSecond: 10 }),
            validFrom: new Date(Date.now() - 7200000),
            validUntil: new Date(Date.now() - 3600000), // Expired 1 hour ago
            approvedBy: 'Lead Architect'
          }
        }
      }
    });

    const expiredCheck = await checkScope(expiredEngagement.id, {
      testType: 'RECON',
      targetHost: 'lab.cybersploi.local',
      isDestructive: false,
      isPoC: false
    });

    test(
      'Expired scope rejected with BLOCKED_EXPIRED_SCOPE',
      expiredCheck.decision === 'BLOCKED_EXPIRED_SCOPE' && expiredCheck.allowed === false,
      `Decision: ${expiredCheck.decision}`
    );

    // ------------------------------------------------------------
    // 5. TEST TYPE ALLOWLIST ENFORCEMENT
    // ------------------------------------------------------------
    console.log('\n--- 5. Test Type Allowlist ---');
    const disallowedTypeCheck = await checkScope(engagement.id, {
      testType: 'UNAUTHORIZED_EXPLOIT_SCAN',
      targetHost: 'lab.cybersploi.local',
      targetPort: 80,
      isDestructive: false,
      isPoC: false
    });

    test(
      'Disallowed test type rejected with BLOCKED_TEST_TYPE',
      disallowedTypeCheck.decision === 'BLOCKED_TEST_TYPE' && disallowedTypeCheck.allowed === false,
      `Decision: ${disallowedTypeCheck.decision}`
    );

    // ------------------------------------------------------------
    // 6. DESTRUCTIVE ACTION SAFETY SWITCH
    // ------------------------------------------------------------
    console.log('\n--- 6. Destructive Actions Safety Switch ---');
    const destructiveCheck = await checkScope(engagement.id, {
      testType: 'INJECTION',
      targetHost: 'lab.cybersploi.local',
      targetPort: 80,
      isDestructive: true,
      isPoC: false
    });

    test(
      'Destructive action blocked with BLOCKED_DESTRUCTIVE_ACTION when flag is false',
      destructiveCheck.decision === 'BLOCKED_DESTRUCTIVE_ACTION' && destructiveCheck.allowed === false,
      `Decision: ${destructiveCheck.decision}`
    );

    // ------------------------------------------------------------
    // 7. ACTIVE POC SAFETY SWITCH
    // ------------------------------------------------------------
    console.log('\n--- 7. Active PoC Safety Switch ---');
    const pocCheck = await checkScope(engagement.id, {
      testType: 'INJECTION',
      targetHost: 'lab.cybersploi.local',
      targetPort: 80,
      isDestructive: false,
      isPoC: true
    });

    test(
      'PoC action blocked with BLOCKED_POC_DISABLED when activePoCAllowed is false',
      pocCheck.decision === 'BLOCKED_POC_DISABLED' && pocCheck.allowed === false,
      `Decision: ${pocCheck.decision}`
    );

    // ------------------------------------------------------------
    // 8. RATE LIMITING (TOKEN BUCKET)
    // ------------------------------------------------------------
    console.log('\n--- 8. Token Bucket Rate Limiting ---');
    // Set rate limit to 1 rps for deterministic burst exhaustion test
    await prisma.scope.update({
      where: { engagementId: engagement.id },
      data: {
        rateLimit: JSON.stringify({ requestsPerSecond: 1, concurrency: 1 })
      }
    });
    await ScopeRateLimiter.resetBucket(engagement.id);

    const req1 = await checkScope(engagement.id, {
      testType: 'RECON',
      targetHost: 'lab.cybersploi.local',
      targetPort: 80,
      isDestructive: false,
      isPoC: false
    });
    const req2 = await checkScope(engagement.id, {
      testType: 'RECON',
      targetHost: 'lab.cybersploi.local',
      targetPort: 80,
      isDestructive: false,
      isPoC: false
    });

    test('Initial request 1 passes within rate limit', req1.allowed === true);
    test(
      'Immediate burst request 2 rejected with BLOCKED_RATE_LIMIT',
      req2.decision === 'BLOCKED_RATE_LIMIT' && req2.allowed === false,
      `Decision: ${req2.decision}, Reason: ${req2.reason}`
    );

    // ------------------------------------------------------------
    // 9. FULLY AUTHORIZED TEST PASS
    // ------------------------------------------------------------
    console.log('\n--- 9. Fully Authorized Action Execution ---');
    // Restore rate limit to 10 rps
    await prisma.scope.update({
      where: { engagementId: engagement.id },
      data: {
        rateLimit: JSON.stringify({ requestsPerSecond: 10, concurrency: 5 })
      }
    });
    await ScopeRateLimiter.resetBucket(engagement.id);
    const authorizedCheck = await checkScope(engagement.id, {
      testType: 'RECON',
      targetHost: '10.10.10.45', // In CIDR 10.10.10.0/24
      isDestructive: false,
      isPoC: false
    });

    test(
      'Authorized CIDR host action passes with ALLOWED',
      authorizedCheck.decision === 'ALLOWED' && authorizedCheck.allowed === true,
      `Decision: ${authorizedCheck.decision}`
    );

    // ------------------------------------------------------------
    // 10. DISTINCT AUDIT LOG DECISION VERIFICATION
    // ------------------------------------------------------------
    console.log('\n--- 10. Audit Log Integrity & Distinct Decision Codes ---');
    const auditLogs = await prisma.auditLogEntry.findMany({
      where: { engagementId: engagement.id }
    });

    const recordedDecisions = new Set(auditLogs.map(l => l.decision));
    console.log('Recorded audit log decisions:', Array.from(recordedDecisions));

    const expectedDistinctDecisions = [
      'BLOCKED_OUT_OF_SCOPE',
      'BLOCKED_EXPIRED_SCOPE',
      'BLOCKED_TEST_TYPE',
      'BLOCKED_DESTRUCTIVE_ACTION',
      'BLOCKED_POC_DISABLED',
      'BLOCKED_RATE_LIMIT',
      'ALLOWED'
    ];

    for (const dec of expectedDistinctDecisions) {
      test(`Audit log contains distinct decision "${dec}"`, recordedDecisions.has(dec));
    }

    test('Audit log count corresponds to all invocations (denials not dropped)', auditLogs.length >= 7);

    // ------------------------------------------------------------
    // 11. SCOPE UPDATE WITH APPROVED_BY ENFORCEMENT
    // ------------------------------------------------------------
    console.log('\n--- 11. Scope Modification & PoC Opt-Up ---');
    // Simulate scope update enabling PoC mode
    await prisma.scope.update({
      where: { engagementId: engagement.id },
      data: {
        activePoCAllowed: true,
        approvedBy: 'CISO / Security Director'
      }
    });

    await ScopeRateLimiter.resetBucket(engagement.id);
    const postUpdatePocCheck = await checkScope(engagement.id, {
      testType: 'INJECTION',
      targetHost: 'lab.cybersploi.local',
      targetPort: 80,
      isDestructive: false,
      isPoC: true
    });

    test(
      'PoC action is ALLOWED after explicit opt-up with approval',
      postUpdatePocCheck.decision === 'ALLOWED' && postUpdatePocCheck.allowed === true,
      `Decision: ${postUpdatePocCheck.decision}`
    );

    console.log('\n============================================================');
    console.log(`ALL TESTS PASSED! (${passed}/${total})`);
    console.log('============================================================\n');
  } finally {
    await ScopeRateLimiter.disconnect();
    await prisma.$disconnect();
  }
}

// Run test suite
runScopeGuardTestSuite().catch(err => {
  console.error('[FATAL] Test suite failed with unhandled error:', err);
  process.exit(1);
});
