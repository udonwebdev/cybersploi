/**
 * CyberSploi Ultra-Deep Authorized Assessment Engine Verification Test Suite
 * Executes end-to-end automated tests against the isolated security testbed:
 * - Negative scope testing
 * - Real socket and HTTP discovery
 * - True finding vs. False-positive differentiation
 * - Full 14-phase autonomous assessment execution
 * - Attack graph generation and chaining
 * - Truthful coverage & blind-spot metrics
 * - Controlled verification session lifecycle and kill-switch
 * - Cancellation mechanics
 * - Report integrity verification
 */

const SecurityTestbed = require('./security-testbed');
const RedTeamOrchestratorService = require('../services/red-team/red-team-orchestrator.service');
const SafetyPolicyService = require('../services/red-team/safety-policy.service');
const ScopeAuthorizationService = require('../services/red-team/scope-authorization.service');
const AssessmentRegistryService = require('../services/red-team/assessment-registry.service');
const VerificationSessionService = require('../services/red-team/verification-session.service');
const prisma = require('../config/database');

async function runTestSuite() {
  console.log('\n============================================================');
  console.log('CYBERSPLOI RED TEAM ASSESSMENT ENGINE VERIFICATION SUITE');
  console.log('============================================================\n');

  let passedTests = 0;
  let totalTests = 0;

  const assert = (condition, testName, detail = '') => {
    totalTests++;
    if (condition) {
      console.log(`[PASS] ${testName}`);
      passedTests++;
    } else {
      console.error(`[FAIL] ${testName} - ${detail}`);
      throw new Error(`Assertion failed: ${testName} (${detail})`);
    }
  };

  // Get active organization from DB
  const org = await prisma.organization.findFirst();
  if (!org) throw new Error('No organization found in database. Run db seed first.');
  const orgId = org.id;

  // Start Security Testbed on localhost 8899 (HTTP) & 8898 (TCP)
  const testbed = new SecurityTestbed(8899, 8898);
  await testbed.start();
  console.log('[Testbed] Initialized on 127.0.0.1:8899 and 127.0.0.1:8898\n');

  try {
    // -------------------------------------------------------------
    // TEST 1: Negative Scope Testing (Section 44)
    // -------------------------------------------------------------
    console.log('--- 1. Testing Negative Scope Boundaries ---');
    const strictScope = ScopeAuthorizationService.parseScope({
      allowedDomains: ['127.0.0.1'],
      allowedPorts: [8899, 8898],
      excludedAssets: ['forbidden.corp']
    }, '127.0.0.1');

    // Probe to unauthorized external host
    const outOfScopeProbe = SafetyPolicyService.validateAction({
      target: 'unauthorized-external.com',
      method: 'GET'
    }, strictScope);
    assert(!outOfScopeProbe.allowed, 'Negative Test: Block out-of-scope host probe');

    // Probe to excluded asset
    const excludedProbe = SafetyPolicyService.validateAction({
      target: 'forbidden.corp',
      method: 'GET'
    }, strictScope);
    assert(!excludedProbe.allowed, 'Negative Test: Block excluded asset probe');

    // Probe with destructive method
    const destructiveProbe = SafetyPolicyService.validateAction({
      target: '127.0.0.1',
      method: 'DELETE'
    }, strictScope);
    assert(!destructiveProbe.allowed, 'Negative Test: Block destructive HTTP method');

    // Prompt injection / Instruction manipulation detection
    const injectionCheck = SafetyPolicyService.validateAction({
      target: '127.0.0.1',
      path: '/test?q=ignore+previous+instructions'
    }, strictScope);
    assert(!injectionCheck.allowed, 'Negative Test: Detect and block adversarial target prompt injection');

    // -------------------------------------------------------------
    // TEST 2: False-Positive Discrimination Test (Section 45)
    // -------------------------------------------------------------
    console.log('\n--- 2. Testing False-Positive Differentiation ---');
    // Ensure the engine distinguishes an authentic secret leak (with key markers) from normal 200 OK responses
    const ReconCartographyService = require('../services/red-team/recon-cartography.service');
    const cartography = await ReconCartographyService.executeApplicationMapping('127.0.0.1', [8899], strictScope);

    const exposedEnvFinding = cartography.discoveredEndpoints.find(e => e.path === '/.env');
    assert(exposedEnvFinding !== undefined, 'True Positive: Discovered authentic sensitive .env file');
    assert(exposedEnvFinding.type === 'exposed_environment_secrets', 'Evidence Verification: Classified as exposed_environment_secrets');

    // Verify that benign pages returning 200 are NOT classified as secret disclosures
    const benignLeak = cartography.sensitiveDisclosures.find(s => s.path === '/benign-page');
    assert(benignLeak === undefined, 'False Positive Reduction: Benign 200 OK page was NOT classified as sensitive secret leak');

    // -------------------------------------------------------------
    // TEST 3: Mandatory Full End-to-End Assessment (Section 43)
    // -------------------------------------------------------------
    console.log('\n--- 3. Executing Full Autonomous Assessment Lifecycle ---');
    
    // Find or create an enrolled asset in Prisma DB
    let asset = await prisma.asset.findFirst({
      where: { organizationId: orgId, value: '127.0.0.1:8899' }
    });
    if (!asset) {
      asset = await prisma.asset.create({
        data: {
          organizationId: orgId,
          type: 'api',
          value: '127.0.0.1:8899',
          description: 'Authorized Security Testbed',
          verificationStatus: 'verified'
        }
      });
    }

    // Create a Scan record
    const scan = await prisma.scan.create({
      data: {
        organizationId: orgId,
        assetId: asset.id,
        type: 'aggressive',
        status: 'running',
        progress: 2,
        startedAt: new Date()
      }
    });

    // Execute the real 14-phase assessment against the testbed
    const assessmentScope = {
      allowedDomains: ['127.0.0.1', 'localhost'],
      allowedPorts: [8899, 8898, 80, 443],
      timeBudgetMinutes: 20,
      destructiveTesting: false,
      credentialTesting: true
    };

    const assessmentResult = await RedTeamOrchestratorService.executeAssessment(
      scan.id,
      asset,
      assessmentScope,
      orgId
    );

    assert(assessmentResult.success === true, 'End-to-End: Assessment completed successfully');
    assert(assessmentResult.verifiedFindingsCount > 0, 'End-to-End: Verified authentic vulnerabilities from testbed');

    // Verify DB records created
    const assessmentDb = await prisma.redTeamAssessment.findUnique({
      where: { id: assessmentResult.assessmentId },
      include: {
        hypotheses: true,
        graphNodes: true,
        graphEdges: true,
        coverage: true,
        events: true,
        sessions: true
      }
    });

    assert(assessmentDb !== null, 'Persistence: RedTeamAssessment record persisted in database');
    assert(assessmentDb.status === 'COMPLETED', 'Persistence: Assessment finalized with truthful COMPLETED status');
    assert(assessmentDb.progress === 100, 'Persistence: Progress recorded as 100% upon finish');
    assert(assessmentDb.hypotheses.length > 0, `Hypothesis Engine: ${assessmentDb.hypotheses.length} hypotheses synthesized and tested`);
    
    // Check that at least one hypothesis was rejected (False Positive Reduction verified)
    const hasRejected = assessmentDb.hypotheses.some(h => h.status === 'REJECTED');
    assert(hasRejected, 'Hypothesis Engine: Successfully disproved and rejected false-positive hypotheses');

    // Check Attack Graph Nodes & Edges
    assert(assessmentDb.graphNodes.length >= 3, `Attack Graph: Generated ${assessmentDb.graphNodes.length} graph nodes`);
    assert(assessmentDb.graphEdges.length >= 2, `Attack Graph: Generated ${assessmentDb.graphEdges.length} graph relations`);

    // Check Coverage & Blind Spots
    assert(assessmentDb.coverage !== null, 'Coverage Engine: Truthful coverage record persisted');
    assert(assessmentDb.coverage.coveragePercent > 0, `Coverage Engine: Calculated coverage is ${assessmentDb.coverage.coveragePercent}%`);
    const blindSpots = JSON.parse(assessmentDb.coverage.blindSpots);
    assert(blindSpots.length > 0, `Blind-Spot Engine: Explicitly identified ${blindSpots.length} operational blind spots`);

    // Check Audit Events
    assert(assessmentDb.events.length >= 10, `Audit Trail: Recorded ${assessmentDb.events.length} chronological audit events`);

    // Check Wellbeing Scorecard, Tech Stack, and Deep Crawl Cartography
    assert(assessmentDb.coverage.breakdown !== null, 'Breakdown: Coverage breakdown stored with deep cartography');
    const breakdown = JSON.parse(assessmentDb.coverage.breakdown);
    assert(breakdown.crawledPages && breakdown.crawledPages.length > 0, `Crawler: Mapped ${breakdown.crawledPages.length} internal pages`);
    assert(breakdown.discoveredForms && breakdown.discoveredForms.length > 0, `Crawler: Mapped ${breakdown.discoveredForms.length} interactive web forms`);
    assert(breakdown.techStack !== undefined, 'Cartography: Technology stack fingerprint recorded');
    assert(breakdown.wellbeingScorecard !== null, 'Wellbeing Engine: 6-pillar scorecard calculated');
    assert(breakdown.wellbeingScorecard.pillars.length === 6, 'Wellbeing Engine: All 6 security pillars evaluated');
    assert(['A+', 'A', 'B', 'C', 'D', 'F'].includes(breakdown.wellbeingScorecard.letterGrade), `Wellbeing Engine: Letter grade assigned (${breakdown.wellbeingScorecard.letterGrade})`);
    assert(breakdown.wellbeingScorecard.overallScore >= 0 && breakdown.wellbeingScorecard.overallScore <= 100, `Wellbeing Engine: Score within bounds (${breakdown.wellbeingScorecard.overallScore}/100)`);

    // Check Deep Attack Surface Hypotheses: Source Maps, CSRF, and Cookie Hygiene
    const hasSourceMapHypo = assessmentDb.hypotheses.some(h => h.title.includes('Source Map'));
    assert(hasSourceMapHypo, 'Deep Assessment: Formulated and verified Exposed Production Source Map hypothesis');

    const hasCsrfHypo = assessmentDb.hypotheses.some(h => h.title.includes('Anti-CSRF'));
    assert(hasCsrfHypo, 'Deep Assessment: Formulated and verified Form Anti-CSRF Protection hypothesis');

    const hasCookieHypo = assessmentDb.hypotheses.some(h => h.title.includes('HttpOnly') || h.title.includes('SameSite') || h.title.includes('Secure Flag'));
    assert(hasCookieHypo, 'Deep Assessment: Formulated and verified Cookie Hygiene & Transport Security hypotheses');

    // -------------------------------------------------------------
    // TEST 4: Controlled Verification Session Lifecycle (Section 26 & 28)
    // -------------------------------------------------------------
    console.log('\n--- 4. Testing Controlled Verification Session Lifecycle ---');
    const session = await VerificationSessionService.createSession({
      assessmentId: assessmentDb.id,
      target: '127.0.0.1:8899',
      findingId: 'VULN-EXPOSED-ENV',
      objective: 'Verify bounded accessibility of environment file in authorized testbed',
      ttlMinutes: 15
    });

    assert(session && session.sessionToken.startsWith('RT-SESS-'), 'Session: Generated secure verification session token');
    assert(session.status === 'ACTIVE', 'Session: Status is ACTIVE upon initialization');

    // Test operator kill-switch termination
    const terminated = await VerificationSessionService.terminateSession(session.sessionToken, 'Operator emergency kill-switch test');
    assert(terminated.status === 'TERMINATED', 'Session Kill-Switch: Status updated immediately to TERMINATED');
    assert(terminated.terminationReason.includes('Operator emergency kill-switch'), 'Session Audit: Termination reason recorded');

    // -------------------------------------------------------------
    // TEST 5: Cancellation Test (Section 48)
    // -------------------------------------------------------------
    console.log('\n--- 5. Testing Cancellation Mechanics ---');
    const cancelScan = await prisma.scan.create({
      data: {
        organizationId: orgId,
        assetId: asset.id,
        type: 'aggressive',
        status: 'running',
        progress: 5,
        startedAt: new Date()
      }
    });

    const cancelAssessment = await prisma.redTeamAssessment.create({
      data: {
        scanId: cancelScan.id,
        phase: 'RECONNAISSANCE',
        currentObjective: 'Active scanning',
        progress: 15,
        status: 'RUNNING',
        startedAt: new Date()
      }
    });

    AssessmentRegistryService.register(cancelAssessment.id, cancelScan.id);
    assert(AssessmentRegistryService.isCancelled(cancelAssessment.id) === false, 'Cancellation: Active job is registered and not cancelled');

    await AssessmentRegistryService.cancel(cancelAssessment.id, 'User clicked stop button');
    assert(AssessmentRegistryService.isCancelled(cancelAssessment.id) === true, 'Cancellation: Job flagged as cancelled in registry');

    const updatedCancelDb = await prisma.redTeamAssessment.findUnique({ where: { id: cancelAssessment.id } });
    assert(updatedCancelDb.status === 'CANCELLED', 'Cancellation: Database records status CANCELLED');

    // -------------------------------------------------------------
    // TEST 6: Report Integrity Test (Section 49)
    // -------------------------------------------------------------
    console.log('\n--- 6. Testing Report Integrity ---');
    const reportFindings = await prisma.vulnerability.findMany({
      where: { scanId: scan.id }
    });
    assert(reportFindings.length > 0, `Report Integrity: Persisted ${reportFindings.length} vulnerabilities for scan`);
    for (const vuln of reportFindings) {
      assert(vuln.evidence !== null && vuln.evidence.length > 0, `Report Traceability: Finding '${vuln.title}' has traceable evidence`);
      assert(vuln.cwe !== null, `Report Traceability: Finding '${vuln.title}' maps to CWE (${vuln.cwe})`);
    }

    // -------------------------------------------------------------
    // TEST 7: Blue Team Defense Handoff Staging
    // -------------------------------------------------------------
    console.log('\n--- 7. Testing Blue Team Defense Handoff Staging ---');
    const redTeamRouter = require('../routes/red-team');
    const handoffLayer = redTeamRouter.stack.find(
      (layer) => layer.route && layer.route.path === '/assessments/:id/handoff-blue-team'
    );
    assert(handoffLayer !== undefined, 'Route Registry: POST /assessments/:id/handoff-blue-team is registered in redTeamRouter');

    const handoffHandler = handoffLayer.route.stack[0].handle;
    let handoffResponse = null;

    await handoffHandler(
      { params: { id: assessmentDb.id } },
      {
        json: (data) => { handoffResponse = data; },
        status: (code) => ({
          json: (data) => { handoffResponse = { statusCode: code, ...data }; }
        })
      }
    );

    assert(handoffResponse !== null, 'Blue Team Handoff: Handler executed and returned response');
    assert(handoffResponse.success === true, 'Blue Team Handoff: Successfully staged findings for defense engine');
    assert(handoffResponse.data.status === 'STAGED_FOR_DEFENSE_ORCHESTRATOR', 'Blue Team Handoff: Status is STAGED_FOR_DEFENSE_ORCHESTRATOR');
    assert(handoffResponse.data.wafRules.length > 0, `Blue Team Handoff: Generated ${handoffResponse.data.wafRules.length} ModSecurity WAF rules`);
    assert(handoffResponse.data.remediationTasks.length > 0, `Blue Team Handoff: Generated ${handoffResponse.data.remediationTasks.length} prioritized remediation tasks`);
    assert(handoffResponse.data.wafRules[0].modSecurityExpression.includes('SecRule'), 'Blue Team Handoff: Verified ModSecurity SecRule syntax');
    assert(handoffResponse.data.wafRules[0].cloudflareExpression.includes('Block'), 'Blue Team Handoff: Verified Cloudflare firewall syntax');

    // Verify DEFENSE_HANDOFF audit event in database
    const handoffEvents = await prisma.assessmentEvent.findMany({
      where: {
        assessmentId: assessmentDb.id,
        phase: 'DEFENSE_HANDOFF'
      }
    });
    assert(handoffEvents.length > 0, 'Blue Team Handoff: Persisted DEFENSE_HANDOFF audit event');
    assert(handoffEvents[0].level === 'SUCCESS', 'Blue Team Handoff: DEFENSE_HANDOFF audit event recorded with SUCCESS level');

    // -------------------------------------------------------------
    // TEST 8: Assessment Brain & Knowledge Model (Final Power Pass)
    // -------------------------------------------------------------
    console.log('\n--- 8. Testing Assessment Brain & Knowledge Model ---');
    assert(breakdown.assessmentBrain !== undefined && breakdown.assessmentBrain !== null, 'Assessment Brain: State persisted in coverage breakdown');
    const brain = breakdown.assessmentBrain;

    // 1. 12-Surface Attack Matrix
    assert(brain.surfaceMatrix !== undefined, 'Assessment Brain: 12-surface attack matrix exists');
    const expectedSurfaces = [
      'EXTERNAL', 'APPLICATION', 'API', 'AUTHENTICATION', 'AUTHORIZATION',
      'DATA', 'FILE', 'ADMINISTRATIVE', 'INTEGRATION', 'BUSINESS_LOGIC',
      'CONFIGURATION', 'DEPENDENCY'
    ];
    for (const surface of expectedSurfaces) {
      assert(brain.surfaceMatrix[surface] !== undefined, `12-Surface Matrix: Tracks surface '${surface}'`);
      assert(['VERIFIED', 'ASSESSED', 'PARTIALLY_ASSESSED', 'NOT_ASSESSED'].includes(brain.surfaceMatrix[surface].status), `12-Surface Matrix: Valid status for '${surface}' (${brain.surfaceMatrix[surface].status})`);
    }

    // 2. Question-Driven Investigation Queue
    assert(Array.isArray(brain.questionQueue), 'Question Queue: Array persisted in brain state');
    assert(brain.questionQueue.length > 0, `Question Queue: Formulated ${brain.questionQueue.length} investigation questions`);
    const sampleQuestion = brain.questionQueue[0];
    assert(sampleQuestion.question && sampleQuestion.question.length > 0, 'Question Queue: Contains defined inquiry question');
    assert(sampleQuestion.securityProperty && sampleQuestion.securityProperty.length > 0, 'Question Queue: Specifies security boundary property');
    assert(sampleQuestion.assumption && sampleQuestion.assumption.length > 0, 'Question Queue: Articulates explicit operational assumption');
    assert(sampleQuestion.provingEvidence && sampleQuestion.disprovingEvidence, 'Question Queue: Contains proving evidence and disproving criteria');
    assert(sampleQuestion.derivedHypothesis && sampleQuestion.derivedHypothesis.length > 0, 'Question Queue: Synthesizes testable derived hypothesis');

    // 3. Deep Authentication State Machine & Authorization Invariants
    assert(brain.authStateMachine !== undefined, 'Auth State Machine: Lifecycle model persisted');
    assert(brain.authStateMachine.states.includes('ANONYMOUS') && brain.authStateMachine.states.includes('AUTHENTICATED'), 'Auth State Machine: Contains valid identity progression states');
    assert(Array.isArray(brain.authorizationMatrix), 'Authorization Matrix: Access control matrix persisted');
    assert(brain.authorizationMatrix.length > 0, `Authorization Matrix: Evaluated ${brain.authorizationMatrix.length} permission invariants`);
    const sampleAuthz = brain.authorizationMatrix[0];
    assert(sampleAuthz.identity && sampleAuthz.resource && sampleAuthz.action, 'Authorization Matrix: Maps identity, resource, and action tuple');
    assert(sampleAuthz.expectedAccess && sampleAuthz.observedAccess, 'Authorization Matrix: Compares expected access against observed access');

    // 4. Root-Cause vs. Symptom Correlation
    assert(Array.isArray(brain.rootCauses), 'Root Causes: Correlation array persisted');
    assert(brain.rootCauses.length > 0, `Root Causes: Correlated findings into ${brain.rootCauses.length} architectural root causes`);
    const sampleRootCause = brain.rootCauses[0];
    assert(sampleRootCause.title && sampleRootCause.rootCause, 'Root Causes: Identifies root architectural deficit');
    assert(sampleRootCause.symptoms && sampleRootCause.symptoms.length > 0, `Root Causes: Groups ${sampleRootCause.symptoms.length} symptom vulnerabilities under '${sampleRootCause.title}'`);

    // 5. Machine-Readable Decision Explanation Logging ("What CyberSploi Is Thinking About")
    assert(brain.currentReasoning !== undefined, 'Operator Reasoning: Current reasoning model persisted');
    assert(brain.currentReasoning.currentInvestigation && brain.currentReasoning.currentInvestigation.length > 0, 'Operator Reasoning: Records active investigation');
    assert(brain.currentReasoning.nextAction && brain.currentReasoning.nextAction.length > 0, 'Operator Reasoning: Records immediate next action');
    assert(brain.currentReasoning.why && brain.currentReasoning.why.length > 0, 'Operator Reasoning: Records strategic rationale (why)');
    assert(brain.memoryStats && brain.memoryStats.decisionLogsCount > 0, `Operator Reasoning: Recorded ${brain.memoryStats.decisionLogsCount} decision explanation audit entries`);

    // 6. Attack-Path Completeness
    assert(Array.isArray(brain.attackPaths), 'Attack Path Completeness: Graph paths analyzed');

    // -------------------------------------------------------------
    // TEST 9: Proof of Execution, Customer Authorization Gate & Tamper-Evident Verification
    // -------------------------------------------------------------
    console.log('\n--- 9. Testing Proof of Execution & Tamper-Evident Verification ---');

    // 1. Customer Authorization Gate: session starts in REQUESTED status
    const requestedSession = await VerificationSessionService.requestSession({
      assessmentId: assessmentDb.id,
      target: '127.0.0.1',
      findingId: 'VULN-EXPOSED-SECRET',
      objective: 'Verify bounded exploitability of exposed configuration secrets',
      requestedActions: ['PROBE_ENDPOINT', 'INSPECT_HEADER', 'FETCH_RETEST_EVIDENCE'],
      ttlMinutes: 15
    });
    assert(requestedSession && requestedSession.status === 'REQUESTED', 'Auth Gate: Session created in REQUESTED state');

    // 2. Action blocked before Customer Authorization Gate approval
    const unapprovedAction = await VerificationSessionService.validateAction(requestedSession.id, 'PROBE_ENDPOINT', '127.0.0.1');
    assert(!unapprovedAction.allowed && unapprovedAction.reason.includes('SESSION_NOT_AUTHORIZED'), 'Auth Gate: Blocked probe execution while in REQUESTED status');

    // 3. Customer Authorization Gate Approval
    const authorizedSession = await VerificationSessionService.authorizeSession(requestedSession.id, {
      authorizedBy: 'Enterprise Security Director',
      permittedActions: ['PROBE_ENDPOINT', 'INSPECT_HEADER', 'FETCH_RETEST_EVIDENCE'],
      ttlMinutes: 25,
      authorizationNotes: 'Explicit customer consent approved in verification suite'
    });
    assert(authorizedSession.status === 'ACTIVE', 'Auth Gate: Session transitioned to ACTIVE upon approval');
    assert(authorizedSession.evidencePayload.authorizedBy === 'Enterprise Security Director', 'Auth Gate: Customer identity recorded');

    // 4. Action Allowlist Enforcement: Permitted action is allowed
    const validAction = await VerificationSessionService.validateAction(authorizedSession.id, 'PROBE_ENDPOINT', '127.0.0.1');
    assert(validAction.allowed === true, 'Allowlist: Permitted action PROBE_ENDPOINT is allowed');

    // 5. Action Allowlist Enforcement: Unallowed action is blocked
    const disallowedAction = await VerificationSessionService.validateAction(authorizedSession.id, 'EXECUTE_REMOTE_SHELL', '127.0.0.1');
    assert(!disallowedAction.allowed && disallowedAction.reason.includes('ACTION_NOT_PERMITTED'), 'Allowlist: Disallowed action EXECUTE_REMOTE_SHELL is strictly blocked');

    // 6. Action Allowlist Enforcement: Out-of-bounds target is blocked
    const outOfBoundsTarget = await VerificationSessionService.validateAction(authorizedSession.id, 'PROBE_ENDPOINT', 'unauthorized-bank.com');
    assert(!outOfBoundsTarget.allowed && outOfBoundsTarget.reason.includes('TARGET_OUT_OF_BOUNDS'), 'Allowlist: Out-of-bounds target probe is strictly blocked');

    // 7. Tamper-Evident Evidence Chaining: Append block 1
    const evidence1 = await VerificationSessionService.recordEvidenceWithHash(authorizedSession.id, {
      action: 'PROBE_ENDPOINT',
      target: '127.0.0.1:8899',
      request: { method: 'GET', endpoint: '/.env' },
      response: { statusCode: 200, containsSecrets: true },
      expectedBehavior: 'HTTP 403 Forbidden',
      observedBehavior: 'HTTP 200 OK with AWS_SECRET_KEY leak'
    });
    assert(evidence1.chainLength === 1, 'Evidence Chain: First evidence block appended');
    assert(evidence1.currentHash && evidence1.currentHash.length === 64, 'Evidence Chain: Generated valid SHA-256 hash (64 hex chars)');

    // 8. Tamper-Evident Evidence Chaining: Append block 2
    const evidence2 = await VerificationSessionService.recordEvidenceWithHash(authorizedSession.id, {
      action: 'INSPECT_HEADER',
      target: '127.0.0.1:8899',
      request: { method: 'HEAD', endpoint: '/' },
      response: { headers: { 'x-powered-by': 'Express' } },
      expectedBehavior: 'Headers sanitized without framework banners',
      observedBehavior: 'Header X-Powered-By exposed'
    });
    assert(evidence2.chainLength === 2, 'Evidence Chain: Second evidence block appended');
    assert(evidence2.evidenceItem.prevHash === evidence1.currentHash, 'Evidence Chain: Block 2 cryptographically linked to Block 1 hash');

    // 9. Mathematical Integrity Verification
    const integrityCheck = await VerificationSessionService.verifyEvidenceIntegrity(authorizedSession.id);
    assert(integrityCheck.valid === true, 'Integrity Check: SHA-256 evidence chain mathematically verified');
    assert(integrityCheck.chainLength === 2, 'Integrity Check: Chain length verified as 2');

    // 10. Tamper Detection Test: Modifying a record invalidates chain
    const sessionForTamper = await prisma.verificationSession.findUnique({ where: { id: authorizedSession.id } });
    const tamperedPayload = JSON.parse(sessionForTamper.evidence);
    const originalAction = tamperedPayload.evidenceChain[0].action;
    tamperedPayload.evidenceChain[0].action = 'TAMPERED_ACTION_PROBE';
    await prisma.verificationSession.update({
      where: { id: authorizedSession.id },
      data: { evidence: JSON.stringify(tamperedPayload) }
    });

    const tamperResult = await VerificationSessionService.verifyEvidenceIntegrity(authorizedSession.id);
    assert(tamperResult.valid === false && tamperResult.brokenAtIndex === 0, 'Tamper Detection: Tampered evidence chain immediately flagged as invalid');

    // Restore untampered state
    tamperedPayload.evidenceChain[0].action = originalAction;
    await prisma.verificationSession.update({
      where: { id: authorizedSession.id },
      data: { evidence: JSON.stringify(tamperedPayload) }
    });
    const restoredCheck = await VerificationSessionService.verifyEvidenceIntegrity(authorizedSession.id);
    assert(restoredCheck.valid === true, 'Tamper Detection: Restored chain verifies successfully');

    // 11. Defensible Proof Object Generation
    const proofObject = await VerificationSessionService.generateProofObject(authorizedSession.id);
    assert(proofObject.proofId && proofObject.proofId.startsWith('PROOF-RT-SESS-'), 'Proof Object: Generated unique proof token');
    assert(proofObject.verificationStatus === 'BOUNDED_CONFIRMED', 'Proof Object: Status is BOUNDED_CONFIRMED');
    assert(proofObject.tamperEvidentSignature === evidence2.currentHash, 'Proof Object: Signature matches head hash of evidence chain');
    assert(proofObject.integrityVerified === true, 'Proof Object: Evidence chain integrity verified');
    assert(proofObject.reproducibilitySteps && proofObject.reproducibilitySteps.length >= 2, 'Proof Object: Contains reproducible verification steps');
    assert(proofObject.reproducibilitySteps[0].command.includes('curl'), 'Proof Object: Reproducibility command provides executable curl verification');

    // 12. Emergency Kill-Switch & Revocation
    const killedSession = await VerificationSessionService.terminateSession(authorizedSession.id, 'Test suite operator emergency termination');
    assert(killedSession.status === 'TERMINATED', 'Kill-Switch: Status updated immediately to TERMINATED');
    const actionAfterKill = await VerificationSessionService.validateAction(authorizedSession.id, 'PROBE_ENDPOINT', '127.0.0.1');
    assert(!actionAfterKill.allowed && actionAfterKill.reason.includes('SESSION_TERMINATED'), 'Kill-Switch: Post-termination probe strictly rejected');

    console.log('\n============================================================');
    console.log(`VERIFICATION COMPLETE: ${passedTests}/${totalTests} TESTS PASSED`);
    console.log('============================================================\n');
  } finally {
    await testbed.stop();
    console.log('[Testbed] Successfully stopped');
  }
}

runTestSuite()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('[TestSuite Failed]:', err);
    process.exit(1);
  });
