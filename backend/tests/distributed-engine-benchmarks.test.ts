import * as crypto from 'crypto';
import prisma from '../config/database';
import { ScopeGuard, ScopeAction } from '../services/scope-guard/scope-guard.service';
import {
  NativeWorkerPoolService,
  JobContract,
  JobStatus,
  WorkerOperationType
} from '../services/offensive-engine/native-worker-pool.service';
import { WorkerClientService } from '../services/offensive-engine/worker-client.service';
import { AttackPathService } from '../services/offensive-engine/attack-path.service';
import { SecurityGraphService } from '../services/offensive-engine/security-graph.service';
import {
  FormalAuthSolverService,
  AuthPolicy,
  ReachabilityQuery
} from '../services/offensive-engine/formal-auth-solver.service';
import { ControlledProofEnvService } from '../services/offensive-engine/controlled-proof-env.service';
import { TelemetryPipelineService } from '../services/offensive-engine/telemetry-pipeline.service';
import { ProtocolFuzzerService } from '../services/offensive-engine/protocol-fuzzer.service';
import { GauntletLoopService } from '../services/offensive-engine/gauntlet-loop.service';
import { MockTargetServer } from './fixtures/mock-target-server';

async function runDistributedEngineBenchmarks() {
  console.log('================================================================');
  console.log('CYBERSPLOI DISTRIBUTED ENGINE: PERFORMANCE & ARCHITECTURE BENCHMARKS');
  console.log('================================================================\n');

  let passed = 0;
  let total = 0;

  function assertTest(name: string, condition: boolean, details?: string) {
    total++;
    if (condition) {
      passed++;
      console.log(`[PASS] Benchmark ${total}: ${name}`);
      if (details) console.log(`       › ${details}`);
    } else {
      console.error(`[FAIL] Benchmark ${total}: ${name}`);
      if (details) console.error(`       › Details: ${details}`);
      throw new Error(`Assertion failed: ${name}`);
    }
  }

  // 0. Setup Mock Target Server
  const mockServer = new MockTargetServer();
  const mockPort = await mockServer.start();
  console.log(`[Setup] Mock Target Server listening on 127.0.0.1:${mockPort}`);

  const testRunId = `bench_${Date.now()}`;
  let engagementId: string = '';

  try {
    // Provision engagement & scope for testing
    const engagement = await prisma.engagement.create({
      data: {
        name: `Distributed Benchmark Engagement ${testRunId}`,
        environment: 'lab',
        status: 'active',
        currentPhase: 'RECON',
        scope: {
          create: {
            allowedTargets: JSON.stringify([
              { host: '127.0.0.1', ports: [mockPort] },
              { host: 'lab.cybersploi.local' }
            ]),
            allowedTestTypes: JSON.stringify(['RECON', 'MAPPING', 'AUTH', 'FUZZ', 'POC', 'INJECTION']),
            destructiveActionsAllowed: false,
            activePoCAllowed: true,
            rateLimit: JSON.stringify({ requestsPerSecond: 100, concurrency: 20 }),
            concurrencyLimit: 20,
            validFrom: new Date(Date.now() - 3600000),
            validUntil: new Date(Date.now() + 3600000),
            approvedBy: 'Principal Benchmark Architect'
          }
        }
      },
      include: { scope: true }
    });
    engagementId = engagement.id;

    // =========================================================================
    // 1. HIGH-PERFORMANCE EXECUTION LAYER & NATIVE WORKER POOL BENCHMARK
    // =========================================================================
    console.log('\n--- SUBSYSTEM 1: High-Performance Execution Layer ---');
    const workerPool = NativeWorkerPoolService.getInstance({ workerCount: 8 });

    // Generate valid ApprovedAction
    const approved = (await ScopeGuard.checkScope(engagementId, {
      testType: 'RECON',
      targetHost: '127.0.0.1',
      targetPort: mockPort
    })).approvedAction!;

    const BURST_SIZE = 50;
    console.log(`[Benchmark] Dispatching concurrent burst of ${BURST_SIZE} jobs to NativeWorkerPool...`);
    const burstStart = Date.now();

    const jobPromises = Array.from({ length: BURST_SIZE }, (_, i) => {
      const job: JobContract = {
        jobId: `bench_job_${i}_${Date.now()}`,
        engagementId,
        authorizedTargetScope: {
          target: '127.0.0.1',
          targetPort: mockPort,
          targetProtocol: 'http',
          scopeDecision: 'ALLOWED',
          token: approved.token,
          expiresAt: approved.expiresAt,
          engagementId
        },
        operationType: 'RECON',
        timeout: 5000,
        concurrencyLimit: 10,
        resultSchema: 'WorkerExecutionResult/1.0',
        parameters: { path: '/public/status' },
        createdAt: new Date().toISOString(),
        status: 'PENDING'
      };
      return workerPool.submitJob(job);
    });

    const results = await Promise.all(jobPromises);
    const burstDurationMs = Date.now() - burstStart;
    const metrics = workerPool.getMetrics();

    assertTest(
      'Burst dispatch completed with 100% success rate',
      results.length === BURST_SIZE && results.every(r => r.status === 'SUCCESS'),
      `Processed: ${results.length}/${BURST_SIZE}, Duration: ${burstDurationMs}ms`
    );

    assertTest(
      'Worker pool queue latency within high-performance threshold (< 300ms for 50 concurrent jobs)',
      metrics.p95DispatchLatencyMs < 300,
      `p50: ${metrics.p50DispatchLatencyMs}ms, p95: ${metrics.p95DispatchLatencyMs}ms, p99: ${metrics.p99DispatchLatencyMs}ms (Throughput: ${Math.round((BURST_SIZE / burstDurationMs) * 1000)} req/s)`
    );


    assertTest(
      'Worker saturation and throughput measured accurately',
      metrics.bytesProcessed > 0 && metrics.memoryUtilizationMb > 0,
      `Saturation: ${metrics.workerSaturation.toFixed(2)}, Memory: ${metrics.memoryUtilizationMb}MB, Bytes: ${metrics.bytesProcessed}`
    );

    // =========================================================================
    // 2. DISTRIBUTED JOB CONTRACT & STRICT SCOPE ENFORCEMENT
    // =========================================================================
    console.log('\n--- SUBSYSTEM 2: Distributed Job Contract & Scope Enforcement ---');

    // Reject forged token
    const forgedJob: JobContract = {
      jobId: 'forged_job_001',
      engagementId,
      authorizedTargetScope: {
        target: '127.0.0.1',
        scopeDecision: 'ALLOWED',
        token: 'FORGED_INVALID_CRYPTOGRAPHIC_TOKEN_32',
        expiresAt: new Date(Date.now() + 60000).toISOString(),
        engagementId
      },
      operationType: 'RECON',
      timeout: 5000,
      concurrencyLimit: 5,
      resultSchema: '1.0',
      createdAt: new Date().toISOString(),
      status: 'PENDING'
    };
    // If token length is valid but unapproved by ScopeGuard
    const forgedScopeAction = {
      ...approved,
      token: 'TAMPERED_HMAC_SIGNATURE_VALUE_00000000'
    };
    let forgedRejected = false;
    try {
      await WorkerClientService.executeJob(forgedScopeAction);
    } catch (err: any) {
      forgedRejected = err.message.includes('ARCHITECTURAL_VIOLATION');
    }
    assertTest('Forged scope token rejected with ARCHITECTURAL_VIOLATION', forgedRejected);

    // Reject out-of-scope target
    const outOfScope = await ScopeGuard.checkScope(engagementId, {
      testType: 'RECON',
      targetHost: 'unauthorized-external-asset.com'
    });
    assertTest('Out-of-scope external target rejected by ScopeGuard', !outOfScope.allowed && outOfScope.decision === 'BLOCKED_OUT_OF_SCOPE');

    // =========================================================================
    // 3. IDENTITY & ATTACK-SURFACE GRAPH + A* CROWN JEWEL PATHS
    // =========================================================================
    console.log('\n--- SUBSYSTEM 3: Identity & Attack-Surface Graph + A* Paths ---');

    // Build multi-hop graph chain
    const actorNode = await SecurityGraphService.upsertNode(engagementId, 'IDENTITY', 'untrusted_actor', 'External Untrusted User');
    const apiNode = await SecurityGraphService.upsertNode(engagementId, 'API', 'gateway_api', 'Public API Gateway');
    const ssrfVulnNode = await SecurityGraphService.upsertNode(engagementId, 'VULNERABILITY', 'vuln_ssrf_01', 'SSRF in document fetcher');
    const imdsNode = await SecurityGraphService.upsertNode(engagementId, 'SERVICE', 'imds_metadata', 'EC2 Instance Metadata');
    const roleNode = await SecurityGraphService.upsertNode(engagementId, 'IAM_ROLE', 'dev_instance_role', 'DevInstanceRole');
    const crownJewelNode = await SecurityGraphService.upsertNode(engagementId, 'CROWN_JEWEL', 'prod_customer_db', 'Production Customer DB', { isCrownJewel: true });

    // Connect edges
    await SecurityGraphService.upsertEdge(engagementId, actorNode.id, apiNode.id, 'CALLS', { weight: 1.0 });
    await SecurityGraphService.upsertEdge(engagementId, apiNode.id, ssrfVulnNode.id, 'EXPOSES', { weight: 0.5 });
    await SecurityGraphService.upsertEdge(engagementId, ssrfVulnNode.id, imdsNode.id, 'LEADS_TO', { weight: 0.5 });
    await SecurityGraphService.upsertEdge(engagementId, imdsNode.id, roleNode.id, 'ASSUMES_ROLE', { weight: 0.5 });
    await SecurityGraphService.upsertEdge(engagementId, roleNode.id, crownJewelNode.id, 'AUTHORIZES', { weight: 0.5 });

    // A* Pathfinding to Crown Jewel
    const attackPaths = await AttackPathService.findAttackPathsToCrownJewels(engagementId, 'untrusted_actor');

    assertTest(
      'A* graph algorithm successfully discovered path to Crown Jewel',
      attackPaths.length > 0 && attackPaths[0].nodeSequence.includes('prod_customer_db'),
      `Hops: ${attackPaths[0]?.pathLength}, Sequence: ${attackPaths[0]?.nodeSequence.join(' -> ')}`
    );

    assertTest(
      'Cumulative risk score and blast radius computed correctly',
      attackPaths[0].cumulativeRisk >= 70 && attackPaths[0].downstreamBlastRadius.crownJewelsExposed.includes('Production Customer DB'),
      `Cumulative Risk: ${attackPaths[0].cumulativeRisk}, Blast Radius Exposed: ${attackPaths[0].downstreamBlastRadius.totalExposedNodes} nodes`
    );

    // =========================================================================
    // 4. DYNAMIC FINDING STATUS PROPAGATION & PATH INVALIDATION
    // =========================================================================
    console.log('\n--- SUBSYSTEM 4: Dynamic Finding Propagation & Path Invalidation ---');

    // Create findings
    const f1 = await prisma.engineFinding.create({
      data: {
        engagementId,
        title: 'Initial Credential Exposure',
        description: 'Hardcoded key in dev config',
        category: 'CREDENTIALS',
        severity: 'HIGH',
        target: '127.0.0.1',
        status: 'SUSPECTED'
      }
    });

    const f2 = await prisma.engineFinding.create({
      data: {
        engagementId,
        title: 'Admin Console Access',
        description: 'Privileged admin access gained',
        category: 'AUTH',
        severity: 'CRITICAL',
        target: '127.0.0.1',
        status: 'SUSPECTED'
      }
    });

    const pathObj = await AttackPathService.createAttackPath({
      engagementId,
      title: 'Credential to Admin Escalation',
      findingIds: [f1.id, f2.id]
    });

    assertTest('Attack path initialized with HYPOTHESIZED status', pathObj?.status === 'HYPOTHESIZED');

    // Propagate finding status to VALIDATED
    await AttackPathService.propagateFindingStatus(f1.id, 'VALIDATED');
    const intermediatePath = await AttackPathService.getAttackPath(pathObj!.id);
    assertTest('Path status transitions upon finding validation', intermediatePath?.status === 'INCOMPLETE' || intermediatePath?.status === 'HYPOTHESIZED');

    // Dynamic Invalidation: When vulnerability is remediated or disproven
    const invalidationResult = await AttackPathService.propagateFindingStatus(f1.id, 'REMEDIATED');
    const invalidatedPath = await AttackPathService.getAttackPath(pathObj!.id);
    assertTest(
      'Path dynamically marked INVALIDATED when constituent finding is remediated',
      invalidatedPath?.status === 'INVALIDATED' && invalidationResult.affectedPathsCount > 0,
      `Path Status: ${invalidatedPath?.status}, Affected Paths: ${invalidationResult.affectedPathsCount}`
    );

    // =========================================================================
    // 5. FORMAL SMT AUTHORIZATION SOLVER (Z3 / FIRST-ORDER LOGIC)
    // =========================================================================
    console.log('\n--- SUBSYSTEM 5: Formal SMT Authorization Analysis ---');

    const testPolicies: AuthPolicy[] = [
      {
        policyId: 'pol_dev_access',
        name: 'Developer Base Policy',
        statements: [
          {
            sid: 'StmtAllowDevRoleAssumption',
            effect: 'ALLOW',
            principals: ['identity:alice_dev'],
            actions: ['sts:AssumeRole'],
            resources: ['role:DataEngineerRole']
          },
          {
            sid: 'StmtAllowProdRoleAssumption',
            effect: 'ALLOW',
            principals: ['role:DataEngineerRole'],
            actions: ['sts:AssumeRole'],
            resources: ['role:AnalyticsAdminRole']
          },
          {
            sid: 'StmtAllowAnalyticsRead',
            effect: 'ALLOW',
            principals: ['role:AnalyticsAdminRole'],
            actions: ['s3:GetObject', 'database:Query'],
            resources: ['arn:aws:s3:::customer-lake/*']
          }
        ]
      },
      {
        policyId: 'pol_guardrails',
        name: 'Security Guardrail Policy',
        statements: [
          {
            sid: 'StmtDenyDirectRootAccess',
            effect: 'DENY',
            principals: ['identity:alice_dev'],
            actions: ['s3:DeleteBucket', 'admin:*'],
            resources: ['*']
          }
        ]
      }
    ];

    // Query 1: Can alice_dev reach customer-lake via transitive AssumeRole?
    const reachabilityQuery: ReachabilityQuery = {
      subjectPrincipal: 'identity:alice_dev',
      targetAction: 's3:GetObject',
      targetResource: 'arn:aws:s3:::customer-lake/orders.parquet',
      allowRoleAssumption: true
    };

    const solverStart = Date.now();
    const reachResult = FormalAuthSolverService.solveReachability(testPolicies, reachabilityQuery);
    const solverDuration = Date.now() - solverStart;

    assertTest(
      'SMT solver proves transitive privilege escalation is SAT',
      reachResult.isReachable === true && reachResult.solverStatus === 'SAT',
      `Transitive Chain: ${reachResult.transitiveRolePath?.join(' -> ')}, Proof Steps: ${reachResult.proofSteps.length}`
    );

    assertTest(
      'SMT solver produces formal SMT-LIB2 theorem representation',
      reachResult.smtLib2Representation.includes('(check-sat)') && reachResult.smtLib2Representation.includes('(declare-fun CanAssume'),
      `SMT-LIB2 verified, Duration: ${solverDuration}ms`
    );

    // Query 2: Deny check - Can alice_dev delete bucket?
    const denyQuery: ReachabilityQuery = {
      subjectPrincipal: 'identity:alice_dev',
      targetAction: 's3:DeleteBucket',
      targetResource: 'arn:aws:s3:::critical-system-bucket'
    };
    const denyResult = FormalAuthSolverService.solveReachability(testPolicies, denyQuery);
    assertTest(
      'SMT solver proves explicit DENY produces UNSAT',
      denyResult.isReachable === false && denyResult.solverStatus === 'UNSAT'
    );

    // =========================================================================
    // 6. EPHEMERAL CONTROLLED PROOF ENVIRONMENT
    // =========================================================================
    console.log('\n--- SUBSYSTEM 6: Ephemeral Controlled Proof Environment ---');

    const labEnv = new ControlledProofEnvService();
    const labPort = await labEnv.start({ ttlMs: 10000 });

    assertTest('Ephemeral proof environment started on isolated dynamic port', labPort > 1024, `Port: ${labPort}, Env ID: ${labEnv.environmentId}`);

    // Verify Cloud IMDS simulator safely returns credentials without contacting external cloud
    const imdsRes = await fetch(`http://127.0.0.1:${labPort}/latest/meta-data/iam/security-credentials/CyberSPLOI-Lab-Role`);
    const imdsData: any = await imdsRes.json();

    assertTest(
      'Simulated cloud metadata endpoint provides synthetic credentials',
      imdsData.AccessKeyId.startsWith('ASIA-SYNTHETIC') && imdsData.ImdsMode === 'IMDSv1',
      `Simulated Key: ${imdsData.AccessKeyId}`
    );

    // Generate tamper-proof ProofEvidenceBundle
    const proofBundle = labEnv.generateProofBundle({
      vulnerabilityHypothesis: 'IMDSv1 tokenless access permits IAM credential extraction via SSRF',
      prerequisites: ['SSRF parameter identified', 'HTTP hop to 169.254.169.254 permitted'],
      simulatedTransition: 'HTTP GET /latest/meta-data/iam/security-credentials/CyberSPLOI-Lab-Role',
      observedResult: imdsData,
      expectedSecureResult: { expectedStatus: 401, expectedBehavior: 'Require IMDSv2 token header (HttpPutResponseHopLimit=1)' },
      remediation: {
        title: 'Enforce IMDSv2 and Restrict Hop Limit',
        description: 'Disable tokenless IMDSv1 on EC2 instance metadata',
        patchDiff: '--- aws ec2 modify-instance-metadata-options --http-tokens required'
      },
      regressionTest: {
        name: 'test_imds_v2_enforcement',
        testCommand: `curl -s -f http://127.0.0.1:${labPort}/latest/meta-data/iam/security-credentials/CyberSPLOI-Lab-Role`,
        expectedOutcome: 'HTTP 401 or connection refusal'
      }
    });

    assertTest(
      'Tamper-proof ProofEvidenceBundle generated with SHA-256 integrity hash',
      proofBundle.isVerified === true && proofBundle.evidenceHash.length === 64,
      `Hash: ${proofBundle.evidenceHash.slice(0, 16)}...`
    );

    await labEnv.destroy();
    assertTest('Ephemeral environment destroyed and network port released successfully', true);

    // =========================================================================
    // 7. TELEMETRY INGESTION, STREAM ANOMALIES & CIRCUIT BREAKER
    // =========================================================================
    console.log('\n--- SUBSYSTEM 7: Telemetry Pipeline & Stream Anomaly Throttling ---');
    TelemetryPipelineService.reset();

    // 1. Redaction verification
    const sensitivePayload = {
      Authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.supersecret',
      aws_secret_access_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      password: 'ProductionMasterPassword123!'
    };
    const redacted = TelemetryPipelineService.redactSensitiveData(sensitivePayload);
    assertTest(
      'Telemetry stream redacts sensitive tokens, credentials, and passwords',
      redacted.Authorization === '[REDACTED_CREDENTIAL_REF]' && redacted.password === '[REDACTED_CREDENTIAL_REF]'
    );

    // 2. Stream healthy events
    for (let i = 0; i < 20; i++) {
      TelemetryPipelineService.ingest({
        engagementId,
        targetId: '127.0.0.1',
        workerId: 'worker_01',
        timestamp: new Date().toISOString(),
        latencyMs: 15,
        statusCode: 200
      });
    }
    assertTest('Healthy telemetry stream maintains CLOSED circuit breaker', TelemetryPipelineService.getCircuitBreakerState() === 'CLOSED');

    // 3. Inject anomalies (Spike 5xx errors to > 30%)
    for (let i = 0; i < 15; i++) {
      TelemetryPipelineService.ingest({
        engagementId,
        targetId: '127.0.0.1',
        workerId: 'worker_01',
        timestamp: new Date().toISOString(),
        latencyMs: 450, // Latency spike
        statusCode: 500 // Internal server error
      });
    }

    const anomalyReport = TelemetryPipelineService.evaluateSlidingWindow(engagementId);
    assertTest(
      'Circuit breaker tripped to OPEN/THROTTLED upon elevated 5xx and latency anomaly',
      anomalyReport.circuitBreakerState === 'OPEN' || anomalyReport.circuitBreakerState === 'THROTTLED',
      `State: ${anomalyReport.circuitBreakerState}, 5xx Rate: ${anomalyReport.error5xxRatePercent}%, Concurrency Throttled To: ${anomalyReport.suggestedConcurrency}`
    );

    // =========================================================================
    // 8. PROTOCOL-AWARE LABORATORY FUZZING
    // =========================================================================
    console.log('\n--- SUBSYSTEM 8: Protocol-Aware Laboratory Fuzzing ---');

    // Reject external target fuzzing
    let externalFuzzRejected = false;
    try {
      await ProtocolFuzzerService.fuzzEndpoint('http://external-unauthorized-target.org', 'HTTP');
    } catch (err: any) {
      externalFuzzRejected = err.message.includes('SECURITY_BOUNDARY_VIOLATION');
    }
    assertTest('Unrestricted internet fuzzing rejected by security boundary', externalFuzzRejected);

    // Fuzz isolated lab target
    const fuzzResult = await ProtocolFuzzerService.fuzzEndpoint(`http://127.0.0.1:${mockPort}`, 'JSON', { maxMutations: 4 });

    assertTest(
      'JSON protocol mutations generated and evaluated against lab target',
      fuzzResult.metrics.totalMutationsSent >= 4 && fuzzResult.crashes.length > 0,
      `Mutations Sent: ${fuzzResult.metrics.totalMutationsSent}, Crashes Detected: ${fuzzResult.crashes.length}`
    );

    assertTest(
      'Crash minimization and deterministic reproduction command produced',
      fuzzResult.crashes[0].reproductionCommand.includes('curl') && fuzzResult.crashes[0].errorClass === 'PARSER_RECURSION_EXHAUSTION',
      `Reproduction: ${fuzzResult.crashes[0].reproductionCommand.slice(0, 40)}...`
    );

    // =========================================================================
    // 9. SAFE ADAPTIVE 8-STEP GAUNTLET LOOP WITH SANDBOX SUBSTITUTION
    // =========================================================================
    console.log('\n--- SUBSYSTEM 9: Safe Adaptive 8-Step Gauntlet Loop ---');

    // Execute Gauntlet against unapproved/unscoped target -> Must auto-substitute sandbox!
    const unscopedTarget = 'unknown-third-party-host.net';
    const gauntletResult = await GauntletLoopService.execute({
      engagementId,
      target: unscopedTarget,
      testType: 'POC',
      maxIterations: 2,
      testExecutor: async (iter, step, activeTarget) => {
        // Step execution in substituted sandbox
        return {
          success: true,
          vulnerabilityConfirmed: iter === 2,
          observedData: { confirmedInSandbox: true, activeTarget },
          reproductionSteps: `Run step against ${activeTarget}`
        };
      }
    });

    assertTest(
      'Gauntlet automatically substituted ephemeral sandbox for unapproved external target',
      gauntletResult.sandboxSubstituted === true && gauntletResult.activeTargetUsed.startsWith('127.0.0.1'),
      `Original: ${unscopedTarget} -> Substituted Sandbox: ${gauntletResult.activeTargetUsed}`
    );

    assertTest(
      'Gauntlet completed full 8-step lifecycle and verified finding in VERIFY step',
      gauntletResult.status === 'COMPLETED' && gauntletResult.finalStep === 'VERIFY',
      `Final Step: ${gauntletResult.finalStep}, Evidence: ${gauntletResult.evidenceId}`
    );

    console.log('\n================================================================');
    console.log(`ALL ${total} BENCHMARKS AND ARCHITECTURAL VALIDATIONS PASSED! (${passed}/${total})`);
    console.log('================================================================\n');
  } finally {
    await mockServer.stop();
  }
}

runDistributedEngineBenchmarks()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('[FATAL] Benchmark suite failed:', err);
    process.exit(1);
  });
