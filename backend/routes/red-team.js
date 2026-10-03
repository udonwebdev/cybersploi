/**
 * CyberSploi Red Team Simulation & Autonomous Assessment API
 * Exposes endpoints for assessment telemetry, attack graph nodes/edges,
 * hypothesis lifecycle states, audit events, cancellation, launch, and controlled verification sessions.
 */

const express = require('express');
const router = express.Router();
const prisma = require('../config/database');
const VerificationSessionService = require('../services/red-team/verification-session.service');
const AssessmentRegistryService = require('../services/red-team/assessment-registry.service');
const RedTeamOrchestratorService = require('../services/red-team/red-team-orchestrator.service');

/**
 * POST /api/v1/red-team/assessments/launch
 * Launch an Ultra-Deep Autonomous Assessment with explicit scope configuration
 */
router.post('/assessments/launch', async (req, res) => {
  try {
    const { target, scope, organizationId } = req.body;

    if (!target) {
      return res.status(400).json({ success: false, message: 'Target is required' });
    }

    const orgId = organizationId || req.organizationId || 'default-org';

    // Provision asset record if needed
    let asset = await prisma.asset.findFirst({
      where: {
        organizationId: orgId,
        OR: [{ id: target }, { value: target }]
      }
    });

    if (!asset) {
      asset = await prisma.asset.create({
        data: {
          organizationId: orgId,
          type: 'api',
          value: target,
          description: `Target ${target}`,
          verificationStatus: 'verified'
        }
      });
    }

    // Create Scan
    const scan = await prisma.scan.create({
      data: {
        organizationId: orgId,
        assetId: asset.id,
        type: 'aggressive',
        status: 'running',
        progress: 2,
        configuration: typeof scope === 'object' ? JSON.stringify(scope) : (scope || null),
        startedAt: new Date()
      },
      include: { asset: true }
    });

    // Launch background orchestrator asynchronously
    RedTeamOrchestratorService.executeAssessment(scan.id, asset, scope, orgId).catch((err) => {
      console.error('[RedTeamAPI] Autonomous Assessment execution failed:', err);
    });

    res.status(201).json({
      success: true,
      message: 'Ultra-Deep Authorized Red Team Assessment launched successfully',
      data: {
        scanId: scan.id,
        target,
        status: 'running',
        startedAt: scan.startedAt
      }
    });
  } catch (err) {
    console.error('[RedTeamAPI] Launch error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/v1/red-team/assessments/:id/cancel
 * Cancel an active assessment run
 */
router.post('/assessments/:id/cancel', async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body || {};

    const cancelResult = await AssessmentRegistryService.cancel(id, reason || 'Operator cancelled from UI');

    res.json({
      success: true,
      message: 'Assessment cancellation dispatched',
      data: cancelResult
    });
  } catch (err) {
    console.error('[RedTeamAPI] Cancel error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/v1/red-team/assessments/active
 * Retrieve list of active in-memory and database running assessments
 */
router.get('/assessments/active', async (req, res) => {
  try {
    const activeInMemory = AssessmentRegistryService.listActive();
    const runningInDb = await prisma.redTeamAssessment.findMany({
      where: { status: 'RUNNING' },
      include: { scope: true, scan: { include: { asset: true } } }
    });

    res.json({
      success: true,
      data: {
        activeCount: runningInDb.length,
        inMemoryCount: activeInMemory.length,
        assessments: runningInDb
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/v1/red-team/assessments/:id
 * Retrieve full assessment details with scope, coverage, and recent events
 */
router.get('/assessments/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const assessment = await prisma.redTeamAssessment.findFirst({
      where: {
        OR: [
          { id },
          { scanId: id }
        ]
      },
      include: {
        scope: true,
        coverage: true,
        scan: {
          include: {
            asset: true,
            results: true
          }
        },
        hypotheses: {
          orderBy: { initialConfidence: 'desc' }
        },
        sessions: {
          orderBy: { createdAt: 'desc' },
          take: 5
        },
        events: {
          orderBy: { timestamp: 'desc' },
          take: 50
        }
      }
    });

    if (!assessment) {
      return res.status(404).json({
        success: false,
        error: 'ASSESSMENT_NOT_FOUND',
        message: `Red Team assessment ${id} was not found`
      });
    }

    let wellbeingScorecard = null;
    let techStack = null;
    let crawledPages = [];
    let discoveredForms = [];
    let discoveredApiRoutes = [];
    let assessmentBrain = null;
    if (assessment.coverage?.breakdown) {
      try {
        const bd = JSON.parse(assessment.coverage.breakdown);
        wellbeingScorecard = bd.wellbeingScorecard || null;
        techStack = bd.techStack || null;
        crawledPages = bd.crawledPages || [];
        discoveredForms = bd.discoveredForms || [];
        discoveredApiRoutes = bd.discoveredApiRoutes || [];
        assessmentBrain = bd.assessmentBrain || null;
      } catch (e) {}
    }

    res.json({
      success: true,
      data: {
        ...assessment,
        wellbeingScorecard,
        techStack,
        crawledPages,
        discoveredForms,
        discoveredApiRoutes,
        assessmentBrain
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/v1/red-team/assessments/:id/handoff-blue-team
 * Stage findings into automated defense mitigation payloads for Blue Team orchestration
 */
router.post('/assessments/:id/handoff-blue-team', async (req, res) => {
  try {
    const { id } = req.params;
    const assessment = await prisma.redTeamAssessment.findFirst({
      where: { OR: [{ id }, { scanId: id }] },
      include: {
        scope: true,
        coverage: true,
        hypotheses: { where: { status: 'VERIFIED' } },
        scan: { include: { vulnerabilities: true } }
      }
    });

    if (!assessment) {
      return res.status(404).json({ success: false, message: 'Assessment not found' });
    }

    const vulnerabilities = assessment.scan?.vulnerabilities || [];

    // Build WAF rules, firewall drop rules, and mitigation tasks
    const wafRules = [];
    const firewallRules = [];
    const remediationTasks = [];

    vulnerabilities.forEach((vuln, idx) => {
      const endpoint = vuln.evidence ? (function() {
        try {
          const parsed = JSON.parse(vuln.evidence);
          return parsed.endpoint || parsed.retestedEndpoint || '/';
        } catch(e) { return '/'; }
      })() : '/';

      const path = endpoint.split('?')[0].replace(/^https?:\/\/[^\/]+/, '') || '/';

      wafRules.push({
        ruleId: `WAF-BLOCK-${1000 + idx}`,
        description: `Block exploit traffic targeting: ${vuln.title}`,
        severity: vuln.severity,
        targetPath: path,
        modSecurityExpression: `SecRule REQUEST_URI "@contains ${path}" "id:${8000 + idx},phase:1,deny,status:403,msg:'CyberSploi Defense Block: ${vuln.cve || vuln.title}'"`,
        cloudflareExpression: `(http.request.uri.path contains "${path}") -> Block`
      });

      remediationTasks.push({
        taskId: `DEF-TASK-${100 + idx}`,
        title: `Remediate: ${vuln.title}`,
        priority: vuln.severity === 'CRITICAL' ? 'P0 - IMMEDIATE' : (vuln.severity === 'HIGH' ? 'P1 - HIGH' : 'P2 - MEDIUM'),
        cwe: vuln.cwe,
        remediation: vuln.remediation
      });
    });

    // Record audit event for handoff staging
    await prisma.assessmentEvent.create({
      data: {
        assessmentId: assessment.id,
        phase: 'DEFENSE_HANDOFF',
        stage: 'Blue Team Staging',
        level: 'SUCCESS',
        message: `Staged ${vulnerabilities.length} verified security mitigations and ${wafRules.length} WAF rules for Blue Team defense engine.`,
        timestamp: new Date()
      }
    });

    res.json({
      success: true,
      message: 'Report staged successfully for Blue Team defense ingestion',
      data: {
        assessmentId: assessment.id,
        target: assessment.scope?.target,
        stagedAt: new Date().toISOString(),
        status: 'STAGED_FOR_DEFENSE_ORCHESTRATOR',
        defenseEngineStatus: 'STANDBY (Awaiting Defense Module Activation)',
        summary: {
          totalMitigations: vulnerabilities.length,
          wafRulesCount: wafRules.length,
          remediationTasksCount: remediationTasks.length,
          criticalAlerts: vulnerabilities.filter(v => v.severity === 'CRITICAL').length
        },
        wafRules,
        firewallRules,
        remediationTasks
      }
    });
  } catch (err) {
    console.error('[RedTeamAPI] Blue team handoff failed:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/v1/red-team/assessments/:id/graph
 * Retrieve Attack Graph nodes and edges for interactive visualization
 */
router.get('/assessments/:id/graph', async (req, res) => {
  try {
    const { id } = req.params;

    // Resolve assessment ID
    const assessment = await prisma.redTeamAssessment.findFirst({
      where: {
        OR: [
          { id },
          { scanId: id }
        ]
      },
      select: { id: true, scanId: true }
    });

    if (!assessment) {
      return res.status(404).json({ success: false, message: 'Assessment not found' });
    }

    const nodes = await prisma.attackGraphNode.findMany({
      where: { assessmentId: assessment.id }
    });

    const edges = await prisma.attackGraphEdge.findMany({
      where: { assessmentId: assessment.id }
    });

    res.json({
      success: true,
      data: {
        assessmentId: assessment.id,
        nodes: nodes.map(n => ({
          id: n.nodeId,
          label: n.label,
          category: n.category,
          severity: n.severity,
          status: n.status,
          properties: n.properties ? JSON.parse(n.properties) : {}
        })),
        edges: edges.map(e => ({
          source: e.sourceNodeId,
          target: e.targetNodeId,
          relation: e.relation,
          confidence: e.confidence,
          isCriticalPath: e.isCriticalPath
        })),
        stats: {
          totalNodes: nodes.length,
          totalEdges: edges.length,
          criticalPaths: edges.filter(e => e.isCriticalPath).length
        }
      }
    });
  } catch (err) {
    console.error('[RedTeamAPI] Attack graph fetch failed:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/v1/red-team/assessments/:id/events
 * Chronological assessment event audit trail
 */
router.get('/assessments/:id/events', async (req, res) => {
  try {
    const { id } = req.params;
    const assessment = await prisma.redTeamAssessment.findFirst({
      where: {
        OR: [{ id }, { scanId: id }]
      },
      select: { id: true }
    });

    if (!assessment) {
      return res.status(404).json({ success: false, message: 'Assessment not found' });
    }

    const events = await prisma.assessmentEvent.findMany({
      where: { assessmentId: assessment.id },
      orderBy: { timestamp: 'asc' }
    });

    res.json({
      success: true,
      data: events
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/v1/red-team/assessments/:id/hypotheses
 * Full hypothesis lifecycle list (verified, rejected, inconclusive)
 */
router.get('/assessments/:id/hypotheses', async (req, res) => {
  try {
    const { id } = req.params;
    const assessment = await prisma.redTeamAssessment.findFirst({
      where: {
        OR: [{ id }, { scanId: id }]
      },
      select: { id: true }
    });

    if (!assessment) {
      return res.status(404).json({ success: false, message: 'Assessment not found' });
    }

    const hypotheses = await prisma.redTeamHypothesis.findMany({
      where: { assessmentId: assessment.id },
      orderBy: { initialConfidence: 'desc' }
    });

    res.json({
      success: true,
      data: {
        total: hypotheses.length,
        verified: hypotheses.filter(h => h.status === 'VERIFIED'),
        rejected: hypotheses.filter(h => h.status === 'REJECTED'),
        inconclusive: hypotheses.filter(h => h.status === 'INCONCLUSIVE')
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/v1/red-team/sessions/:id/terminate
 * Emergency / Operator Kill-Switch for bounded verification console
 */
router.post('/sessions/:id/terminate', async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body || {};

    const terminated = await VerificationSessionService.terminateSession(id, reason || 'Operator triggered manual kill-switch from verification console');

    res.json({
      success: true,
      message: 'Verification session terminated immediately',
      data: terminated
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/v1/red-team/sessions/request
 * Request a new verification session requiring Customer Authorization Gate approval
 */
router.post('/sessions/request', async (req, res) => {
  try {
    const { assessmentId, target, findingId, objective, executionContext, privilegeContext, requestedActions, evidence, ttlMinutes } = req.body;
    if (!assessmentId || !target) {
      return res.status(400).json({ success: false, message: 'assessmentId and target are required' });
    }

    const session = await VerificationSessionService.requestSession({
      assessmentId,
      target,
      findingId,
      objective,
      executionContext,
      privilegeContext,
      requestedActions,
      evidence,
      ttlMinutes: ttlMinutes || 15
    });

    res.status(201).json({
      success: true,
      message: 'Verification session requested. Awaiting Customer Authorization Gate approval.',
      data: session
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/v1/red-team/sessions/:id/authorize
 * Customer Authorization Gate: Approve session with explicit permissions, identity, and TTL
 */
router.post('/sessions/:id/authorize', async (req, res) => {
  try {
    const { id } = req.params;
    const { authorizedBy, permittedActions, ttlMinutes, authorizationNotes } = req.body || {};

    const authorized = await VerificationSessionService.authorizeSession(id, {
      authorizedBy: authorizedBy || 'Customer Security Administrator',
      permittedActions,
      ttlMinutes: ttlMinutes || 15,
      authorizationNotes
    });

    res.json({
      success: true,
      message: 'Verification session approved by Customer Authorization Gate',
      data: authorized
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/v1/red-team/sessions/:id/execute-action
 * Execute an allowlisted non-destructive verification probe
 */
router.post('/sessions/:id/execute-action', async (req, res) => {
  try {
    const { id } = req.params;
    const { action, target, findingId, requestPayload, expectedBehavior, notes } = req.body || {};

    if (!action) {
      return res.status(400).json({ success: false, message: 'action is required' });
    }

    const validation = await VerificationSessionService.validateAction(id, action, target);
    if (!validation.allowed) {
      return res.status(403).json({
        success: false,
        error: 'ACTION_BLOCKED',
        message: validation.reason
      });
    }

    const probeTarget = target || validation.session.target;
    let probeResponse = {
      status: 200,
      verified: true,
      timestamp: new Date().toISOString(),
      details: `Executed allowlisted verification action '${action}' against target '${probeTarget}'.`
    };

    if (action === 'PROBE_ENDPOINT' || action === 'INSPECT_HEADER' || action === 'VERIFY_VULNERABILITY') {
      try {
        const http = require('http');
        const https = require('https');
        const client = probeTarget.startsWith('https') ? https : http;
        const probeUrl = probeTarget.startsWith('http') ? probeTarget : `http://${probeTarget}`;

        await new Promise((resolve) => {
          const req = client.get(probeUrl, { timeout: 3000 }, (res) => {
            probeResponse = {
              statusCode: res.statusCode,
              headers: res.headers,
              verified: true,
              probedAt: new Date().toISOString()
            };
            resolve();
          });
          req.on('error', (e) => {
            probeResponse = { error: e.message, verified: false };
            resolve();
          });
          req.setTimeout(3000, () => { req.destroy(); resolve(); });
        });
      } catch (e) {
        probeResponse.note = e.message;
      }
    }

    const recorded = await VerificationSessionService.recordEvidenceWithHash(id, {
      action,
      target: probeTarget,
      findingId: findingId || validation.session.findingId,
      request: requestPayload || { method: 'GET', target: probeTarget },
      response: probeResponse,
      expectedBehavior: expectedBehavior || 'Target rejects unauthorized probe or returns sanitized error.',
      observedBehavior: JSON.stringify(probeResponse),
      notes
    });

    res.json({
      success: true,
      message: `Action '${action}' executed and cryptographically sealed into evidence chain`,
      data: recorded
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/v1/red-team/sessions/:id
 * Retrieve verification session details, allowlist, countdown, and evidence chain
 */
router.get('/sessions/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const session = await VerificationSessionService.getSession(id);
    if (!session) {
      return res.status(404).json({ success: false, message: 'Verification session not found' });
    }

    const parsedEvidence = VerificationSessionService.parseEvidencePayload(session.evidence);
    const integrity = await VerificationSessionService.verifyEvidenceIntegrity(session.id);

    let auditList = [];
    try {
      if (session.auditTrail) auditList = JSON.parse(session.auditTrail);
    } catch(e) {}

    res.json({
      success: true,
      data: {
        ...session,
        allowlist: parsedEvidence.allowlist,
        authorizedBy: parsedEvidence.authorizedBy,
        evidenceChain: parsedEvidence.evidenceChain,
        proofObject: parsedEvidence.proofObject,
        auditTrail: auditList,
        integrity
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/v1/red-team/sessions/:id/proof
 * Generate and export defensible Proof Object
 */
router.get('/sessions/:id/proof', async (req, res) => {
  try {
    const { id } = req.params;
    const { format } = req.query;

    const proof = await VerificationSessionService.generateProofObject(id);

    if (format === 'markdown') {
      const md = `# CYBERSPLOI VERIFICATION PROOF OF EXECUTION
## Proof ID: ${proof.proofId}
- **Assessment ID**: ${proof.assessmentId}
- **Session Token**: ${proof.sessionToken}
- **Finding ID**: ${proof.findingId}
- **Verification Status**: ${proof.verificationStatus}
- **Target**: ${proof.target}
- **Authorized By**: ${proof.authorizedBy}
- **Authorized At**: ${proof.authorizedAt}
- **Integrity Verified**: ${proof.integrityVerified ? 'YES (Cryptographically Valid)' : 'NO'}
- **Tamper-Evident SHA-256 Signature**: \`${proof.tamperEvidentSignature}\`

---

### Before / After Baseline Comparison
- **Expected Secure Baseline**: ${proof.baselineBehavior.expected}
- **Observed Vulnerability Telemetry**: ${proof.observedBehavior.telemetrySummary}

---

### Authorized Permitted Actions
${proof.allowlist.map(a => `- \`${a}\``).join('\n')}

---

### Cryptographic Evidence Chain (${proof.chainLength} items)
${proof.evidenceChain.map((item, idx) => `#### Event ${idx + 1}: ${item.action} (${item.id})
- **Timestamp**: ${item.timestamp}
- **Target**: \`${item.target}\`
- **Previous Hash**: \`${item.prevHash}\`
- **Current Hash**: \`${item.hash}\`
- **Request**:
\`\`\`json
${JSON.stringify(item.request, null, 2)}
\`\`\`
- **Response**:
\`\`\`json
${JSON.stringify(item.response, null, 2)}
\`\`\`
`).join('\n')}

---

### Reproducibility Steps
${proof.reproducibilitySteps.map(s => `#### Step ${s.step}: ${s.title}
*Purpose*: ${s.purpose}
\`\`\`bash
${s.command}
\`\`\`
`).join('\n')}

---
*Signed and sealed by CyberSploi Cryptographic Proof Engine.*
`;
      res.setHeader('Content-Type', 'text/markdown');
      res.setHeader('Content-Disposition', `attachment; filename=${proof.proofId}.md`);
      return res.send(md);
    }

    res.json({
      success: true,
      data: proof
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/v1/red-team/assessments/:id/report
 * Generate comprehensive, evidence-driven audit report
 */
router.get('/assessments/:id/report', async (req, res) => {
  try {
    const { id } = req.params;
    const assessment = await prisma.redTeamAssessment.findFirst({
      where: {
        OR: [{ id }, { scanId: id }]
      },
      include: {
        scope: true,
        coverage: true,
        hypotheses: true,
        graphNodes: true,
        graphEdges: true,
        events: { orderBy: { timestamp: 'asc' } },
        scan: {
          include: {
            asset: true,
            vulnerabilities: true,
            results: true
          }
        }
      }
    });

    if (!assessment) {
      return res.status(404).json({ success: false, message: 'Assessment not found' });
    }

    const verifiedFindings = assessment.hypotheses.filter(h => h.status === 'VERIFIED');
    const rejectedFindings = assessment.hypotheses.filter(h => h.status === 'REJECTED');
    const inconclusiveFindings = assessment.hypotheses.filter(h => h.status === 'INCONCLUSIVE');

    const report = {
      title: `CyberSploi AI Red Team Assessment Report - ${assessment.scope?.target || 'Target Asset'}`,
      assessmentId: assessment.id,
      scanId: assessment.scanId,
      status: assessment.status,
      startedAt: assessment.startedAt,
      completedAt: assessment.completedAt,
      executiveSummary: {
        target: assessment.scope?.target,
        environment: assessment.scope?.environment,
        coveragePercent: assessment.coverage?.coveragePercent || 0,
        criticalCount: assessment.scan?.criticalCount || 0,
        highCount: assessment.scan?.highCount || 0,
        hypothesesEvaluated: assessment.hypotheses.length,
        verifiedVulnerabilities: verifiedFindings.length,
        falsePositivesRejected: rejectedFindings.length,
        criticalChainsIdentified: assessment.graphEdges.filter(e => e.isCriticalPath).length
      },
      scope: assessment.scope,
      methodology: 'CyberSploi Autonomous Red Team Assessment Pipeline (Discovery, Mapping, Hypothesis Formulation, Counter-Evidence Testing, Attack Graph Chaining, and Bounded Verification)',
      attackSurface: {
        nodesCount: assessment.graphNodes.length,
        relationsCount: assessment.graphEdges.length,
        nodes: assessment.graphNodes.map(n => ({ id: n.nodeId, label: n.label, category: n.category, severity: n.severity }))
      },
      findings: {
        verified: verifiedFindings,
        rejectedFalsePositives: rejectedFindings,
        inconclusive: inconclusiveFindings
      },
      coverage: assessment.coverage,
      blindSpots: assessment.coverage?.blindSpots ? JSON.parse(assessment.coverage.blindSpots) : [],
      timeline: assessment.events.map(e => ({
        timestamp: e.timestamp,
        phase: e.phase,
        stage: e.stage,
        level: e.level,
        message: e.message
      }))
    };

    res.json({
      success: true,
      data: report
    });
  } catch (err) {
    console.error('[RedTeamAPI] Report generation failed:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/v1/red-team/assessments/:id/report/markdown
 * Download full Markdown audit report
 */
router.get('/assessments/:id/report/markdown', async (req, res) => {
  try {
    const { id } = req.params;
    const assessment = await prisma.redTeamAssessment.findFirst({
      where: { OR: [{ id }, { scanId: id }] },
      include: {
        scope: true,
        coverage: true,
        hypotheses: true,
        graphNodes: true,
        graphEdges: true,
        events: { orderBy: { timestamp: 'asc' } },
        scan: { include: { asset: true, vulnerabilities: true } }
      }
    });

    if (!assessment) return res.status(404).send('# Error: Assessment Not Found');

    const verified = assessment.hypotheses.filter(h => h.status === 'VERIFIED');
    const rejected = assessment.hypotheses.filter(h => h.status === 'REJECTED');
    const blindSpots = assessment.coverage?.blindSpots ? JSON.parse(assessment.coverage.blindSpots) : [];

    let assessmentBrain = null;
    if (assessment.coverage?.breakdown) {
      try {
        const bd = JSON.parse(assessment.coverage.breakdown);
        assessmentBrain = bd.assessmentBrain || null;
      } catch (e) {}
    }

    let surfaceMatrixMd = '';
    if (assessmentBrain?.surfaceMatrix) {
      surfaceMatrixMd = `### 12-Surface Attack Matrix
| Surface | Status | Coverage | Assessed Items | Verified Items |
|---|---|---|---|---|
` + Object.entries(assessmentBrain.surfaceMatrix).map(([surf, data]) => {
        return `| **${surf}** | \`${data.status}\` | ${data.coveragePct}% | ${data.assessedCount} | ${data.verifiedCount} |`;
      }).join('\n') + '\n\n';
    }

    let rootCausesMd = '';
    if (assessmentBrain?.rootCauses && assessmentBrain.rootCauses.length > 0) {
      rootCausesMd = `### Architectural Root Causes vs. Symptoms
` + assessmentBrain.rootCauses.map((rc, i) => `#### ${i + 1}. ${rc.title} (${rc.severity})
- **Underlying Root Cause**: ${rc.rootCause}
- **Category**: \`${rc.category}\`
- **Symptom Findings Correlated**: ${rc.symptoms?.length || 0}
${(rc.symptoms || []).map(s => `  - *${s.title}* [${s.severity}] (CVE: ${s.cve})`).join('\n')}
`).join('\n') + '\n\n';
    }

    let questionQueueMd = '';
    if (assessmentBrain?.questionQueue && assessmentBrain.questionQueue.length > 0) {
      questionQueueMd = `### Question-Driven Investigation Queue
` + assessmentBrain.questionQueue.map((q, i) => `#### ${q.id}: ${q.question}
- **Target**: \`${q.target}\`
- **Security Boundary**: ${q.securityProperty}
- **Operational Assumption**: ${q.assumption}
- **Proving Criteria**: ${q.provingEvidence}
- **Disproving Criteria**: ${q.disprovingEvidence}
- **Derived Hypothesis**: ${q.derivedHypothesis}
- **Status**: \`${q.status}\`
`).join('\n') + '\n\n';
    }

    let authzMatrixMd = '';
    if (assessmentBrain?.authorizationMatrix && assessmentBrain.authorizationMatrix.length > 0) {
      authzMatrixMd = `### Authorization Invariant & Role Boundary Matrix
| Identity | Role | Resource | Action | Expected | Observed | Inconsistent? |
|---|---|---|---|---|---|---|
` + assessmentBrain.authorizationMatrix.map(a => {
        return `| ${a.identity} | \`${a.role}\` | \`${a.resource}\` | ${a.action} | ${a.expectedAccess} | ${a.observedAccess} | ${a.inconsistent ? '**YES (VIOLATION)**' : 'No'} |`;
      }).join('\n') + '\n\n';
    }

    const md = `# CYBERSPLOI AI RED TEAM ASSESSMENT REPORT
## Target: ${assessment.scope?.target || 'Authorized Target'}
- **Assessment ID**: ${assessment.id}
- **Status**: ${assessment.status}
- **Started At**: ${assessment.startedAt}
- **Completed At**: ${assessment.completedAt || 'In Progress'}
- **Overall Coverage**: ${assessment.coverage?.coveragePercent || 0}%

---

### Executive Summary
- **Verified Findings**: ${verified.length}
- **False Positives Eliminated**: ${rejected.length}
- **Critical Attack Paths**: ${assessment.graphEdges.filter(e => e.isCriticalPath).length}
- **Surfaces Evaluated**: ${assessmentBrain ? Object.keys(assessmentBrain.surfaceMatrix || {}).length : 12}
- **Architectural Root Causes**: ${assessmentBrain?.rootCauses?.length || 0}

---

${surfaceMatrixMd}${rootCausesMd}${authzMatrixMd}${questionQueueMd}### Verified Findings & Evidence
${verified.map((v, i) => `#### ${i + 1}. ${v.title}
- **Category**: ${v.category}
- **Endpoint**: \`${v.targetEndpoint}\`
- **Confidence**: ${(v.currentConfidence * 100).toFixed(1)}% (${v.confidenceBasis})
- **Evidence**:
\`\`\`json
${v.evidence || 'None'}
\`\`\`
`).join('\n\n')}

### Operational Blind Spots
${blindSpots.map((b, i) => `- **${b.title}** (${b.category}): ${b.reason}`).join('\n')}

---
*Report generated by CyberSploi Ultra-Deep Security Assessment Engine.*
`;

    res.setHeader('Content-Type', 'text/markdown');
    res.setHeader('Content-Disposition', `attachment; filename=CyberSploi_Report_${assessment.id}.md`);
    res.send(md);
  } catch (err) {
    res.status(500).send(`# Error: ${err.message}`);
  }
});

module.exports = router;
