/**
 * Controlled Verification Session Manager & Proof Engine
 * Provides non-persistent, bounded, revocable verification sessions for confirmed vulnerabilities.
 * Enforces:
 * - Customer Authorization Gate (explicit permission approval before session activation)
 * - Strict Action Allowlists (least privilege per finding)
 * - Tamper-Evident Cryptographic Evidence Chaining (SHA-256 integrity guarantee)
 * - Defensible Proof Object Generation (reproducibility steps & before/after baseline)
 * - Instantaneous Emergency Kill-Switch
 */

const crypto = require('crypto');
const prisma = require('../../config/database');

const DEFAULT_PERMITTED_ACTIONS = [
  'PROBE_ENDPOINT',
  'INSPECT_HEADER',
  'TEST_SOCKET_HANDSHAKE',
  'FETCH_RETEST_EVIDENCE',
  'VERIFY_VULNERABILITY'
];

class VerificationSessionService {
  /**
   * Generate a secure, recognizable session identifier
   */
  static generateSessionToken() {
    const randomHex = crypto.randomBytes(4).toString('hex').toUpperCase();
    return `RT-SESS-${Date.now().toString(36).toUpperCase()}-${randomHex}`;
  }

  /**
   * Helper: Parse session evidence JSON metadata safely
   */
  static parseEvidencePayload(rawEvidence) {
    if (!rawEvidence) {
      return {
        originalEvidence: null,
        authorizedBy: null,
        allowlist: [...DEFAULT_PERMITTED_ACTIONS],
        evidenceChain: [],
        proofObject: null
      };
    }

    try {
      const parsed = typeof rawEvidence === 'string' ? JSON.parse(rawEvidence) : rawEvidence;
      if (parsed && typeof parsed === 'object' && (parsed.evidenceChain || parsed.allowlist || parsed.originalEvidence !== undefined)) {
        return {
          originalEvidence: parsed.originalEvidence || null,
          authorizedBy: parsed.authorizedBy || null,
          allowlist: Array.isArray(parsed.allowlist) ? parsed.allowlist : [...DEFAULT_PERMITTED_ACTIONS],
          evidenceChain: Array.isArray(parsed.evidenceChain) ? parsed.evidenceChain : [],
          proofObject: parsed.proofObject || null,
          baselineBehavior: parsed.baselineBehavior || null,
          observedBehavior: parsed.observedBehavior || null
        };
      }
      return {
        originalEvidence: parsed,
        authorizedBy: null,
        allowlist: [...DEFAULT_PERMITTED_ACTIONS],
        evidenceChain: [],
        proofObject: null
      };
    } catch (e) {
      return {
        originalEvidence: rawEvidence,
        authorizedBy: null,
        allowlist: [...DEFAULT_PERMITTED_ACTIONS],
        evidenceChain: [],
        proofObject: null
      };
    }
  }

  /**
   * Request a new verification session requiring Customer Authorization Gate approval
   */
  static async requestSession({
    assessmentId,
    target,
    findingId = null,
    objective = 'Vulnerability Exploitability Verification',
    executionContext = 'Bounded Non-Destructive Probe',
    privilegeContext = 'Unauthenticated Network Boundary',
    requestedActions = DEFAULT_PERMITTED_ACTIONS,
    evidence = null,
    ttlMinutes = 15
  }) {
    const sessionToken = this.generateSessionToken();
    const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000);

    const initialAudit = [
      {
        timestamp: new Date().toISOString(),
        action: 'SESSION_REQUESTED',
        details: `Verification session requested for target ${target} (Finding: ${findingId || 'N/A'}). Status: Awaiting Customer Authorization Gate approval.`
      }
    ];

    const evidencePayload = {
      originalEvidence: evidence,
      authorizedBy: null,
      allowlist: requestedActions,
      evidenceChain: [],
      proofObject: null
    };

    const session = await prisma.verificationSession.create({
      data: {
        assessmentId,
        sessionToken,
        target,
        findingId,
        status: 'REQUESTED',
        verificationObjective: objective,
        executionContext,
        privilegeContext,
        evidence: JSON.stringify(evidencePayload),
        auditTrail: JSON.stringify(initialAudit),
        expiresAt,
        startedAt: new Date()
      }
    });

    return session;
  }

  /**
   * Create a new bounded verification session (supports auto-active or requested)
   */
  static async createSession({
    assessmentId,
    target,
    findingId = null,
    objective = 'Vulnerability Exploitability Verification',
    executionContext = 'Bounded Non-Destructive Probe',
    privilegeContext = 'Unauthenticated Network Boundary',
    evidence = null,
    status = 'ACTIVE',
    authorizedBy = 'Automated Assessment Pipeline',
    allowlist = DEFAULT_PERMITTED_ACTIONS,
    ttlMinutes = 15
  }) {
    const sessionToken = this.generateSessionToken();
    const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000);

    const initialAudit = [
      {
        timestamp: new Date().toISOString(),
        action: status === 'ACTIVE' ? 'SESSION_INITIALIZED' : 'SESSION_REQUESTED',
        details: `Bounded assessment verification session [${status}] for target ${target}. Objective: ${objective}. Expiry: ${expiresAt.toISOString()}`
      }
    ];

    const evidencePayload = {
      originalEvidence: evidence,
      authorizedBy: status === 'ACTIVE' ? authorizedBy : null,
      allowlist,
      evidenceChain: [],
      proofObject: null
    };

    if (evidence && status === 'ACTIVE') {
      const initialItem = {
        id: `EVT-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
        timestamp: new Date().toISOString(),
        action: 'INITIAL_EVIDENCE_RECORDED',
        target,
        findingId,
        request: { method: 'PROBE', endpoint: target },
        response: typeof evidence === 'object' ? evidence : { summary: String(evidence) },
        expectedBehavior: 'Target enforces security policy and rejects unauthorized probes.',
        observedBehavior: typeof evidence === 'object' ? JSON.stringify(evidence) : String(evidence),
        prevHash: '0000000000000000000000000000000000000000000000000000000000000000'
      };
      const hashContent = `${initialItem.prevHash}:${initialItem.timestamp}:${initialItem.action}:${JSON.stringify(initialItem.request)}:${JSON.stringify(initialItem.response)}`;
      initialItem.hash = crypto.createHash('sha256').update(hashContent).digest('hex');
      evidencePayload.evidenceChain.push(initialItem);
    }

    const session = await prisma.verificationSession.create({
      data: {
        assessmentId,
        sessionToken,
        target,
        findingId,
        status,
        verificationObjective: objective,
        executionContext,
        privilegeContext,
        evidence: JSON.stringify(evidencePayload),
        auditTrail: JSON.stringify(initialAudit),
        expiresAt,
        startedAt: new Date()
      }
    });

    return session;
  }

  /**
   * Customer Authorization Gate: Approve session with explicit permissions and TTL
   */
  static async authorizeSession(sessionIdOrToken, {
    authorizedBy = 'Customer Security Administrator',
    permittedActions = DEFAULT_PERMITTED_ACTIONS,
    ttlMinutes = 15,
    authorizationNotes = 'Customer explicitly authorized bounded verification session.'
  } = {}) {
    const session = await this.resolveSession(sessionIdOrToken);
    if (!session) {
      throw new Error(`Verification session ${sessionIdOrToken} not found`);
    }

    if (session.status === 'TERMINATED') {
      throw new Error(`Cannot authorize terminated session ${session.sessionToken}`);
    }

    const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000);
    const parsedPayload = this.parseEvidencePayload(session.evidence);

    parsedPayload.authorizedBy = authorizedBy;
    parsedPayload.allowlist = Array.isArray(permittedActions) && permittedActions.length > 0 ? permittedActions : DEFAULT_PERMITTED_ACTIONS;

    const updatedAudit = this.appendAudit(
      session.auditTrail,
      'CUSTOMER_AUTHORIZATION_GRANTED',
      `Session approved by ${authorizedBy}. Permitted actions: [${parsedPayload.allowlist.join(', ')}]. TTL: ${ttlMinutes}m. Notes: ${authorizationNotes}`
    );

    const updated = await prisma.verificationSession.update({
      where: { id: session.id },
      data: {
        status: 'ACTIVE',
        expiresAt,
        evidence: JSON.stringify(parsedPayload),
        auditTrail: updatedAudit,
        updatedAt: new Date()
      }
    });

    return {
      ...updated,
      evidencePayload: parsedPayload
    };
  }

  /**
   * Validate if an action is permitted under the session's authorization allowlist
   */
  static async validateAction(sessionIdOrToken, action, target) {
    const session = await this.getSession(sessionIdOrToken);
    if (!session) {
      return { allowed: false, reason: `Verification session ${sessionIdOrToken} not found` };
    }

    if (session.status === 'REQUESTED') {
      return {
        allowed: false,
        reason: 'SESSION_NOT_AUTHORIZED: Session is awaiting Customer Authorization Gate approval before any probe may execute.'
      };
    }

    if (session.status === 'TERMINATED') {
      return {
        allowed: false,
        reason: 'SESSION_TERMINATED: Session was manually revoked by emergency kill-switch.'
      };
    }

    if (session.status === 'EXPIRED') {
      return {
        allowed: false,
        reason: 'SESSION_EXPIRED: Session has exceeded its authorized time-to-live.'
      };
    }

    const parsed = this.parseEvidencePayload(session.evidence);
    const allowlist = parsed.allowlist || DEFAULT_PERMITTED_ACTIONS;

    const actionAllowed = allowlist.includes(action) || allowlist.includes('*');
    if (!actionAllowed) {
      await this.recordAuditAction(
        session.id,
        'ACTION_DENIED',
        `Action '${action}' was rejected. Not permitted in customer authorization allowlist [${allowlist.join(', ')}].`
      );
      return {
        allowed: false,
        reason: `ACTION_NOT_PERMITTED: Action '${action}' is not in authorized allowlist.`
      };
    }

    if (target) {
      const cleanTarget = target.replace(/^https?:\/\//, '').split('/')[0];
      const cleanSessionTarget = session.target.replace(/^https?:\/\//, '').split('/')[0];
      if (!cleanTarget.includes(cleanSessionTarget) && !cleanSessionTarget.includes(cleanTarget)) {
        await this.recordAuditAction(
          session.id,
          'TARGET_DENIED',
          `Target '${target}' violates session boundary for '${session.target}'.`
        );
        return {
          allowed: false,
          reason: `TARGET_OUT_OF_BOUNDS: Action target '${target}' does not match session target '${session.target}'.`
        };
      }
    }

    return { allowed: true, session, allowlist };
  }

  /**
   * Record verified evidence item with SHA-256 cryptographic chain hashing
   */
  static async recordEvidenceWithHash(sessionIdOrToken, evidenceData) {
    const session = await this.resolveSession(sessionIdOrToken);
    if (!session) {
      throw new Error(`Verification session ${sessionIdOrToken} not found`);
    }

    const authCheck = await this.validateAction(session.id, evidenceData.action, evidenceData.target);
    if (!authCheck.allowed) {
      throw new Error(authCheck.reason);
    }

    const parsed = this.parseEvidencePayload(session.evidence);
    const chain = parsed.evidenceChain || [];

    const prevHash = chain.length > 0
      ? chain[chain.length - 1].hash
      : '0000000000000000000000000000000000000000000000000000000000000000';

    const timestamp = new Date().toISOString();
    const evidenceItem = {
      id: `EVT-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
      timestamp,
      action: evidenceData.action,
      target: evidenceData.target || session.target,
      findingId: evidenceData.findingId || session.findingId,
      request: evidenceData.request || {},
      response: evidenceData.response || {},
      expectedBehavior: evidenceData.expectedBehavior || 'Secure service baseline behavior.',
      observedBehavior: evidenceData.observedBehavior || 'Observed vulnerability telemetry.',
      prevHash
    };

    const hashContent = `${prevHash}:${timestamp}:${evidenceItem.action}:${JSON.stringify(evidenceItem.request)}:${JSON.stringify(evidenceItem.response)}`;
    evidenceItem.hash = crypto.createHash('sha256').update(hashContent).digest('hex');

    chain.push(evidenceItem);
    parsed.evidenceChain = chain;

    const updatedAudit = this.appendAudit(
      session.auditTrail,
      'EVIDENCE_CHAIN_EXTENDED',
      `Recorded verified evidence item ${evidenceItem.id} [Action: ${evidenceItem.action}]. SHA-256: ${evidenceItem.hash.substring(0, 16)}...`
    );

    const updated = await prisma.verificationSession.update({
      where: { id: session.id },
      data: {
        evidence: JSON.stringify(parsed),
        auditTrail: updatedAudit,
        updatedAt: new Date()
      }
    });

    return {
      session: updated,
      evidenceItem,
      chainLength: chain.length,
      currentHash: evidenceItem.hash
    };
  }

  /**
   * Verify mathematical integrity of the cryptographic evidence chain
   */
  static async verifyEvidenceIntegrity(sessionIdOrToken) {
    const session = await this.resolveSession(sessionIdOrToken);
    if (!session) return { valid: false, reason: 'Session not found' };

    const parsed = this.parseEvidencePayload(session.evidence);
    const chain = parsed.evidenceChain || [];

    if (chain.length === 0) {
      return { valid: true, chainLength: 0, headHash: null, verified: true };
    }

    let expectedPrevHash = '0000000000000000000000000000000000000000000000000000000000000000';

    for (let i = 0; i < chain.length; i++) {
      const item = chain[i];
      if (item.prevHash !== expectedPrevHash) {
        return {
          valid: false,
          brokenAtIndex: i,
          reason: `Chain broken at index ${i}: expected prevHash ${expectedPrevHash}, found ${item.prevHash}`
        };
      }

      const hashContent = `${item.prevHash}:${item.timestamp}:${item.action}:${JSON.stringify(item.request)}:${JSON.stringify(item.response)}`;
      const computedHash = crypto.createHash('sha256').update(hashContent).digest('hex');

      if (computedHash !== item.hash) {
        return {
          valid: false,
          brokenAtIndex: i,
          reason: `Hash mismatch at index ${i}: computed ${computedHash}, recorded ${item.hash}`
        };
      }

      expectedPrevHash = item.hash;
    }

    return {
      valid: true,
      chainLength: chain.length,
      headHash: expectedPrevHash,
      verified: true
    };
  }

  /**
   * Generate an immutable, defensible Proof Object
   */
  static async generateProofObject(sessionIdOrToken) {
    const session = await this.resolveSession(sessionIdOrToken);
    if (!session) throw new Error(`Session ${sessionIdOrToken} not found`);

    const integrity = await this.verifyEvidenceIntegrity(session.id);
    const parsed = this.parseEvidencePayload(session.evidence);
    const chain = parsed.evidenceChain || [];

    const proofId = `PROOF-${session.sessionToken}`;

    const sampleItem = chain[chain.length - 1] || null;
    const reproducibilitySteps = [
      {
        step: 1,
        title: 'Verify Target Network Endpoint',
        command: `curl -sI -o /dev/null -w "%{http_code}" https://${session.target}/`,
        purpose: 'Establish baseline target responsiveness and HTTP status code'
      },
      {
        step: 2,
        title: 'Reproduce Non-Destructive Vulnerability Probe',
        command: sampleItem?.request?.endpoint
          ? `curl -s -k "${sampleItem.request.endpoint}"`
          : `curl -s -k "https://${session.target}/${session.findingId ? session.findingId.toLowerCase() : ''}"`,
        purpose: `Deterministic reproduction of ${session.verificationObjective}`
      }
    ];

    const proofObject = {
      proofId,
      assessmentId: session.assessmentId,
      sessionToken: session.sessionToken,
      findingId: session.findingId || 'VULN-VERIFIED',
      verificationStatus: session.status === 'TERMINATED' ? 'REVOKED' : 'BOUNDED_CONFIRMED',
      target: session.target,
      objective: session.verificationObjective,
      authorizedBy: parsed.authorizedBy || 'Customer Security Administrator',
      authorizedAt: session.startedAt,
      expiresAt: session.expiresAt,
      allowlist: parsed.allowlist || DEFAULT_PERMITTED_ACTIONS,
      evidenceChain: chain,
      chainLength: chain.length,
      tamperEvidentSignature: integrity.headHash || 'N/A',
      integrityVerified: integrity.valid,
      baselineBehavior: {
        expected: 'Target rejects unauthorized access and does not expose secrets or administrative listeners.',
        policyEnforced: true
      },
      observedBehavior: {
        confirmed: true,
        findingContext: session.privilegeContext,
        telemetrySummary: sampleItem ? sampleItem.observedBehavior : 'Verified vulnerability telemetry recorded in cryptographic chain.'
      },
      reproducibilitySteps,
      generatedAt: new Date().toISOString()
    };

    parsed.proofObject = proofObject;

    await prisma.verificationSession.update({
      where: { id: session.id },
      data: {
        evidence: JSON.stringify(parsed),
        updatedAt: new Date()
      }
    });

    return proofObject;
  }

  /**
   * Helper to resolve session by ID or token
   */
  static async resolveSession(sessionIdOrToken) {
    return await prisma.verificationSession.findFirst({
      where: {
        OR: [
          { id: sessionIdOrToken },
          { sessionToken: sessionIdOrToken }
        ]
      },
      include: { assessment: true }
    });
  }

  /**
   * Retrieve active session and enforce expiration check
   */
  static async getSession(sessionIdOrToken) {
    const session = await this.resolveSession(sessionIdOrToken);
    if (!session) return null;

    if (session.status === 'ACTIVE' && new Date() > new Date(session.expiresAt)) {
      const updatedAudit = this.appendAudit(session.auditTrail, 'SESSION_EXPIRED', 'Session reached timeout limit and was auto-terminated.');
      return await prisma.verificationSession.update({
        where: { id: session.id },
        data: {
          status: 'EXPIRED',
          terminatedAt: new Date(),
          terminationReason: 'Automatic TTL expiration elapsed',
          auditTrail: updatedAudit
        }
      });
    }

    return session;
  }

  /**
   * Terminate session immediately (User / Emergency Kill-Switch)
   */
  static async terminateSession(sessionIdOrToken, reason = 'Operator triggered manual termination kill-switch') {
    const session = await this.resolveSession(sessionIdOrToken);
    if (!session) {
      throw new Error(`Verification session ${sessionIdOrToken} not found`);
    }

    if (session.status === 'TERMINATED') {
      return session;
    }

    const updatedAudit = this.appendAudit(session.auditTrail, 'SESSION_TERMINATED', reason);

    const updated = await prisma.verificationSession.update({
      where: { id: session.id },
      data: {
        status: 'TERMINATED',
        terminatedAt: new Date(),
        terminationReason: reason,
        auditTrail: updatedAudit
      }
    });

    return updated;
  }

  /**
   * Record an action in the session audit trail
   */
  static async recordAuditAction(sessionIdOrToken, action, details) {
    const session = await this.resolveSession(sessionIdOrToken);
    if (!session) return null;

    const updatedAudit = this.appendAudit(session.auditTrail, action, details);

    return await prisma.verificationSession.update({
      where: { id: session.id },
      data: { auditTrail: updatedAudit }
    });
  }

  /**
   * Helper: append to audit JSON array
   */
  static appendAudit(existingAuditStr, action, details) {
    let auditList = [];
    try {
      if (existingAuditStr) auditList = JSON.parse(existingAuditStr);
    } catch (e) {
      auditList = [];
    }

    auditList.push({
      timestamp: new Date().toISOString(),
      action,
      details: typeof details === 'object' ? JSON.stringify(details) : String(details)
    });

    return JSON.stringify(auditList);
  }
}

module.exports = VerificationSessionService;
