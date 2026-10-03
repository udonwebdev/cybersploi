import * as crypto from 'crypto';
import prisma from '../../config/database';

export type FindingStatus =
  | 'SUSPECTED'
  | 'TESTED'
  | 'VALIDATED'
  | 'PROVEN'
  | 'DISPROVEN'
  | 'INCONCLUSIVE';

export interface CreateFindingRequest {
  engagementId: string;
  title: string;
  description: string;
  category: string;
  severity: string;
  target: string;
  hypothesisId?: string;
}

export interface CreateEvidenceRequest {
  findingId?: string;
  actionId: string;
  target: string;
  observation: string;
  requestMetadata?: any;
  responseMetadata?: any;
  responseBodyData?: any;
  reproductionSteps?: string;
  authContext?: any;
  workerResult?: any;
  previousEvidenceId?: string; // For corrections / amendments
}

export class FindingEvidenceService {
  /**
   * Computes deterministic SHA-256 hash for immutable evidence record.
   */
  public static calculateEvidenceHash(data: {
    actionId: string;
    target: string;
    observation: string;
    timestamp: string;
    requestMetadata?: string;
    responseMetadata?: string;
    responseBodyData?: string;
    authContext?: string;
    previousEvidenceId?: string | null;
  }): string {
    const raw = `${data.actionId}|${data.target}|${data.observation}|${data.timestamp}|${data.requestMetadata || ''}|${data.responseMetadata || ''}|${data.responseBodyData || ''}|${data.authContext || ''}|${data.previousEvidenceId || 'root'}`;
    return crypto.createHash('sha256').update(raw).digest('hex');
  }

  /**
   * Alias for createEvidence for compatibility across engine agents
   */
  public static async attachEvidence(req: CreateEvidenceRequest) {
    return this.createEvidence(req);
  }

  /**
   * Creates an immutable evidence entry.
   * If previousEvidenceId is provided, chains this record to the previous one (correction pattern).
   */
  public static async createEvidence(req: CreateEvidenceRequest) {
    const now = new Date();
    const requestMetadataStr = req.requestMetadata ? JSON.stringify(req.requestMetadata) : null;
    const responseMetadataStr = req.responseMetadata ? JSON.stringify(req.responseMetadata) : null;
    const responseBodyStr = req.responseBodyData ? JSON.stringify(req.responseBodyData) : null;
    const authContextStr = req.authContext ? JSON.stringify(req.authContext) : null;
    const workerResultStr = req.workerResult ? JSON.stringify(req.workerResult) : null;

    // Verify parent evidence exists if correction
    if (req.previousEvidenceId) {
      const parent = await prisma.engineEvidence.findUnique({
        where: { id: req.previousEvidenceId }
      });
      if (!parent) {
        throw new Error(`PREVIOUS_EVIDENCE_NOT_FOUND: Parent evidence ${req.previousEvidenceId} does not exist`);
      }
    }

    const hash = this.calculateEvidenceHash({
      actionId: req.actionId,
      target: req.target,
      observation: req.observation,
      timestamp: now.toISOString(),
      requestMetadata: requestMetadataStr || undefined,
      responseMetadata: responseMetadataStr || undefined,
      responseBodyData: responseBodyStr || undefined,
      authContext: authContextStr || undefined,
      previousEvidenceId: req.previousEvidenceId
    });

    const evidence = await prisma.engineEvidence.create({
      data: {
        findingId: req.findingId || null,
        actionId: req.actionId,
        target: req.target,
        timestamp: now,
        observation: req.observation,
        requestMetadata: requestMetadataStr,
        responseMetadata: responseMetadataStr,
        responseBodyData: responseBodyStr,
        reproductionSteps: req.reproductionSteps || null,
        authContext: authContextStr,
        workerResult: workerResultStr,
        hash,
        isImmutable: true,
        previousEvidenceId: req.previousEvidenceId || null
      }
    });

    return evidence;
  }

  /**
   * Strict Immutability Guard: Rejects any attempt to mutate an existing evidence record.
   */
  public static async updateEvidence(evidenceId: string, _mutationData: any): Promise<never> {
    throw new Error(`IMMUTABLE_EVIDENCE_VIOLATION: Evidence records are strictly immutable (Record ID: ${evidenceId}). Direct updates are prohibited. Use createEvidence() with previousEvidenceId to create a linked correction.`);
  }

  /**
   * Creates a new Finding in the default SUSPECTED state.
   */
  public static async createFinding(req: CreateFindingRequest) {
    return prisma.engineFinding.create({
      data: {
        engagementId: req.engagementId,
        title: req.title,
        description: req.description,
        category: req.category.toUpperCase(),
        severity: req.severity.toUpperCase(),
        target: req.target,
        status: 'SUSPECTED',
        reproducible: false,
        hypothesisId: req.hypothesisId || null
      }
    });
  }

  /**
   * Authoritative Finding state transition enforcer.
   * SUSPECTED -> TESTED -> VALIDATED -> PROVEN
   * Terminal: DISPROVEN, INCONCLUSIVE
   */
  public static async transitionFinding(
    findingId: string,
    targetStatus: FindingStatus,
    options?: { reproductionSteps?: string; reason?: string }
  ) {
    const finding = await prisma.engineFinding.findUnique({
      where: { id: findingId },
      include: { evidence: true }
    });

    if (!finding) {
      throw new Error(`Finding with ID ${findingId} does not exist`);
    }

    const currentStatus = finding.status as FindingStatus;

    // Validate state graph
    const validTransitions: Record<FindingStatus, FindingStatus[]> = {
      SUSPECTED: ['TESTED', 'DISPROVEN', 'INCONCLUSIVE'],
      TESTED: ['VALIDATED', 'DISPROVEN', 'INCONCLUSIVE', 'SUSPECTED'],
      VALIDATED: ['PROVEN', 'DISPROVEN', 'INCONCLUSIVE', 'TESTED'],
      PROVEN: ['DISPROVEN', 'INCONCLUSIVE', 'VALIDATED'],
      DISPROVEN: ['SUSPECTED', 'TESTED'],
      INCONCLUSIVE: ['SUSPECTED', 'TESTED']
    };

    if (!validTransitions[currentStatus].includes(targetStatus)) {
      throw new Error(`ILLEGAL_FINDING_TRANSITION: Cannot transition finding from '${currentStatus}' to '${targetStatus}'. Allowed: [${validTransitions[currentStatus].join(', ')}]`);
    }

    // INVARIANT 1: A Finding cannot become VALIDATED without Evidence.
    if (targetStatus === 'VALIDATED') {
      if (!finding.evidence || finding.evidence.length === 0) {
        throw new Error(`EVIDENCE_REQUIRED: Cannot transition finding to 'VALIDATED' without at least one immutable evidence record.`);
      }
    }

    // INVARIANT 2: A Finding cannot become PROVEN without reproducible Evidence.
    if (targetStatus === 'PROVEN') {
      if (!finding.evidence || finding.evidence.length === 0) {
        throw new Error(`EVIDENCE_REQUIRED: Cannot transition finding to 'PROVEN' without evidence.`);
      }
      const hasReproducibleEvidence = finding.evidence.some(e =>
        e.reproductionSteps && e.reproductionSteps.trim().length > 0
      );
      if (!hasReproducibleEvidence && (!options?.reproductionSteps || options.reproductionSteps.trim().length === 0)) {
        throw new Error(`REPRODUCIBLE_EVIDENCE_REQUIRED: Cannot transition finding to 'PROVEN' without verifiable, reproducible evidence steps.`);
      }
    }

    const updated = await prisma.engineFinding.update({
      where: { id: findingId },
      data: {
        status: targetStatus,
        reproducible: targetStatus === 'PROVEN' ? true : finding.reproducible
      },
      include: { evidence: true }
    });

    return updated;
  }

  /**
   * Retrieves full evidence chain for a finding.
   */
  public static async getEvidenceChain(findingId: string) {
    return prisma.engineEvidence.findMany({
      where: { findingId },
      orderBy: { timestamp: 'asc' },
      include: {
        previousEvidence: true
      }
    });
  }
}
