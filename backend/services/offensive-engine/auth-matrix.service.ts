import prisma from '../../config/database';
import { FindingEvidenceService } from './finding-evidence.service';

export interface AuthContext {
  role: string;
  subjectIdentity: string;
  objectIdentity: string;
  tenantId?: string;
  token?: string;
  headers?: Record<string, string>;
}

export interface AuthMatrixEvaluationItem {
  engagementId: string;
  assetId?: string;
  operation: string;
  authContext: AuthContext;
  declaredExpected?: 'ALLOWED' | 'DENIED' | 'UNKNOWN';
  observed: 'ALLOWED' | 'DENIED' | 'ERROR';
  evidenceData?: any;
}

export interface AuthMatrixRecordOutput {
  id: string;
  operation: string;
  role: string;
  subjectIdentity: string;
  objectIdentity: string;
  expected: string;
  observed: string;
  result: 'MATCH' | 'DISCREPANCY' | 'UNKNOWN';
  evidenceId?: string | null;
  findingId?: string | null;
}

export class AuthMatrixService {
  /**
   * Evaluates access for a specific role and operation, delegating to recordEvaluation
   */
  public static async evaluateAccess(params: {
    engagementId: string;
    operation: string;
    role: string;
    declaredExpected?: 'ALLOWED' | 'DENIED' | 'UNKNOWN';
    observed: 'ALLOWED' | 'DENIED' | 'ERROR';
    target?: string;
  }): Promise<AuthMatrixRecordOutput> {
    return this.recordEvaluation({
      engagementId: params.engagementId,
      operation: params.operation,
      authContext: {
        role: params.role,
        subjectIdentity: `identity_${params.role.toLowerCase()}`,
        objectIdentity: params.target || 'target_endpoint'
      },
      declaredExpected: params.declaredExpected,
      observed: params.observed
    });
  }

  /**
   * Records an authorization observation and computes the outcome.
   * If a discrepancy is observed (e.g. Expected DENIED, but Observed ALLOWED),
   * an engine Finding is created or linked.
   */
  public static async recordEvaluation(item: AuthMatrixEvaluationItem): Promise<AuthMatrixRecordOutput> {
    const { engagementId, assetId, operation, authContext, observed, evidenceData } = item;
    const role = authContext.role || 'anonymous';
    const subjectIdentity = authContext.subjectIdentity || 'unknown_subject';
    const objectIdentity = authContext.objectIdentity || 'unknown_object';

    // "If no role policy has been declared, mark the expectation as UNKNOWN rather than fabricating one."
    const expected = item.declaredExpected || 'UNKNOWN';

    let result: 'MATCH' | 'DISCREPANCY' | 'UNKNOWN';
    if (expected === 'UNKNOWN') {
      result = 'UNKNOWN';
    } else if (expected === observed) {
      result = 'MATCH';
    } else {
      result = 'DISCREPANCY';
    }

    let evidenceId: string | undefined;
    let findingId: string | undefined;

    // Discrepancy triggers finding creation/update and immutable evidence recording
    if (result === 'DISCREPANCY') {
      const isHorizontal = authContext.tenantId !== undefined;
      const category = isHorizontal ? 'IDOR' : 'AUTH';
      const severity = observed === 'ALLOWED' && expected === 'DENIED' ? 'HIGH' : 'MEDIUM';

      // 1. Create Finding in SUSPECTED state
      const finding = await FindingEvidenceService.createFinding({
        engagementId,
        title: `Broken Authorization: ${operation} accessible by ${role}`,
        description: `Discrepancy in ${isHorizontal ? 'Horizontal' : 'Vertical'} Access Control. Expected: ${expected}, Observed: ${observed}`,
        category,
        severity,
        target: objectIdentity
      });
      findingId = finding.id;

      // 2. Create immutable evidence linked to finding
      const ev = await FindingEvidenceService.createEvidence({
        findingId: finding.id,
        actionId: `auth_${Date.now()}`,
        target: objectIdentity,
        observation: `Authorization discrepancy detected: Operation '${operation}' for Role '${role}' (Subject: ${subjectIdentity}) expected '${expected}' but observed '${observed}'`,
        requestMetadata: { authContext },
        responseMetadata: evidenceData || { observed },
        authContext: { role, subjectIdentity, objectIdentity },
        reproductionSteps: `Replay operation '${operation}' with role token for '${subjectIdentity}' against target object '${objectIdentity}'`
      });
      evidenceId = ev.id;

      // 3. Transition finding: SUSPECTED -> TESTED -> VALIDATED
      await FindingEvidenceService.transitionFinding(finding.id, 'TESTED');
      await FindingEvidenceService.transitionFinding(finding.id, 'VALIDATED');
    }

    // Persist to AuthMatrixRecord
    const record = await prisma.authMatrixRecord.create({
      data: {
        engagementId,
        assetId: assetId || null,
        operation,
        role,
        subjectIdentity,
        objectIdentity,
        expected,
        observed,
        result,
        evidenceId: evidenceId || null,
        findingId: findingId || null
      }
    });

    return {
      id: record.id,
      operation: record.operation,
      role: record.role,
      subjectIdentity: record.subjectIdentity,
      objectIdentity: record.objectIdentity,
      expected: record.expected,
      observed: record.observed,
      result: record.result as any,
      evidenceId: record.evidenceId,
      findingId: record.findingId
    };
  }

  /**
   * Generates the tabular representation of the matrix:
   * Operation | Role | Expected | Observed | Result | Evidence
   */
  public static async generateMatrix(engagementId: string): Promise<AuthMatrixRecordOutput[]> {
    const records = await prisma.authMatrixRecord.findMany({
      where: { engagementId },
      orderBy: [{ operation: 'asc' }, { role: 'asc' }]
    });

    return records.map(r => ({
      id: r.id,
      operation: r.operation,
      role: r.role,
      subjectIdentity: r.subjectIdentity,
      objectIdentity: r.objectIdentity,
      expected: r.expected,
      observed: r.observed,
      result: r.result as any,
      evidenceId: r.evidenceId,
      findingId: r.findingId
    }));
  }
}
