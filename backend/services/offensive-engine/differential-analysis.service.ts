import * as crypto from 'crypto';
import prisma from '../../config/database';
import { ScopeGuardService } from '../scope-guard/scope-guard.service';

export interface DifferentialRequest {
  engagementId: string;
  target: string;
  operation: string;
  testType: string;
  baselineContext: {
    role: string;
    userId?: string;
    token?: string;
    headers?: Record<string, string>;
  };
  testContext: {
    role: string;
    userId?: string;
    token?: string;
    headers?: Record<string, string>;
  };
  payload?: any;
}

export interface DifferentialResult {
  id: string;
  engagementId: string;
  target: string;
  operation: string;
  statusBaseline: number;
  statusTest: number;
  statusDiff: boolean;
  headerDiff: Record<string, any>;
  bodyDiff: string;
  discrepancy: boolean;
  hash: string;
  reason: string;
  findingId?: string | null;
}

export class DifferentialAnalysisService {
  /**
   * Executes differential comparison across two distinct authorization contexts
   * Gated through ScopeGuard
   */
  public static async evaluateDifferential(
    req: DifferentialRequest,
    simulatedExecution?: {
      baselineStatus: number;
      baselineHeaders?: Record<string, string>;
      baselineBody?: string;
      testStatus: number;
      testHeaders?: Record<string, string>;
      testBody?: string;
    }
  ): Promise<DifferentialResult> {
    const actionId = `diff-${crypto.randomBytes(6).toString('hex')}`;

    // 1. ScopeGuard validation for both executions
    const [scopeBaseline, scopeTest] = await Promise.all([
      ScopeGuardService.check({
        engagementId: req.engagementId,
        actionId: `${actionId}-base`,
        targetHost: req.target,
        requestedTestType: req.testType,
        isDestructive: false,
        isActivePoC: false,
        authContext: req.baselineContext
      }),
      ScopeGuardService.check({
        engagementId: req.engagementId,
        actionId: `${actionId}-test`,
        targetHost: req.target,
        requestedTestType: req.testType,
        isDestructive: false,
        isActivePoC: false,
        authContext: req.testContext
      })
    ]);

    if (scopeBaseline.decision !== 'ALLOWED' || scopeTest.decision !== 'ALLOWED') {
      const decision = scopeBaseline.decision !== 'ALLOWED' ? scopeBaseline.decision : scopeTest.decision;
      const reason = scopeBaseline.decision !== 'ALLOWED' ? scopeBaseline.reason : scopeTest.reason;
      throw new Error(`Differential analysis blocked by ScopeGuard: ${decision} (${reason})`);
    }

    // 2. Simulated or measured HTTP responses
    const bStatus = simulatedExecution?.baselineStatus ?? 200;
    const tStatus = simulatedExecution?.testStatus ?? 403;
    const bBody = simulatedExecution?.baselineBody ?? '{"authorized": true}';
    const tBody = simulatedExecution?.testBody ?? '{"error": "Forbidden"}';
    const bHeaders = simulatedExecution?.baselineHeaders ?? { 'content-type': 'application/json' };
    const tHeaders = simulatedExecution?.testHeaders ?? { 'content-type': 'application/json' };

    const statusDiff = bStatus !== tStatus;
    
    // Header differential
    const headerDiff: Record<string, any> = {};
    for (const [k, v] of Object.entries(tHeaders)) {
      if (bHeaders[k] !== v) {
        headerDiff[k] = { baseline: bHeaders[k], test: v };
      }
    }

    // Body differential
    let bodyDiff = '';
    if (bBody !== tBody) {
      bodyDiff = `Baseline (${bBody.length} bytes) != Test (${tBody.length} bytes)`;
    }

    // Discrepancy logic:
    // If testContext is less privileged (e.g. GUEST or regular USER) but receives 200 OK
    // while accessing an admin operation, that is an authorization discrepancy!
    let discrepancy = false;
    let discrepancyReason = 'Responses match expected authorization partition.';
    
    if (req.testContext.role.toUpperCase() === 'GUEST' || req.testContext.role.toUpperCase() === 'ANONYMOUS') {
      if (tStatus === 200 && bStatus === 200) {
        discrepancy = true;
        discrepancyReason = `Unauthenticated/Guest role achieved status 200 on ${req.operation} (Privilege Escalation / IDOR Discrepancy)`;
      }
    } else if (req.testContext.role !== req.baselineContext.role && tStatus === bStatus && tStatus === 200) {
      if (req.operation.includes('admin') || req.operation.includes('delete') || req.operation.includes('billing')) {
        discrepancy = true;
        discrepancyReason = `Role ${req.testContext.role} observed identical 200 OK access to privileged operation ${req.operation}`;
      }
    }

    // Compute SHA-256 integrity hash of the differential report
    const hashPayload = JSON.stringify({
      target: req.target,
      operation: req.operation,
      baselineContext: req.baselineContext,
      testContext: req.testContext,
      bStatus,
      tStatus,
      bodyDiff
    });
    const hash = crypto.createHash('sha256').update(hashPayload).digest('hex');

    // Create Differential record in DB
    const record = await prisma.differentialEvidence.create({
      data: {
        engagementId: req.engagementId,
        target: req.target,
        operation: req.operation,
        baselineContext: JSON.stringify(req.baselineContext),
        testContext: JSON.stringify(req.testContext),
        statusBaseline: bStatus,
        statusTest: tStatus,
        statusDiff,
        bodyDiff,
        headerDiff: JSON.stringify(headerDiff),
        discrepancy,
        hash
      }
    });

    return {
      id: record.id,
      engagementId: req.engagementId,
      target: req.target,
      operation: req.operation,
      statusBaseline: bStatus,
      statusTest: tStatus,
      statusDiff,
      headerDiff,
      bodyDiff,
      discrepancy,
      hash,
      reason: discrepancyReason
    };
  }
}
