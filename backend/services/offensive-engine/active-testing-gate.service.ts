import prisma from '../../config/database';
import { ScopeGuard, ScopeAction, ApprovedAction } from '../scope-guard/scope-guard.service';
import { ScopeRateLimiter } from '../scope-guard/rate-limiter';
import { isTargetAllowed, AllowedTargetRule } from '../scope-guard/cidr.util';

export interface GateEvaluationRequest {
  engagementId: string;
  action: ScopeAction;
  authContext?: any;
}

export interface GateEvaluationResult {
  canExecute: boolean;
  decision: string;
  blockingReason?: string;
  conditionFailed?: number;
  approvedAction?: ApprovedAction;
  auditLogId?: string;
}

export class ActiveTestingGate {
  /**
   * Evaluates all 10 mandatory safety conditions before any active PoC or testing action.
   * If ANY condition fails, execution is halted immediately and blocking reason is persisted.
   */
  public static async evaluate(req: GateEvaluationRequest): Promise<GateEvaluationResult> {
    const { engagementId, action, authContext } = req;
    const now = new Date();
    const targetHost = (action.targetHost || action.target || '').trim();
    const requestedTestType = (action.testType || 'UNKNOWN').toUpperCase().trim();

    // 1. Engagement exists & is active
    const engagement = await prisma.engagement.findUnique({
      where: { id: engagementId },
      include: { scope: true }
    });

    if (!engagement) {
      return this.recordBlocked(engagementId, targetHost, requestedTestType, 1, 'BLOCKED_OUT_OF_SCOPE', 'Condition 1 Failed: Engagement does not exist');
    }
    if (engagement.status !== 'active') {
      return this.recordBlocked(engagementId, targetHost, requestedTestType, 1, 'BLOCKED_EXPIRED_SCOPE', `Condition 1 Failed: Engagement is not active (current: '${engagement.status}')`);
    }

    // 2. Scope exists
    if (!engagement.scope) {
      return this.recordBlocked(engagementId, targetHost, requestedTestType, 2, 'BLOCKED_EXPIRED_SCOPE', 'Condition 2 Failed: No Scope attached to engagement');
    }
    const scope = engagement.scope;

    // 3. Scope is currently valid
    if (now < new Date(scope.validFrom) || now > new Date(scope.validUntil)) {
      return this.recordBlocked(engagementId, targetHost, requestedTestType, 3, 'BLOCKED_EXPIRED_SCOPE', `Condition 3 Failed: Scope window invalid (validFrom: ${scope.validFrom.toISOString()}, validUntil: ${scope.validUntil.toISOString()})`);
    }

    // 4. Target matches allowedTargets
    const allowedTargets: (AllowedTargetRule | string)[] = (() => {
      try { return JSON.parse(scope.allowedTargets); } catch { return []; }
    })();
    const targetInScope = isTargetAllowed(targetHost, action.targetPort, action.targetProtocol, allowedTargets);
    if (!targetInScope) {
      return this.recordBlocked(engagementId, targetHost, requestedTestType, 4, 'BLOCKED_OUT_OF_SCOPE', `Condition 4 Failed: Target '${targetHost}' is not in allowedTargets`);
    }

    // 5. Test type is present in allowedTestTypes
    const allowedTestTypes: string[] = (() => {
      try { return JSON.parse(scope.allowedTestTypes).map((t: string) => t.toUpperCase().trim()); } catch { return []; }
    })();
    if (!allowedTestTypes.includes(requestedTestType)) {
      return this.recordBlocked(engagementId, targetHost, requestedTestType, 5, 'BLOCKED_TEST_TYPE', `Condition 5 Failed: Test type '${requestedTestType}' not in allowedTestTypes`);
    }

    // 6. activePoCAllowed is true (if action is PoC)
    if (action.isPoC && !scope.activePoCAllowed) {
      return this.recordBlocked(engagementId, targetHost, requestedTestType, 6, 'BLOCKED_POC_DISABLED', 'Condition 6 Failed: Active PoC execution is disabled in Scope');
    }

    // 7. Action not prohibited by destructiveActionsAllowed
    if (action.isDestructive && !scope.destructiveActionsAllowed) {
      return this.recordBlocked(engagementId, targetHost, requestedTestType, 7, 'BLOCKED_DESTRUCTIVE_ACTION', 'Condition 7 Failed: Destructive actions disabled in Scope');
    }

    // 8. Rate & concurrency limits permit execution
    const rateLimitConfig = ScopeRateLimiter.parseRateLimit(scope.rateLimit);
    const maxConcurrency = scope.concurrencyLimit || rateLimitConfig.concurrency || 5;
    if (ScopeRateLimiter.getConcurrency(engagementId) >= maxConcurrency) {
      return this.recordBlocked(engagementId, targetHost, requestedTestType, 8, 'BLOCKED_CONCURRENCY', `Condition 8 Failed: Concurrency limit (${maxConcurrency}) reached`);
    }
    const tokenResult = await ScopeRateLimiter.consumeToken(engagementId, scope.rateLimit);
    if (!tokenResult.allowed) {
      return this.recordBlocked(engagementId, targetHost, requestedTestType, 8, 'BLOCKED_RATE_LIMIT', `Condition 8 Failed: Rate limit exceeded (${rateLimitConfig.rps} req/s)`);
    }

    // 9. Required authorization context exists
    // If operation requires auth and no authContext is supplied, halt
    if (action.testType !== 'RECON' && action.testType !== 'MAPPING') {
      if (authContext && typeof authContext === 'object' && authContext.required && !authContext.subject) {
        return this.recordBlocked(engagementId, targetHost, requestedTestType, 9, 'BLOCKED_OUT_OF_SCOPE', 'Condition 9 Failed: Required Authorization Context (subject) missing');
      }
    }

    // 10. Action has passed ScopeGuard
    const scopeResult = await ScopeGuard.checkScope(engagementId, {
      ...action,
      targetHost
    });

    if (!scopeResult.allowed) {
      return {
        canExecute: false,
        decision: scopeResult.decision,
        blockingReason: `Condition 10 Failed: ScopeGuard rejected with ${scopeResult.decision}: ${scopeResult.reason}`,
        conditionFailed: 10,
        auditLogId: scopeResult.auditLogId
      };
    }

    return {
      canExecute: true,
      decision: 'ALLOWED',
      approvedAction: scopeResult.approvedAction,
      auditLogId: scopeResult.auditLogId
    };
  }

  private static async recordBlocked(
    engagementId: string,
    targetHost: string,
    testType: string,
    conditionFailed: number,
    decision: string,
    reason: string
  ): Promise<GateEvaluationResult> {
    let auditLogId: string | undefined;
    try {
      const entry = await prisma.auditLogEntry.create({
        data: {
          engagementId,
          action: `${testType} -> ${targetHost}`,
          targetHost: targetHost || '<UNKNOWN>',
          requestedTestType: testType,
          decision,
          reason,
          metadata: JSON.stringify({ conditionFailed, timestamp: new Date().toISOString() })
        }
      });
      auditLogId = entry.id;
    } catch {}

    return {
      canExecute: false,
      decision,
      blockingReason: reason,
      conditionFailed,
      auditLogId
    };
  }
}
