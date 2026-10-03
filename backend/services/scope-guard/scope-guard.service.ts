import * as crypto from 'crypto';
import prisma from '../../config/database';
import { isTargetAllowed, AllowedTargetRule, normalizeTargetHost } from './cidr.util';
import { ScopeRateLimiter, RateLimitConfig } from './rate-limiter';

export type ScopeDecision =
  | 'ALLOWED'
  | 'BLOCKED_OUT_OF_SCOPE'
  | 'BLOCKED_EXPIRED_SCOPE'
  | 'BLOCKED_TEST_TYPE'
  | 'BLOCKED_RATE_LIMIT'
  | 'BLOCKED_CONCURRENCY'
  | 'BLOCKED_DESTRUCTIVE_ACTION'
  | 'BLOCKED_POC_DISABLED';

export interface ScopeAction {
  actionId?: string;
  engagementId?: string;
  testType?: string;
  requestedTestType?: string;
  targetHost?: string;
  target?: string;
  targetPort?: number;
  targetProtocol?: string;
  isDestructive?: boolean;
  isPoC?: boolean;
  isActivePoC?: boolean;
  authContext?: any;
  payload?: any;
}

export interface ApprovedAction {
  actionId: string;
  engagementId: string;
  target: string;
  targetPort?: number;
  targetProtocol?: string;
  testType: string;
  isDestructive: boolean;
  isPoC: boolean;
  scopeDecision: 'ALLOWED';
  issuedAt: string;
  expiresAt: string;
  token: string;
}

export interface ScopeCheckResult {
  allowed: boolean;
  reason?: string;
  decision: ScopeDecision;
  auditLogId?: string;
  approvedAction?: ApprovedAction;
}

const SCOPE_SIGNING_SECRET = process.env.JWT_SECRET || 'cybersploi-engine-guard-internal-secret-key-32chars';

export class ScopeGuard {
  /**
   * Helper to safely parse JSON strings from SQLite
   */
  private static parseJsonField<T>(fieldValue: any, fallback: T): T {
    if (!fieldValue) return fallback;
    if (typeof fieldValue === 'object') return fieldValue as T;
    if (typeof fieldValue === 'string') {
      try {
        return JSON.parse(fieldValue) as T;
      } catch {
        return fallback;
      }
    }
    return fallback;
  }

  /**
   * Generates a tamper-proof cryptographic authorization token for an approved action.
   */
  public static signApprovedAction(payload: Omit<ApprovedAction, 'token'>): string {
    const raw = `${payload.actionId}|${payload.engagementId}|${payload.target}|${payload.testType}|${payload.expiresAt}`;
    return crypto.createHmac('sha256', SCOPE_SIGNING_SECRET).update(raw).digest('hex');
  }

  /**
   * Verifies an ApprovedAction token before worker execution.
   */
  public static verifyApprovedAction(action: ApprovedAction): boolean {
    try {
      if (!action || !action.token || action.scopeDecision !== 'ALLOWED') return false;
      if (new Date(action.expiresAt).getTime() < Date.now()) return false;
      const expected = this.signApprovedAction({
        actionId: action.actionId,
        engagementId: action.engagementId,
        target: action.target,
        targetPort: action.targetPort,
        targetProtocol: action.targetProtocol,
        testType: action.testType,
        isDestructive: action.isDestructive,
        isPoC: action.isPoC,
        scopeDecision: 'ALLOWED',
        issuedAt: action.issuedAt,
        expiresAt: action.expiresAt
      });
      const bufA = Buffer.from(action.token);
      const bufB = Buffer.from(expected);
      if (bufA.length !== bufB.length) return false;
      return crypto.timingSafeEqual(bufA, bufB);
    } catch {
      return false;
    }
  }

  /**
   * Primary entry point: ScopeGuard.check(action, target)
   * Evaluates if action against target is authorized under engagement scope.
   */
  public static async check(action: ScopeAction, target?: string): Promise<ScopeCheckResult> {
    const effectiveTarget = (target || action.target || action.targetHost || '').trim();
    const engagementId = action.engagementId;

    if (!engagementId) {
      return {
        allowed: false,
        decision: 'BLOCKED_OUT_OF_SCOPE',
        reason: 'Scope check failed: Missing engagementId in action context'
      };
    }

    return this.checkScope(engagementId, {
      ...action,
      targetHost: effectiveTarget
    });
  }

  /**
   * Authorizes any engine action against the target scope.
   * Denials and approvals are strictly audit-logged.
   */
  public static async checkScope(
    engagementId: string,
    action: ScopeAction
  ): Promise<ScopeCheckResult> {
    const requestedTestType = (action.testType || action.requestedTestType || 'UNKNOWN').toUpperCase().trim();
    const targetHost = (action.targetHost || action.target || '').trim();
    const now = new Date();

    // Malformed target rejection
    if (!targetHost || targetHost.length > 512 || targetHost.includes(';') || targetHost.includes('`') || targetHost.includes('|')) {
      // Log blocked malformed target
      let auditLogId: string | undefined;
      try {
        const entry = await prisma.auditLogEntry.create({
          data: {
            engagementId,
            action: `${requestedTestType} -> ${targetHost || '<EMPTY>'}`,
            targetHost: targetHost || '<EMPTY>',
            requestedTestType,
            decision: 'BLOCKED_OUT_OF_SCOPE',
            reason: 'Malformed or illegal target string detected',
            metadata: JSON.stringify({ rawTarget: targetHost, isDestructive: action.isDestructive, isPoC: action.isPoC })
          }
        });
        auditLogId = entry.id;
      } catch {}
      return {
        allowed: false,
        decision: 'BLOCKED_OUT_OF_SCOPE',
        reason: 'Malformed or illegal target string detected',
        auditLogId
      };
    }

    // 1. Fetch engagement and scope
    const engagement = await prisma.engagement.findUnique({
      where: { id: engagementId },
      include: { scope: true }
    });

    let decision: ScopeDecision;
    let reason: string | undefined;
    let allowed = false;

    if (!engagement) {
      decision = 'BLOCKED_OUT_OF_SCOPE';
      reason = `Engagement with ID ${engagementId} does not exist`;
    } else if (!engagement.scope) {
      decision = 'BLOCKED_EXPIRED_SCOPE';
      reason = `Engagement ${engagementId} does not have an attached scope record`;
    } else {
      const scope = engagement.scope;
      const allowedTargets = this.parseJsonField<(AllowedTargetRule | string)[]>(scope.allowedTargets, []);
      const allowedTestTypes = this.parseJsonField<string[]>(scope.allowedTestTypes, []).map(t => t.toUpperCase().trim());
      const rateLimitConfig = this.parseJsonField<RateLimitConfig>(scope.rateLimit, { requestsPerSecond: 10, concurrency: 5 });
      const maxConcurrency = scope.concurrencyLimit || rateLimitConfig.concurrency || 5;

      // RULE 1: TARGET SCOPE BOUNDARY
      // Any action against a host not in allowedTargets is rejected and logged, regardless of engagement status.
      const targetInScope = isTargetAllowed(targetHost, action.targetPort, action.targetProtocol, allowedTargets);

      if (!targetInScope) {
        decision = 'BLOCKED_OUT_OF_SCOPE';
        reason = `Target '${targetHost}'${action.targetPort ? ':' + action.targetPort : ''} is not authorized in allowedTargets for engagement ${engagementId}`;
      }
      // RULE 2: ENGAGEMENT STATUS & TEMPORAL VALIDITY
      else if (engagement.status !== 'active') {
        decision = 'BLOCKED_EXPIRED_SCOPE';
        reason = `Engagement is not active (current status: '${engagement.status}')`;
      } else if (now < new Date(scope.validFrom)) {
        decision = 'BLOCKED_EXPIRED_SCOPE';
        reason = `Scope validity window has not started yet (validFrom: ${new Date(scope.validFrom).toISOString()})`;
      } else if (now > new Date(scope.validUntil)) {
        decision = 'BLOCKED_EXPIRED_SCOPE';
        reason = `Scope has expired (validUntil: ${new Date(scope.validUntil).toISOString()})`;
      }
      // RULE 3: TEST TYPE ALLOWLIST
      else if (!allowedTestTypes.includes(requestedTestType)) {
        decision = 'BLOCKED_TEST_TYPE';
        reason = `Test type '${requestedTestType}' is not in allowedTestTypes: [${allowedTestTypes.join(', ')}]`;
      }
      // RULE 4: DESTRUCTIVE ACTION SAFETY SWITCH
      else if (action.isDestructive && !scope.destructiveActionsAllowed) {
        decision = 'BLOCKED_DESTRUCTIVE_ACTION';
        reason = `Destructive action blocked: Scope has destructiveActionsAllowed set to false`;
      }
      // RULE 5: ACTIVE POC SAFETY SWITCH
      else if ((action.isPoC || action.isActivePoC) && !scope.activePoCAllowed) {
        decision = 'BLOCKED_POC_DISABLED';
        reason = `Active PoC blocked: Scope has activePoCAllowed set to false (recon/hypothesis only)`;
      }
      // RULE 6: CONCURRENCY LIMIT
      else if (ScopeRateLimiter.getConcurrency(engagementId) >= maxConcurrency) {
        decision = 'BLOCKED_CONCURRENCY';
        reason = `Concurrency limit reached: Maximum ${maxConcurrency} active concurrent actions for engagement ${engagementId}`;
      }
      // RULE 7: TOKEN BUCKET RATE LIMITING
      else {
        const rateLimitResult = await ScopeRateLimiter.consumeToken(engagementId, rateLimitConfig);
        if (!rateLimitResult.allowed) {
          decision = 'BLOCKED_RATE_LIMIT';
          reason = rateLimitResult.reason || 'Engagement rate limit exceeded';
        } else {
          decision = 'ALLOWED';
          allowed = true;
        }
      }
    }

    // 8. WRITE AUDIT LOG ENTRY (Never silently discard blocked requests)
    let auditLogId: string | undefined;
    try {
      if (engagement) {
        const entry = await prisma.auditLogEntry.create({
          data: {
            engagementId,
            action: `${requestedTestType} -> ${targetHost}${action.targetPort ? ':' + action.targetPort : ''}`,
            targetHost: targetHost || '<UNKNOWN>',
            requestedTestType,
            decision,
            reason: reason || null,
            metadata: JSON.stringify({
              targetPort: action.targetPort,
              targetProtocol: action.targetProtocol,
              isDestructive: action.isDestructive,
              isPoC: action.isPoC,
              status: engagement.status,
              environment: engagement.environment
            })
          }
        });
        auditLogId = entry.id;
      }
    } catch (logErr: any) {
      console.error(`[ScopeGuard] CRITICAL: Failed to write audit log for engagement ${engagementId}:`, logErr.message);
    }

    // 9. ISSUE APPROVED ACTION IF ALLOWED
    let approvedAction: ApprovedAction | undefined;
    if (allowed && engagement) {
      const actionId = action.actionId || `act_${crypto.randomBytes(8).toString('hex')}`;
      const issuedAt = now.toISOString();
      const expiresAt = new Date(Date.now() + 60000).toISOString(); // 60s window to execute
      const unsigned = {
        actionId,
        engagementId,
        target: targetHost,
        targetPort: action.targetPort,
        targetProtocol: action.targetProtocol,
        testType: requestedTestType,
        isDestructive: !!action.isDestructive,
        isPoC: !!(action.isPoC || action.isActivePoC),
        scopeDecision: 'ALLOWED' as const,
        issuedAt,
        expiresAt
      };
      const token = this.signApprovedAction(unsigned);
      approvedAction = { ...unsigned, token };
    }

    return {
      allowed,
      reason,
      decision,
      auditLogId,
      approvedAction
    };
  }
}

export const ScopeGuardService = ScopeGuard;

export async function checkScope(
  engagementId: string,
  action: ScopeAction
): Promise<ScopeCheckResult> {
  return ScopeGuard.checkScope(engagementId, action);
}

export default ScopeGuard;
