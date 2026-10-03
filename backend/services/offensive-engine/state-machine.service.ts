import prisma from '../../config/database';
import { ScopeGuard } from '../scope-guard/scope-guard.service';

export type EnginePhase =
  | 'RECON'
  | 'MAPPING'
  | 'HYPOTHESIS_GEN'
  | 'ACTIVE_TESTING'
  | 'VALIDATION'
  | 'POC'
  | 'IMPACT_VERIFICATION'
  | 'ATTACK_PATH_ANALYSIS'
  | 'EVIDENCE_COLLECTION'
  | 'REPORTING'
  | 'RETEST';

export const ENGINE_PHASE_ORDER: EnginePhase[] = [
  'RECON',
  'MAPPING',
  'HYPOTHESIS_GEN',
  'ACTIVE_TESTING',
  'VALIDATION',
  'POC',
  'IMPACT_VERIFICATION',
  'ATTACK_PATH_ANALYSIS',
  'EVIDENCE_COLLECTION',
  'REPORTING',
  'RETEST'
];

// Map of valid state transitions (sequential forward progression, direct jump to RETEST from REPORTING, and RESET/RESTART to RECON)
const ALLOWED_TRANSITIONS: Record<EnginePhase, EnginePhase[]> = {
  RECON: ['MAPPING'],
  MAPPING: ['HYPOTHESIS_GEN', 'RECON'],
  HYPOTHESIS_GEN: ['ACTIVE_TESTING', 'MAPPING'],
  ACTIVE_TESTING: ['VALIDATION', 'HYPOTHESIS_GEN'],
  VALIDATION: ['POC', 'ATTACK_PATH_ANALYSIS', 'ACTIVE_TESTING'],
  POC: ['IMPACT_VERIFICATION', 'VALIDATION'],
  IMPACT_VERIFICATION: ['ATTACK_PATH_ANALYSIS'],
  ATTACK_PATH_ANALYSIS: ['EVIDENCE_COLLECTION'],
  EVIDENCE_COLLECTION: ['REPORTING'],
  REPORTING: ['RETEST', 'RECON'],
  RETEST: ['ACTIVE_TESTING', 'VALIDATION', 'REPORTING', 'RECON']
};

export interface TransitionRequest {
  engagementId: string;
  targetPhase: EnginePhase;
  actor: string;
  reason: string;
  actionId?: string;
  bypassPoCCheck?: boolean; // Only for dry-run simulation
}

export interface TransitionResult {
  success: boolean;
  previousPhase: EnginePhase;
  currentPhase: EnginePhase;
  transitionId?: string;
  error?: string;
  blockingReason?: string;
}

export class EngagementStateMachine {
  /**
   * Validates whether a state transition is legal according to the authoritative phase graph.
   */
  public static isValidTransition(from: EnginePhase, to: EnginePhase): boolean {
    if (from === to) return true;
    const allowed = ALLOWED_TRANSITIONS[from];
    return Array.isArray(allowed) && allowed.includes(to);
  }

  /**
   * Authoritative transition handler. Rejects illegal transitions and persists valid transitions.
   */
  public static async transition(req: TransitionRequest): Promise<TransitionResult> {
    const { engagementId, targetPhase, actor, reason, actionId } = req;

    const engagement = await prisma.engagement.findUnique({
      where: { id: engagementId },
      include: { scope: true }
    });

    if (!engagement) {
      return {
        success: false,
        previousPhase: 'RECON',
        currentPhase: 'RECON',
        error: `Engagement ${engagementId} does not exist`
      };
    }

    const previousPhase = (engagement.currentPhase || 'RECON') as EnginePhase;

    // RULE 1: Authoritative phase transition check
    if (!this.isValidTransition(previousPhase, targetPhase)) {
      return {
        success: false,
        previousPhase,
        currentPhase: previousPhase,
        error: `ILLEGAL_TRANSITION: Cannot transition engagement from '${previousPhase}' to '${targetPhase}'. Allowed: [${(ALLOWED_TRANSITIONS[previousPhase] || []).join(', ')}]`
      };
    }

    // RULE 2: POC gate invariant
    // POC must be unreachable unless Scope.activePoCAllowed === true
    if (targetPhase === 'POC') {
      if (!engagement.scope) {
        return {
          success: false,
          previousPhase,
          currentPhase: previousPhase,
          error: 'POC_BLOCKED_NO_SCOPE',
          blockingReason: 'POC phase unreachable: No Scope attached to engagement'
        };
      }
      if (!engagement.scope.activePoCAllowed) {
        return {
          success: false,
          previousPhase,
          currentPhase: previousPhase,
          error: 'POC_BLOCKED_POC_DISABLED',
          blockingReason: 'POC phase unreachable: Scope has activePoCAllowed set to false'
        };
      }
      if (engagement.status !== 'active') {
        return {
          success: false,
          previousPhase,
          currentPhase: previousPhase,
          error: 'POC_BLOCKED_ENGAGEMENT_INACTIVE',
          blockingReason: `POC phase unreachable: Engagement status is '${engagement.status}', must be 'active'`
        };
      }
    }

    // Persist transition record and update current phase in an atomic transaction
    const [transitionRecord, updatedEngagement] = await prisma.$transaction([
      prisma.engagementStateTransition.create({
        data: {
          engagementId,
          previousState: previousPhase,
          newState: targetPhase,
          actor: actor || 'system',
          reason: reason || 'Phase progression',
          scopeId: engagement.scope?.id || null,
          actionId: actionId || null
        }
      }),
      prisma.engagement.update({
        where: { id: engagementId },
        data: {
          currentPhase: targetPhase,
          startedAt: engagement.startedAt || (targetPhase !== 'RECON' ? new Date() : null),
          endedAt: targetPhase === 'REPORTING' ? new Date() : engagement.endedAt
        }
      })
    ]);

    return {
      success: true,
      previousPhase,
      currentPhase: targetPhase,
      transitionId: transitionRecord.id
    };
  }

  /**
   * Retrieves full state transition history for an engagement.
   */
  public static async getHistory(engagementId: string) {
    return prisma.engagementStateTransition.findMany({
      where: { engagementId },
      orderBy: { timestamp: 'asc' }
    });
  }
}
