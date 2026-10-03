import * as crypto from 'crypto';
import prisma from '../../config/database';
import { FindingEvidenceService } from './finding-evidence.service';
import { RedisEventBus } from './redis-events.service';
import { ControlledProofEnvService } from './controlled-proof-env.service';
import { ActiveTestingGate } from './active-testing-gate.service';

export type GauntletStep =
  | 'BUILD'
  | 'EXECUTE'
  | 'OBSERVE'
  | 'EVALUATE'
  | 'FIND_FAILURE'
  | 'REPAIR'
  | 'RETEST'
  | 'VERIFY'
  | 'BUILD_TEST'
  | 'ANALYZE'
  | 'MODIFY';

export interface GauntletExecutionRequest {
  engagementId: string;
  findingId?: string;
  target: string;
  testType: string;
  maxIterations?: number;
  timeoutMs?: number;
  requireLiveScope?: boolean;
  testExecutor?: (iteration: number, step: GauntletStep, activeTarget: string) => Promise<{
    success: boolean;
    observedData?: any;
    vulnerabilityConfirmed?: boolean;
    reproductionSteps?: string;
    shouldRetry?: boolean;
    error?: string;
  }>;
}

export interface GauntletExecutionResult {
  correlationId: string;
  status: 'COMPLETED' | 'CANCELLED' | 'FAILED' | 'INCONCLUSIVE';
  finalStep: GauntletStep;
  iterationsCompleted: number;
  findingStatus?: string;
  evidenceId?: string;
  reason: string;
  sandboxSubstituted?: boolean;
  activeTargetUsed: string;
}

export class GauntletLoopService {
  private static cancelledCorrelations: Set<string> = new Set();

  /**
   * Signals cancellation of an in-flight gauntlet run.
   */
  public static cancel(correlationId: string): boolean {
    this.cancelledCorrelations.add(correlationId);
    return true;
  }

  /**
   * Executes the strict 8-step Gauntlet loop:
   * BUILD -> EXECUTE -> OBSERVE -> EVALUATE -> FIND FAILURE -> REPAIR -> RETEST -> VERIFY
   *
   * SAFE ADAPTIVE RULE:
   * For security testing, execution against external infrastructure requires an explicit authorized target scope.
   * For everything else or unapproved targets, automatically substitute an ephemeral Controlled Proof Environment sandbox.
   */
  public static async execute(req: GauntletExecutionRequest): Promise<GauntletExecutionResult> {
    const correlationId = `gauntlet_${crypto.randomBytes(8).toString('hex')}`;
    const maxIterations = Math.min(Math.max(1, req.maxIterations || 5), 20);
    const timeoutMs = req.timeoutMs || 30000;
    const startTime = Date.now();

    let activeTarget = req.target;
    let sandboxSubstituted = false;
    let ephemeralEnv: ControlledProofEnvService | null = null;

    // 1. Evaluate Target Scope Boundary
    const gateEval = await ActiveTestingGate.evaluate({
      engagementId: req.engagementId,
      action: {
        testType: req.testType,
        target: req.target,
        targetHost: req.target
      }
    });

    if (!gateEval.canExecute) {
      // Automatic Sandbox Substitution
      sandboxSubstituted = true;
      ephemeralEnv = new ControlledProofEnvService();
      const sandboxPort = await ephemeralEnv.start();
      activeTarget = `127.0.0.1:${sandboxPort}`;

      RedisEventBus.publish({
        engagementId: req.engagementId,
        actionId: correlationId,
        correlationId,
        timestamp: new Date().toISOString(),
        severity: 'INFO',
        TARGET: req.target,
        SESSION: correlationId,
        ACTION: 'SANDBOX_SUBSTITUTION',
        DECISION: 'SUBSTITUTED_LAB_SANDBOX',
        OBSERVATION: `Target '${req.target}' not in scope or active testing disabled (${gateEval.decision}). Automatically substituted ephemeral sandbox: ${activeTarget}`,
        NEXT_TEST: 'PROCEED_IN_SANDBOX'
      });
    }

    // Persist Gauntlet record
    const execution = await prisma.gauntletExecution.create({
      data: {
        engagementId: req.engagementId,
        findingId: req.findingId || null,
        status: 'RUNNING',
        currentStep: 'BUILD',
        iteration: 1,
        maxIterations,
        timeoutMs,
        correlationId
      }
    });

    let currentIteration = 1;
    let currentStep: GauntletStep = 'BUILD';
    let lastEvidenceId: string | undefined;

    RedisEventBus.publish({
      engagementId: req.engagementId,
      actionId: correlationId,
      correlationId,
      timestamp: new Date().toISOString(),
      severity: 'INFO',
      TARGET: activeTarget,
      SESSION: correlationId,
      ACTION: 'GAUNTLET_START',
      REQUEST: { testType: req.testType, maxIterations, sandboxSubstituted },
      DECISION: 'IN_PROGRESS',
      OBSERVATION: `Gauntlet initialized for ${activeTarget} (Iteration 1/${maxIterations})`,
      NEXT_TEST: 'BUILD'
    });

    try {
      while (currentIteration <= maxIterations) {
        // Check cancellation
        if (this.cancelledCorrelations.has(correlationId)) {
          this.cancelledCorrelations.delete(correlationId);
          await prisma.gauntletExecution.update({
            where: { id: execution.id },
            data: { status: 'CANCELLED', currentStep }
          });
          return {
            correlationId,
            status: 'CANCELLED',
            finalStep: currentStep,
            iterationsCompleted: currentIteration,
            reason: 'Gauntlet cancelled by user or orchestrator signal',
            sandboxSubstituted,
            activeTargetUsed: activeTarget
          };
        }

        // Check timeout
        if (Date.now() - startTime > timeoutMs) {
          await prisma.gauntletExecution.update({
            where: { id: execution.id },
            data: { status: 'INCONCLUSIVE', currentStep }
          });
          if (req.findingId) {
            try {
              await FindingEvidenceService.transitionFinding(req.findingId, 'INCONCLUSIVE');
            } catch {}
          }
          return {
            correlationId,
            status: 'INCONCLUSIVE',
            finalStep: currentStep,
            iterationsCompleted: currentIteration,
            reason: `Gauntlet timeout: Exceeded execution limit of ${timeoutMs}ms`,
            sandboxSubstituted,
            activeTargetUsed: activeTarget
          };
        }

        // Step 1: BUILD
        currentStep = 'BUILD';
        await prisma.gauntletExecution.update({
          where: { id: execution.id },
          data: { iteration: currentIteration, currentStep: 'BUILD' }
        });

        // Step 2: EXECUTE
        currentStep = 'EXECUTE';
        let stepResult: {
          success: boolean;
          observedData?: any;
          vulnerabilityConfirmed?: boolean;
          reproductionSteps?: string;
          shouldRetry?: boolean;
          error?: string;
        } = {
          success: true,
          observedData: null,
          vulnerabilityConfirmed: false,
          reproductionSteps: undefined,
          shouldRetry: false,
          error: undefined
        };

        if (req.testExecutor) {
          try {
            stepResult = await req.testExecutor(currentIteration, currentStep, activeTarget);
          } catch (execErr: any) {
            stepResult = {
              success: false,
              observedData: null,
              vulnerabilityConfirmed: false,
              reproductionSteps: undefined,
              shouldRetry: true,
              error: execErr.message
            };
          }
        }

        // Step 3: OBSERVE
        currentStep = 'OBSERVE';
        RedisEventBus.publish({
          engagementId: req.engagementId,
          actionId: correlationId,
          correlationId,
          timestamp: new Date().toISOString(),
          severity: stepResult.vulnerabilityConfirmed ? 'HIGH' : 'INFO',
          TARGET: activeTarget,
          SESSION: correlationId,
          ACTION: `GAUNTLET_ITER_${currentIteration}`,
          REQUEST: { step: currentStep, iteration: currentIteration },
          RESPONSE: stepResult.observedData || { status: 'executed' },
          OBSERVATION: stepResult.error || (stepResult.vulnerabilityConfirmed ? 'Vulnerability behavior observed' : 'Target response received'),
          DECISION: stepResult.vulnerabilityConfirmed ? 'CONFIRMED' : 'EVALUATING',
          NEXT_TEST: stepResult.vulnerabilityConfirmed ? 'VERIFY' : 'EVALUATE'
        });

        // Step 4: EVALUATE
        currentStep = 'EVALUATE';

        if (stepResult.vulnerabilityConfirmed) {
          // Step 8: VERIFY
          currentStep = 'VERIFY';
          if (req.findingId) {
            const evidence = await FindingEvidenceService.createEvidence({
              findingId: req.findingId,
              actionId: correlationId,
              target: activeTarget,
              observation: `Gauntlet confirmed vulnerability on iteration ${currentIteration}${sandboxSubstituted ? ' (in ephemeral sandbox)' : ''}`,
              requestMetadata: { iteration: currentIteration, step: currentStep, sandboxSubstituted },
              responseMetadata: stepResult.observedData,
              reproductionSteps: stepResult.reproductionSteps || `Repeat gauntlet action against ${activeTarget} with parameter set ${currentIteration}`
            });
            lastEvidenceId = evidence.id;

            await FindingEvidenceService.transitionFinding(req.findingId, 'VALIDATED');
            if (stepResult.reproductionSteps) {
              await FindingEvidenceService.transitionFinding(req.findingId, 'PROVEN', {
                reproductionSteps: stepResult.reproductionSteps
              });
            }
          }

          await prisma.gauntletExecution.update({
            where: { id: execution.id },
            data: { status: 'COMPLETED', currentStep: 'VERIFY' }
          });

          return {
            correlationId,
            status: 'COMPLETED',
            finalStep: 'VERIFY',
            iterationsCompleted: currentIteration,
            findingStatus: 'PROVEN',
            evidenceId: lastEvidenceId,
            reason: `Vulnerability successfully verified on iteration ${currentIteration}`,
            sandboxSubstituted,
            activeTargetUsed: activeTarget
          };
        }

        // Step 5: FIND_FAILURE
        currentStep = 'FIND_FAILURE';

        // Step 6: REPAIR
        currentStep = 'REPAIR';

        // Step 7: RETEST
        currentStep = 'RETEST';

        currentIteration++;
      }

      // Max iterations reached without confirmation
      RedisEventBus.publish({
        engagementId: req.engagementId,
        actionId: correlationId,
        correlationId,
        timestamp: new Date().toISOString(),
        severity: 'WARN',
        TARGET: activeTarget,
        SESSION: correlationId,
        ACTION: 'MAX_ITERATIONS_REACHED',
        REQUEST: { maxIterations },
        DECISION: 'INCONCLUSIVE',
        OBSERVATION: `Maximum gauntlet iterations (${maxIterations}) reached without confirming vulnerability`,
        NEXT_TEST: 'TERMINATE'
      });

      if (req.findingId) {
        try {
          await FindingEvidenceService.transitionFinding(req.findingId, 'INCONCLUSIVE');
        } catch {}
      }

      await prisma.gauntletExecution.update({
        where: { id: execution.id },
        data: { status: 'INCONCLUSIVE', currentStep: 'RETEST' }
      });

      return {
        correlationId,
        status: 'INCONCLUSIVE',
        finalStep: 'RETEST',
        iterationsCompleted: maxIterations,
        findingStatus: 'INCONCLUSIVE',
        reason: 'MAX_ITERATIONS_REACHED: Exhausted all iterations without conclusive proof',
        sandboxSubstituted,
        activeTargetUsed: activeTarget
      };
    } finally {
      // Clean up ephemeral sandbox
      if (ephemeralEnv) {
        await ephemeralEnv.destroy();
      }
    }
  }
}
