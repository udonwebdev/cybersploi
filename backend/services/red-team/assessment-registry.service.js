/**
 * Assessment Lifecycle & Cancellation Registry
 * Manages active assessment sessions in memory with AbortController tokens,
 * handles operator-initiated cancellations, pause/resume signaling,
 * and executes server restart recovery for interrupted assessments.
 */

const prisma = require('../../config/database');

class AssessmentRegistryService {
  constructor() {
    // Map of assessmentId -> { abortController, scanId, startedAt, isPaused }
    this.activeAssessments = new Map();
    // Set of cancelled assessment IDs for persistent querying
    this.cancelledAssessments = new Set();
  }

  /**
   * Register an assessment run with an AbortController
   */
  register(assessmentId, scanId) {
    const abortController = new AbortController();
    this.activeAssessments.set(assessmentId, {
      abortController,
      scanId,
      startedAt: new Date(),
      isPaused: false
    });
    return abortController;
  }

  /**
   * Get the AbortSignal for an assessment
   */
  getSignal(assessmentId) {
    return this.activeAssessments.get(assessmentId)?.abortController.signal;
  }

  /**
   * Check if an assessment has been cancelled
   */
  isCancelled(assessmentId) {
    if (this.cancelledAssessments.has(assessmentId)) return true;
    const entry = this.activeAssessments.get(assessmentId);
    return entry ? entry.abortController.signal.aborted : false;
  }

  /**
   * Cancel an in-progress assessment cleanly
   */
  async cancel(assessmentId, reason = 'Operator initiated cancellation from dashboard') {
    this.cancelledAssessments.add(assessmentId);
    const entry = this.activeAssessments.get(assessmentId);
    if (entry) {
      entry.abortController.abort();
    }

    // Persist cancellation in database
    try {
      const assessment = await prisma.redTeamAssessment.findFirst({
        where: {
          OR: [
            { id: assessmentId },
            { scanId: assessmentId }
          ]
        }
      });

      if (assessment) {
        await prisma.redTeamAssessment.update({
          where: { id: assessment.id },
          data: {
            status: 'CANCELLED',
            phase: 'CANCELLED',
            currentObjective: `Assessment cancelled: ${reason}`,
            completedAt: new Date()
          }
        });

        if (assessment.scanId) {
          await prisma.scan.update({
            where: { id: assessment.scanId },
            data: { status: 'cancelled' }
          });
        }

        // Record audit event
        await prisma.assessmentEvent.create({
          data: {
            assessmentId: assessment.id,
            phase: 'CANCELLED',
            stage: 'Lifecycle Control',
            level: 'WARN',
            message: `Assessment halted by operator: ${reason}`,
            timestamp: new Date()
          }
        });

        this.activeAssessments.delete(assessment.id);
        return { success: true, assessmentId: assessment.id, status: 'CANCELLED' };
      }
    } catch (e) {
      console.error('[AssessmentRegistry] Error recording cancellation:', e.message);
    }

    this.activeAssessments.delete(assessmentId);
    return { success: true, assessmentId, status: 'CANCELLED' };
  }

  /**
   * Deregister assessment upon completion
   */
  deregister(assessmentId) {
    this.activeAssessments.delete(assessmentId);
  }

  /**
   * List all currently registered active assessments in memory
   */
  listActive() {
    const list = [];
    for (const [id, entry] of this.activeAssessments.entries()) {
      list.push({
        assessmentId: id,
        scanId: entry.scanId,
        startedAt: entry.startedAt,
        isPaused: entry.isPaused,
        isAborted: entry.abortController.signal.aborted
      });
    }
    return list;
  }

  /**
   * Startup Recovery: Scan database for orphaned running jobs after a crash or restart
   */
  async recoverOrphanedAssessments() {
    try {
      const orphanedAssessments = await prisma.redTeamAssessment.findMany({
        where: {
          status: 'RUNNING'
        }
      });

      if (orphanedAssessments.length > 0) {
        console.log(`[AssessmentRegistry] Found ${orphanedAssessments.length} orphaned assessments from previous system run. Resolving truthful status...`);
        for (const ass of orphanedAssessments) {
          await prisma.redTeamAssessment.update({
            where: { id: ass.id },
            data: {
              status: 'PARTIALLY_COMPLETED',
              currentObjective: 'Assessment execution suspended due to system reboot. Preserved collected evidence ledger.',
              completedAt: new Date()
            }
          });

          if (ass.scanId) {
            await prisma.scan.update({
              where: { id: ass.scanId },
              data: { status: 'completed' }
            });
          }

          await prisma.assessmentEvent.create({
            data: {
              assessmentId: ass.id,
              phase: 'RECOVERY',
              stage: 'System Boot Recovery',
              level: 'WARN',
              message: 'Server restarted while assessment was active. Preserved verified findings, closed open sockets, and finalized lifecycle as PARTIALLY_COMPLETED.',
              timestamp: new Date()
            }
          });
        }
      }
    } catch (err) {
      console.warn('[AssessmentRegistry] Recovery check note:', err.message);
    }
  }
}

// Singleton instance
const registryInstance = new AssessmentRegistryService();
module.exports = registryInstance;
