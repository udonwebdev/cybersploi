const Queue = require('bull');
const prisma = require('../config/database');
const EndpointAgent = require('./endpoint-agent.service');
const { v4: uuidv4 } = require('uuid');

const remediationQueue = new Queue('remediation-tasks', {
  redis: { host: process.env.REDIS_HOST || 'localhost', port: process.env.REDIS_PORT || 6379 }
});

class RemediationOrchestratorService {
  constructor() {
    this.name = 'Remediation Orchestrator';
    this.initProcessor();
  }

  initProcessor() {
    remediationQueue.process('execute-step', 5, async (job) => {
      const { taskId, incidentId, stepId, step } = job.data;
      console.log(`Executing remediation step ${stepId} for incident ${incidentId}`);

      // Mark task running
      await prisma.$executeRaw`
        UPDATE "RemediationTask" SET "status" = 'running', "startedAt" = ${new Date()}, "updatedAt" = ${new Date()} WHERE "id" = ${taskId}
      `;

      try {
        // Parse action and parameters
        const actionType = step.action;
        const params = step.parameters ? JSON.parse(step.parameters || '{}') : {};

        // Example action types: 'isolate-host', 'block-ip', 'kill-process', 'run-script'
        let result = null;

        if (['isolate-host','kill-process','run-script','install-patch','uninstall-file','quarantine-file','block-ip'].includes(actionType)) {
          // If an endpoint id provided in params, call endpoint agent
          if (params.endpointId || params.endpoint) {
            result = await EndpointAgent.executeAction(params.endpointId || params.endpoint, actionType, params);
          } else if (params.targetIp) {
            // network level - call network device API or use alerting stub
            result = { success: true, message: `Network action simulated: ${actionType} ${params.targetIp}` };
          } else {
            // fallback simulation
            result = { success: true, message: `Action ${actionType} executed in simulation mode` };
          }
        } else {
          // Unknown action - mark as failed
          result = { success: false, message: `Unsupported action: ${actionType}` };
        }

        // Persist EndpointAction if present
        const endpointActionId = `ea_${uuidv4()}`;
        await prisma.$executeRaw`
          INSERT INTO "EndpointAction" ("id","remediationTaskId","endpointId","actionType","parameters","status","startedAt","completedAt","result")
          VALUES (${endpointActionId}, ${taskId}, ${params.endpointId || params.endpoint || null}, ${actionType}, ${JSON.stringify(params)}, ${result.success ? 'completed' : 'failed'}, ${new Date()}, ${new Date()}, ${JSON.stringify(result)})
        `;

        // Update remediation task
        await prisma.$executeRaw`
          UPDATE "RemediationTask" SET "status" = ${result.success ? 'completed' : 'failed'}, "completedAt" = ${new Date()}, "result" = ${JSON.stringify(result)}, "updatedAt" = ${new Date()} WHERE "id" = ${taskId}
        `;

        return { success: true, result };
      } catch (err) {
        console.error('remediation step failed:', err.message);
        await prisma.$executeRaw`
          UPDATE "RemediationTask" SET "status" = 'failed', "updatedAt" = ${new Date()} WHERE "id" = ${taskId}
        `;
        throw err;
      }
    });

    remediationQueue.on('completed', (job) => {
      console.log('remediation job completed', job.id);
    });

    remediationQueue.on('failed', (job, err) => {
      console.error('remediation job failed', job.id, err.message);
    });
  }

  // Enqueue a remediation task (wraps the queue add)
  async enqueueTask(taskId, incidentId, step) {
    try {
      await remediationQueue.add('execute-step', { taskId, incidentId, stepId: step.id, step }, { attempts: 3, backoff: { type: 'exponential', delay: 2000 }, removeOnComplete: true });
      return { success: true };
    } catch (error) {
      console.error('enqueueTask error:', error.message);
      return { success: false, error: error.message };
    }
  }
}

module.exports = new RemediationOrchestratorService();
