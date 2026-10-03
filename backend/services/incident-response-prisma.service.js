const prisma = require('../config/database');
const Queue = require('bull');
const { v4: uuidv4 } = require('uuid');

const remediationQueue = new Queue('remediation-tasks', {
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379,
  },
});

class IncidentResponseService {
  constructor() {
    this.name = 'Incident Response Service (Prisma)';
  }

  async createIncident({ organizationId, title, description = '', severity = 'medium', detectionSource = 'external', indicators = [], metadata = {}, detectedAt = null, createdBy = null }) {
    const id = `inc_${uuidv4()}`;

    try {
      const incident = await prisma.incident.create({
        data: {
          id,
          organizationId,
          title,
          description,
          severity,
          status: 'open',
          detectionSource,
          detectedAt: detectedAt || new Date(),
          indicators: JSON.stringify(indicators),
          metadata: JSON.stringify(metadata),
        },
      });

      // Create alert record
      const alertId = `alert_${uuidv4()}`;
      await prisma.alert.create({
        data: {
          id: alertId,
          organizationId,
          incidentId: id,
          provider: detectionSource,
          payload: JSON.stringify({ title, description, indicators }),
          severity,
        },
      });

      // Enqueue triage job
      await remediationQueue.add('triage', { incidentId: id, organizationId }, { attempts: 3, removeOnComplete: true });

      return { success: true, incidentId: id };
    } catch (error) {
      console.error('createIncident error:', error.message);
      return { success: false, error: error.message };
    }
  }

  async getIncident(incidentId) {
    try {
      const incident = await prisma.incident.findUnique({
        where: { id: incidentId },
        include: {
          remediationTasks: true,
          alerts: true,
        },
      });

      if (!incident) return null;

      return {
        ...incident,
        indicators: JSON.parse(incident.indicators),
        metadata: incident.metadata ? JSON.parse(incident.metadata) : {},
      };
    } catch (error) {
      console.error('getIncident error:', error.message);
      throw error;
    }
  }

  async listIncidents(organizationId, filter = {}) {
    try {
      const where = { organizationId, ...(filter.status && { status: filter.status }) };
      const incidents = await prisma.incident.findMany({
        where,
        order​By: { createdAt: 'desc' },
        take: filter.limit || 100,
      });

      return incidents.map(inc => ({
        ...inc,
        indicators: JSON.parse(inc.indicators),
        metadata: inc.metadata ? JSON.parse(inc.metadata) : {},
      }));
    } catch (error) {
      console.error('listIncidents error:', error.message);
      throw error;
    }
  }

  async updateIncidentStatus(incidentId, newStatus) {
    try {
      await prisma.incident.update({
        where: { id: incidentId },
        data: { status: newStatus },
      });

      return { success: true };
    } catch (error) {
      console.error('updateIncidentStatus error:', error.message);
      return { success: false, error: error.message };
    }
  }

  async runPlaybookForIncident(incidentId, playbookId) {
    try {
      const playbook = await prisma.playbook.findUnique({
        where: { id: playbookId },
        include: { steps: { orderBy: { sequence: 'asc' } } },
      });

      if (!playbook) return { success: false, error: 'Playbook not found' };

      for (const step of playbook.steps) {
        const taskId = `task_${uuidv4()}`;
        await prisma.remediationTask.create({
          data: {
            id: taskId,
            incidentId,
            playbookStepId: step.id,
            status: 'pending',
          },
        });

        await remediationQueue.add('execute-step', { taskId, incidentId, stepId: step.id, step }, { attempts: 3, removeOnComplete: true });
      }

      await this.updateIncidentStatus(incidentId, 'in_progress');
      return { success: true };
    } catch (error) {
      console.error('runPlaybookForIncident error:', error.message);
      return { success: false, error: error.message };
    }
  }
}

module.exports = new IncidentResponseService();
