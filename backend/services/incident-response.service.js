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
    this.name = 'Incident Response Service';
  }

  /**
   * Create a new incident and optionally kick off a playbook
   */
  async createIncident({ organizationId, title, description, severity = 'medium', detectionSource = 'external', indicators = [], metadata = {}, detectedAt = null, createdBy = null }) {
    const id = `inc_${uuidv4()}`;
    const now = new Date();

    try {
      await prisma.$executeRaw`
        INSERT INTO "Incident" ("id","organizationId","title","description","severity","status","detectionSource","detectedAt","indicators","metadata","createdAt","updatedAt")
        VALUES (${id}, ${organizationId}, ${title}, ${description}, ${severity}, 'open', ${detectionSource}, ${detectedAt}, ${JSON.stringify(indicators)}, ${JSON.stringify(metadata)}, ${now}, ${now})
      `;

      // Create an alert record
      const alertId = `alert_${uuidv4()}`;
      await prisma.$executeRaw`
        INSERT INTO "Alert" ("id","organizationId","incidentId","provider","payload","severity","receivedAt")
        VALUES (${alertId}, ${organizationId}, ${id}, ${detectionSource}, ${JSON.stringify({ title, description, indicators })}, ${severity}, ${now})
      `;

      // Enqueue a triage job
      await remediationQueue.add('triage', { incidentId: id, organizationId }, { attempts: 3, removeOnComplete: true });

      return { success: true, incidentId: id };
    } catch (error) {
      console.error('createIncident error:', error.message);
      return { success: false, error: error.message };
    }
  }

  async getIncident(incidentId) {
    try {
      const rows = await prisma.$queryRaw`
        SELECT * FROM "Incident" WHERE "id" = ${incidentId} LIMIT 1
      `;

      const incident = Array.isArray(rows) ? rows[0] : rows;
      if (!incident) return null;

      // fetch remediation tasks
      const tasks = await prisma.$queryRaw`
        SELECT * FROM "RemediationTask" WHERE "incidentId" = ${incidentId} ORDER BY "createdAt" ASC
      `;

      // fetch alerts
      const alerts = await prisma.$queryRaw`
        SELECT * FROM "Alert" WHERE "incidentId" = ${incidentId} ORDER BY "receivedAt" ASC
      `;

      incident.remediationTasks = tasks || [];
      incident.alerts = alerts || [];

      return incident;
    } catch (error) {
      console.error('getIncident error:', error.message);
      throw error;
    }
  }

  async listIncidents(organizationId, filter = {}) {
    try {
      const statusFilter = filter.status ? ` AND "status" = ${filter.status} ` : '';
      const rows = await prisma.$queryRaw`
        SELECT * FROM "Incident" WHERE "organizationId" = ${organizationId} ${statusFilter} ORDER BY "createdAt" DESC LIMIT ${filter.limit || 100}
      `;

      return rows || [];
    } catch (error) {
      console.error('listIncidents error:', error.message);
      throw error;
    }
  }

  async updateIncidentStatus(incidentId, newStatus) {
    try {
      const now = new Date();
      await prisma.$executeRaw`
        UPDATE "Incident" SET "status" = ${newStatus}, "updatedAt" = ${now} WHERE "id" = ${incidentId}
      `;

      return { success: true };
    } catch (error) {
      console.error('updateIncidentStatus error:', error.message);
      return { success: false, error: error.message };
    }
  }

  /**
   * Assign and run a playbook for an incident
   */
  async runPlaybookForIncident(incidentId, playbookId) {
    try {
      // Create remediation tasks for each step in the playbook
      const steps = await prisma.$queryRaw`
        SELECT * FROM "PlaybookStep" WHERE "playbookId" = ${playbookId} ORDER BY "sequence" ASC
      `;

      for (const step of steps) {
        const taskId = `task_${uuidv4()}`;
        await prisma.$executeRaw`
          INSERT INTO "RemediationTask" ("id","incidentId","playbookStepId","status","createdAt","updatedAt")
          VALUES (${taskId}, ${incidentId}, ${step.id}, 'pending', ${new Date()}, ${new Date()})
        `;

        // enqueue task
        await remediationQueue.add('execute-step', { taskId, incidentId, stepId: step.id, step }, { attempts: 3, removeOnComplete: true });
      }

      // mark incident assigned
      await this.updateIncidentStatus(incidentId, 'in_progress');

      return { success: true };
    } catch (error) {
      console.error('runPlaybookForIncident error:', error.message);
      return { success: false, error: error.message };
    }
  }
}

module.exports = new IncidentResponseService();
