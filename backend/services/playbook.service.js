const prisma = require('../config/database');
const { v4: uuidv4 } = require('uuid');

class PlaybookService {
  constructor() {
    this.name = 'Playbook Service';
  }

  async createPlaybook({ organizationId, name, description = '', createdBy = null }) {
    const id = `pb_${uuidv4()}`;
    const now = new Date();

    try {
      await prisma.$executeRaw`
        INSERT INTO "Playbook" ("id","organizationId","name","description","isActive","createdBy","createdAt","updatedAt")
        VALUES (${id}, ${organizationId}, ${name}, ${description}, true, ${createdBy}, ${now}, ${now})
      `;

      return { success: true, playbookId: id };
    } catch (error) {
      console.error('createPlaybook error:', error.message);
      return { success: false, error: error.message };
    }
  }

  async getPlaybook(playbookId) {
    try {
      const rows = await prisma.$queryRaw`
        SELECT * FROM "Playbook" WHERE "id" = ${playbookId} LIMIT 1
      `;
      const playbook = Array.isArray(rows) ? rows[0] : rows;
      if (!playbook) return null;

      const steps = await prisma.$queryRaw`
        SELECT * FROM "PlaybookStep" WHERE "playbookId" = ${playbookId} ORDER BY "sequence" ASC
      `;

      playbook.steps = steps || [];
      return playbook;
    } catch (error) {
      console.error('getPlaybook error:', error.message);
      throw error;
    }
  }

  async addStep(playbookId, { sequence = 0, action, parameters = {}, timeoutMs = 60000 }) {
    const id = `pbs_${uuidv4()}`;
    try {
      await prisma.$executeRaw`
        INSERT INTO "PlaybookStep" ("id","playbookId","sequence","action","parameters","timeoutMs","createdAt","updatedAt")
        VALUES (${id}, ${playbookId}, ${sequence}, ${action}, ${JSON.stringify(parameters)}, ${timeoutMs}, ${new Date()}, ${new Date()})
      `;

      return { success: true, stepId: id };
    } catch (error) {
      console.error('addStep error:', error.message);
      return { success: false, error: error.message };
    }
  }

  async listPlaybooks(organizationId) {
    try {
      const rows = await prisma.$queryRaw`
        SELECT * FROM "Playbook" WHERE "organizationId" = ${organizationId} ORDER BY "createdAt" DESC
      `;
      return rows || [];
    } catch (error) {
      console.error('listPlaybooks error:', error.message);
      throw error;
    }
  }
}

module.exports = new PlaybookService();
