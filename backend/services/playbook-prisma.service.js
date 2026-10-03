const prisma = require('../config/database');
const { v4: uuidv4 } = require('uuid');

class PlaybookServicePrisma {
  constructor() {
    this.name = 'Playbook Service (Prisma)';
  }

  async createPlaybook({ organizationId, name, description = '', createdBy = null }) {
    const id = `pb_${uuidv4()}`;

    try {
      const playbook = await prisma.playbook.create({
        data: {
          id,
          organizationId,
          name,
          description,
          isActive: true,
          createdBy,
        },
      });

      return { success: true, playbookId: id };
    } catch (error) {
      console.error('createPlaybook error:', error.message);
      return { success: false, error: error.message };
    }
  }

  async getPlaybook(playbookId) {
    try {
      const playbook = await prisma.playbook.findUnique({
        where: { id: playbookId },
        include: { steps: { orderBy: { sequence: 'asc' } } },
      });

      if (!playbook) return null;

      return {
        ...playbook,
        steps: playbook.steps.map(step => ({
          ...step,
          parameters: step.parameters ? JSON.parse(step.parameters) : {},
        })),
      };
    } catch (error) {
      console.error('getPlaybook error:', error.message);
      throw error;
    }
  }

  async addStep(playbookId, { sequence = 0, action, parameters = {}, timeoutMs = 60000 }) {
    const id = `pbs_${uuidv4()}`;
    try {
      const step = await prisma.playbookStep.create({
        data: {
          id,
          playbookId,
          sequence,
          action,
          parameters: JSON.stringify(parameters),
          timeoutMs,
        },
      });

      return { success: true, stepId: id };
    } catch (error) {
      console.error('addStep error:', error.message);
      return { success: false, error: error.message };
    }
  }

  async listPlaybooks(organizationId) {
    try {
      const playbooks = await prisma.playbook.findMany({
        where: { organizationId },
        include: { steps: { select: { id: true, sequence: true, action: true } } },
        orderBy: { createdAt: 'desc' },
      });

      return playbooks;
    } catch (error) {
      console.error('listPlaybooks error:', error.message);
      throw error;
    }
  }
}

module.exports = new PlaybookServicePrisma();
