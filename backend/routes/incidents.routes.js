const express = require('express');
const router = express.Router();

const IncidentService = require('../services/incident-response.service');
const PlaybookService = require('../services/playbook.service');
const AlertingService = require('../services/alerting.service');

/**
 * POST /
 * Create a new incident
 */
router.post('/', async (req, res) => {
  try {
    const { title, description, severity, detectionSource, indicators, metadata, detectedAt } = req.body;
    const organizationId = req.organizationId || req.body.organizationId || process.env.DEFAULT_ORG || 'org_default';

    const result = await IncidentService.createIncident({
      organizationId,
      title,
      description,
      severity,
      detectionSource,
      indicators,
      metadata,
      detectedAt,
      createdBy: req.userId || null,
    });

    if (!result.success) return res.status(500).json({ success: false, error: result.error });

    // notify via webhook
    try {
      const incident = await IncidentService.getIncident(result.incidentId);
      await AlertingService.notifyIncident(incident);
    } catch (err) {
      console.warn('Alerting failed (non-fatal):', err.message);
    }

    res.status(201).json({ success: true, incidentId: result.incidentId });
  } catch (error) {
    console.error('Create incident error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /
 * List incidents for organization
 */
router.get('/', async (req, res) => {
  try {
    const organizationId = req.organizationId || req.query.organizationId || process.env.DEFAULT_ORG || 'org_default';
    const filter = { status: req.query.status, limit: parseInt(req.query.limit) || 100 };
    const rows = await IncidentService.listIncidents(organizationId, filter);
    res.json({ success: true, incidents: rows });
  } catch (error) {
    console.error('List incidents error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /:id
 * Get a single incident
 */
router.get('/:id', async (req, res) => {
  try {
    const incident = await IncidentService.getIncident(req.params.id);
    if (!incident) return res.status(404).json({ success: false, error: 'Incident not found' });
    res.json({ success: true, incident });
  } catch (error) {
    console.error('Get incident error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /:id/run-playbook
 * Run a playbook against an incident
 */
router.post('/:id/run-playbook', async (req, res) => {
  try {
    const incidentId = req.params.id;
    const { playbookId } = req.body;

    if (!playbookId) return res.status(400).json({ success: false, error: 'playbookId required' });

    const result = await IncidentService.runPlaybookForIncident(incidentId, playbookId);
    if (!result.success) return res.status(500).json({ success: false, error: result.error });

    res.json({ success: true, message: 'Playbook started' });
  } catch (error) {
    console.error('Run playbook error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============ Playbook endpoints ============

/**
 * POST /playbooks
 * Create playbook
 */
router.post('/playbooks', async (req, res) => {
  try {
    const { name, description } = req.body;
    const organizationId = req.organizationId || req.body.organizationId || process.env.DEFAULT_ORG || 'org_default';

    const result = await PlaybookService.createPlaybook({ organizationId, name, description, createdBy: req.userId || null });
    if (!result.success) return res.status(500).json({ success: false, error: result.error });

    res.status(201).json({ success: true, playbookId: result.playbookId });
  } catch (error) {
    console.error('Create playbook error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /playbooks
 * List playbooks
 */
router.get('/playbooks', async (req, res) => {
  try {
    const organizationId = req.organizationId || req.query.organizationId || process.env.DEFAULT_ORG || 'org_default';
    const rows = await PlaybookService.listPlaybooks(organizationId);
    res.json({ success: true, playbooks: rows });
  } catch (error) {
    console.error('List playbooks error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /playbooks/:id
 * Get playbook with steps
 */
router.get('/playbooks/:id', async (req, res) => {
  try {
    const pb = await PlaybookService.getPlaybook(req.params.id);
    if (!pb) return res.status(404).json({ success: false, error: 'Playbook not found' });
    res.json({ success: true, playbook: pb });
  } catch (error) {
    console.error('Get playbook error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /playbooks/:id/steps
 * Add a step to a playbook
 */
router.post('/playbooks/:id/steps', async (req, res) => {
  try {
    const playbookId = req.params.id;
    const { sequence, action, parameters, timeoutMs } = req.body;

    const result = await PlaybookService.addStep(playbookId, { sequence, action, parameters, timeoutMs });
    if (!result.success) return res.status(500).json({ success: false, error: result.error });

    res.status(201).json({ success: true, stepId: result.stepId });
  } catch (error) {
    console.error('Add step error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
