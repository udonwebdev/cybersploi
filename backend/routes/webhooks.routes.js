const express = require('express');
const router = express.Router();
const crypto = require('crypto');

// In-memory webhook registry (in production, persist to DB)
const webhookRegistry = new Map();

const WebhookService = {
  subscribe(organizationId, url, events = ['incident.created', 'incident.resolved']) {
    const id = `webhook_${crypto.randomBytes(16).toString('hex')}`;
    webhookRegistry.set(id, {
      id,
      organizationId,
      url,
      events,
      active: true,
      createdAt: new Date(),
      failureCount: 0,
    });
    return id;
  },

  unsubscribe(webhookId) {
    return webhookRegistry.delete(webhookId);
  },

  async broadcast(event, organizationId, payload) {
    for (const [, webhook] of webhookRegistry) {
      if (webhook.organizationId === organizationId && webhook.events.includes(event) && webhook.active) {
        try {
          const signature = crypto
            .createHmac('sha256', process.env.WEBHOOK_SECRET || 'webhook-secret')
            .update(JSON.stringify(payload))
            .digest('hex');

          await fetch(webhook.url, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-Webhook-Signature': signature,
              'X-Webhook-Event': event,
            },
            body: JSON.stringify(payload),
            timeout: 10000,
          });

          webhook.failureCount = 0;
        } catch (err) {
          console.warn(`Webhook ${webhook.id} failed:`, err.message);
          webhook.failureCount++;
          if (webhook.failureCount >= 5) webhook.active = false;
        }
      }
    }
  },
};

/**
 * POST /
 * Subscribe to incident webhooks
 */
router.post('/', (req, res) => {
  try {
    const { url, events } = req.body;
    const organizationId = req.organizationId || req.body.organizationId || process.env.DEFAULT_ORG;

    if (!url) return res.status(400).json({ success: false, error: 'url required' });

    const webhookId = WebhookService.subscribe(organizationId, url, events);
    res.status(201).json({ success: true, webhookId });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /
 * List webhooks
 */
router.get('/', (req, res) => {
  try {
    const organizationId = req.organizationId || process.env.DEFAULT_ORG;
    const webhooks = Array.from(webhookRegistry.values()).filter(w => w.organizationId === organizationId);
    res.json({ success: true, webhooks });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * DELETE /:id
 * Unsubscribe
 */
router.delete('/:id', (req, res) => {
  try {
    const success = WebhookService.unsubscribe(req.params.id);
    res.json({ success: !!success });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = { router, WebhookService };
