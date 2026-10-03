const axios = require('axios');

class AlertingService {
  constructor(config = {}) {
    this.name = 'Alerting Service';
    this.webhookUrl = process.env.ALERT_WEBHOOK_URL || config.webhookUrl || null;
    this.suppressDelivery = process.env.ALERT_SUPPRESS_DELIVERY === 'true' || config.suppressDelivery || false;
  }

  async sendWebhook(payload) {
    if (!this.webhookUrl || this.suppressDelivery) {
      console.log('Alerting (simulated):', payload);
      return { success: true, simulated: true };
    }

    try {
      const res = await axios.post(this.webhookUrl, payload, { timeout: 5000 });
      return { success: true, status: res.status, data: res.data };
    } catch (error) {
      console.error('sendWebhook error:', error.message);
      return { success: false, error: error.message };
    }
  }

  async notifyIncident(incident) {
    const payload = {
      id: incident.id,
      title: incident.title,
      severity: incident.severity,
      status: incident.status,
      detectedAt: incident.detectedAt,
      indicators: incident.indicators || [],
    };

    return await this.sendWebhook({ type: 'incident.created', payload });
  }
}

module.exports = new AlertingService();
