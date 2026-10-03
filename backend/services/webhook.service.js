/**
 * Webhook System
 * Sends real-time alerts to Slack, Teams, Email, etc.
 */

const axios = require('axios');
const config = require('../config');

class WebhookService {
  constructor() {
    this.hooks = {
      slack: config.SLACK_WEBHOOK_URL,
      teams: config.TEAMS_WEBHOOK_URL,
      custom: config.CUSTOM_WEBHOOKS || [],
    };
  }

  async sendSlackAlert(data) {
    if (!this.hooks.slack) return { error: 'Slack webhook not configured' };

    try {
      const message = {
        text: `🚨 Security Alert: ${data.title}`,
        attachments: [
          {
            color: this.getSeverityColor(data.severity),
            fields: [
              { title: 'Severity', value: data.severity.toUpperCase(), short: true },
              { title: 'Type', value: data.type, short: true },
              { title: 'Description', value: data.description, short: false },
              { title: 'Asset', value: data.asset_id, short: true },
              { title: 'CVSS Score', value: data.cvss_score || 'N/A', short: true },
            ],
            actions: [
              {
                type: 'button',
                text: 'View Details',
                url: `${config.FRONTEND_URL}/findings/${data.id}`,
              },
            ],
          },
        ],
      };

      await axios.post(this.hooks.slack, message);
      console.log('Slack alert sent:', data.title);
      return { success: true };
    } catch (error) {
      console.error('Slack webhook error:', error.message);
      return { error: error.message };
    }
  }

  async sendTeamsAlert(data) {
    if (!this.hooks.teams) return { error: 'Teams webhook not configured' };

    try {
      const message = {
        '@type': 'MessageCard',
        '@context': 'https://schema.org/extensions',
        summary: `Security Alert: ${data.title}`,
        themeColor: this.getSeverityHexColor(data.severity),
        sections: [
          {
            activityTitle: `🚨 ${data.title}`,
            activitySubtitle: `Severity: ${data.severity.toUpperCase()}`,
            facts: [
              { name: 'Type', value: data.type },
              { name: 'Description', value: data.description },
              { name: 'Asset', value: data.asset_id },
              { name: 'CVSS Score', value: data.cvss_score || 'N/A' },
            ],
            markdown: true,
          },
        ],
        potentialAction: [
          {
            '@type': 'OpenUri',
            name: 'View in CYBERSPLOI',
            targets: [
              {
                os: 'default',
                uri: `${config.FRONTEND_URL}/findings/${data.id}`,
              },
            ],
          },
        ],
      };

      await axios.post(this.hooks.teams, message);
      console.log('Teams alert sent:', data.title);
      return { success: true };
    } catch (error) {
      console.error('Teams webhook error:', error.message);
      return { error: error.message };
    }
  }

  async sendEmailAlert(data) {
    try {
      // Implementation depends on email service (SendGrid, AWS SES, etc.)
      console.log('Email alert would be sent:', data.title);
      return { success: true };
    } catch (error) {
      console.error('Email webhook error:', error.message);
      return { error: error.message };
    }
  }

  async triggerWebhooks(event, data) {
    

    if (data.severity === 'critical' || data.severity === 'high') {
      await this.sendSlackAlert(data);
      await this.sendTeamsAlert(data);
    }

    // Send to custom webhooks
    for (const hook of this.hooks.custom) {
      try {
        await axios.post(hook, {
          event,
          timestamp: new Date(),
          data,
        });
      } catch (error) {
        console.error(`Custom webhook error: ${hook}`, error.message);
      }
    }

    return { success: true, webhooks_triggered: 2 + this.hooks.custom.length };
  }

  getSeverityColor(severity) {
    const colors = {
      critical: 'danger',
      high: 'warning',
      medium: 'attention',
      low: 'good',
    };
    return colors[severity] || 'good';
  }

  getSeverityHexColor(severity) {
    const colors = {
      critical: '#cc0000',
      high: '#ff9900',
      medium: '#ffcc00',
      low: '#00cc00',
    };
    return colors[severity] || '#0099ff';
  }

  async registerCustomHook(url) {
    this.hooks.custom.push(url);
    console.log('Custom webhook registered:', url);
    return { success: true, total_hooks: this.hooks.custom.length };
  }
}

module.exports = new WebhookService();
