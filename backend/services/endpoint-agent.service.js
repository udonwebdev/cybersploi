const axios = require('axios');

class EndpointAgentService {
  constructor() {
    this.name = 'Endpoint Agent Service';
    this.simulate = process.env.ENDPOINT_AGENT_SIMULATE === 'true' || true; // default to simulate for safety
    this.defaultTimeout = 15000;
  }

  async executeAction(endpointIdOrHost, action, params = {}) {
    try {
      if (this.simulate) {
        console.log(`Simulating endpoint action ${action} on ${endpointIdOrHost}`, params);
        return { success: true, simulated: true, message: `Simulated ${action}` };
      }

      // endpointIdOrHost can be hostname or an id we resolve here; keep simple map env var
      const base = process.env.ENDPOINT_AGENT_BASE_URL || `http://${endpointIdOrHost}`;
      const url = `${base}/api/agent/action`;
      const res = await axios.post(url, { action, params }, { timeout: params.timeoutMs || this.defaultTimeout });
      return { success: true, status: res.status, data: res.data };
    } catch (error) {
      console.error('executeAction error:', error.message);
      return { success: false, error: error.message };
    }
  }
}

module.exports = new EndpointAgentService();
