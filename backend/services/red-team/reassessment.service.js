/**
 * Adaptive Reassessment & Blind-Spot Resolution Engine
 * Conducts second-pass adaptive testing for unresolved hypotheses,
 * audits weak-confidence conclusions, and dynamically probes identified blind spots.
 * This ensures the Ultra-Deep assessment does not perform a single shallow pass.
 */

const axios = require('axios');
const net = require('net');
const SafetyPolicyService = require('./safety-policy.service');

class ReassessmentService {
  /**
   * Execute adaptive self-reassessment and retesting
   */
  static async executeReassessment({
    host,
    scope,
    hypotheses,
    blindSpots,
    appData
  }) {
    const retestedHypotheses = [];
    const resolvedCount = { verified: 0, rejected: 0, remainedInconclusive: 0 };
    const adaptiveDiscoveries = [];

    // 1. Re-evaluate Inconclusive or Low-Confidence Hypotheses
    for (const hypo of hypotheses) {
      if (hypo.status === 'INCONCLUSIVE' || (hypo.currentConfidence >= 0.3 && hypo.currentConfidence <= 0.7)) {
        const retestResult = await this.retestHypothesis(hypo, host, scope);
        retestedHypotheses.push(retestResult);

        if (retestResult.status === 'VERIFIED') resolvedCount.verified++;
        else if (retestResult.status === 'REJECTED') resolvedCount.rejected++;
        else resolvedCount.remainedInconclusive++;
      } else {
        retestedHypotheses.push(hypo);
      }
    }

    // 2. Adaptive Investigation of Discovered Blind Spots
    // If there were unexamined API paths discovered during mapping, conduct secondary authorized probes
    if (appData && appData.discoveredEndpoints) {
      const unprobedEndpoints = appData.discoveredEndpoints.filter(ep => ep.type === 'exposed_api_schema' || ep.type === 'robots_file');
      
      for (const ep of unprobedEndpoints) {
        if (ep.type === 'robots_file') {
          // Parse robots.txt for disallowed routes that are in scope
          const parsedDisallowed = this.extractRobotsPaths(ep.snippet || '');
          for (const disPath of parsedDisallowed.slice(0, 3)) {
            const fullUrl = `${appData.baseUrl}${disPath}`;
            const safety = SafetyPolicyService.validateAction({ target: fullUrl, path: disPath, method: 'GET' }, scope);
            if (!safety.allowed) continue;

            try {
              const res = await axios.get(fullUrl, {
                timeout: 2500,
                validateStatus: () => true,
                headers: { 'User-Agent': 'CyberSploi-Authorized-RedTeam/3.0 (Adaptive-Retest)' }
              });

              if (res.status === 200 && res.data) {
                adaptiveDiscoveries.push({
                  path: disPath,
                  source: 'robots_reassessment',
                  statusCode: res.status,
                  note: 'Sensitive disallowed path from robots.txt confirmed accessible without authorization'
                });
              }
            } catch (err) {}
          }
        }
      }
    }

    return {
      updatedHypotheses: retestedHypotheses,
      resolvedCount,
      adaptiveDiscoveries,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Secondary retest probe for an individual hypothesis
   */
  static async retestHypothesis(hypo, host, scope) {
    const updated = { ...hypo };
    updated.retestAttempts = (updated.retestAttempts || 0) + 1;

    try {
      if (hypo.category === 'network_service') {
        const port = hypo.observedEvidence?.port || parseInt(hypo.targetEndpoint?.split(':')[1] || '0');
        if (port > 0) {
          const socketCheck = await this.probeSocketWithExtendedTimeout(host, port, 2500);
          if (socketCheck.open) {
            updated.status = 'VERIFIED';
            updated.currentConfidence = 0.99;
            updated.evidence = JSON.stringify({
              repeatable: true,
              confirmedOnRetest: true,
              port,
              banner: socketCheck.banner || 'Confirmed live TCP listener',
              timestamp: new Date().toISOString()
            });
            updated.verifiedAt = new Date();
          } else {
            updated.status = 'REJECTED';
            updated.currentConfidence = 0.1;
            updated.rejectionReason = `Retest confirmation failed: Port ${port} did not respond during secondary extended-timeout probe.`;
            updated.rejectedAt = new Date();
          }
        }
      } else if (hypo.targetEndpoint && hypo.targetEndpoint.startsWith('http')) {
        const safety = SafetyPolicyService.validateAction({ target: hypo.targetEndpoint, method: 'GET' }, scope);
        if (!safety.allowed) {
          updated.status = 'REJECTED';
          updated.rejectionReason = `Retest blocked: Target endpoint failed scope validation (${safety.reason})`;
          return updated;
        }

        const res = await axios.get(hypo.targetEndpoint, {
          timeout: 3500,
          validateStatus: () => true,
          headers: { 'User-Agent': 'CyberSploi-Authorized-RedTeam/3.0 (Secondary-Verification)' }
        });

        if (res.status === 200 && res.data) {
          updated.status = 'VERIFIED';
          updated.currentConfidence = 0.97;
          updated.evidence = JSON.stringify({
            confirmedOnRetest: true,
            statusCode: res.status,
            retestTimestamp: new Date().toISOString()
          });
          updated.verifiedAt = new Date();
        } else if (res.status === 404 || res.status === 403 || res.status === 401) {
          updated.status = 'REJECTED';
          updated.currentConfidence = 0.05;
          updated.rejectionReason = `Retest disproved hypothesis: Secondary probe returned HTTP ${res.status}`;
          updated.rejectedAt = new Date();
        }
      }
    } catch (err) {
      updated.rejectionReason = `Retest encountered timeout/network error: ${err.message}`;
    }

    return updated;
  }

  /**
   * Helper: Probe TCP socket with extended timeout
   */
  static probeSocketWithExtendedTimeout(host, port, timeout = 2500) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(timeout);
      let banner = '';

      socket.on('connect', () => {
        socket.destroy();
        resolve({ open: true, banner });
      });
      socket.on('data', (d) => {
        banner += d.toString('utf8', 0, 100);
        socket.destroy();
        resolve({ open: true, banner });
      });
      socket.on('timeout', () => {
        socket.destroy();
        resolve({ open: false });
      });
      socket.on('error', () => {
        socket.destroy();
        resolve({ open: false });
      });
      try {
        socket.connect(port, host);
      } catch (e) {
        resolve({ open: false });
      }
    });
  }

  /**
   * Parse robots.txt content to identify disallowed paths
   */
  static extractRobotsPaths(robotsContent) {
    if (!robotsContent || typeof robotsContent !== 'string') return [];
    const lines = robotsContent.split('\n');
    const paths = [];
    for (const line of lines) {
      const match = line.match(/^Disallow:\s*([^\s#]+)/i);
      if (match && match[1] && match[1] !== '/') {
        paths.push(match[1].trim());
      }
    }
    return paths;
  }
}

module.exports = ReassessmentService;
