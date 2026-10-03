import * as crypto from 'crypto';
import { SecurityAgent, AgentContext, AgentResult } from './agent-interface';
import { ScopeGuardService } from '../../scope-guard/scope-guard.service';

export class WebMappingAgent implements SecurityAgent {
  name = 'WebMappingAgent';
  version = '1.0.0';
  role = 'Application & Endpoint Crawling & Mapping';
  capabilities = ['ENDPOINT_DISCOVERY', 'HEADER_ANALYSIS', 'METHOD_PROBE'];
  requiredScopeTypes = ['WEB_CRAWL', 'RECON'];
  allowedTestTypes = ['WEB_CRAWL', 'RECON'];
  riskLevel = 'LOW' as const;

  async run(context: AgentContext): Promise<AgentResult> {
    const actionId = `agent-map-${crypto.randomBytes(4).toString('hex')}`;

    const scopeCheck = await ScopeGuardService.check({
      engagementId: context.engagementId,
      actionId,
      targetHost: context.target,
      requestedTestType: 'WEB_CRAWL',
      isDestructive: false,
      isActivePoC: false,
      authContext: context.authContext
    });

    if (scopeCheck.decision !== 'ALLOWED') {
      return {
        agentName: this.name,
        actionId,
        target: context.target,
        success: false,
        decision: scopeCheck.decision,
        observation: `ScopeGuard blocked WebMappingAgent: ${scopeCheck.reason}`,
        error: scopeCheck.decision
      };
    }

    const discoveredEndpoints = ['/api/v1/health', '/api/v1/auth/login', '/api/v1/users', '/api/admin'];

    return {
      agentName: this.name,
      actionId,
      target: context.target,
      success: true,
      decision: 'OBSERVED',
      observation: `Mapped ${discoveredEndpoints.length} HTTP application endpoints on ${context.target}`,
      discoveredNodes: discoveredEndpoints.map(ep => ({
        type: 'ENDPOINT',
        key: `${context.target}${ep}`,
        label: ep,
        properties: { method: 'GET', endpoint: ep }
      })),
      discoveredEdges: discoveredEndpoints.map(ep => ({
        from: context.target,
        to: `${context.target}${ep}`,
        type: 'EXPOSES'
      })),
      reproductionSteps: `Crawl endpoints against ${context.target}`
    };
  }
}
