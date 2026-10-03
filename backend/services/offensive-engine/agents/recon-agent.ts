import * as crypto from 'crypto';
import { SecurityAgent, AgentContext, AgentResult } from './agent-interface';
import { ScopeGuardService } from '../../scope-guard/scope-guard.service';
import { CapabilityRegistryService } from '../capability-registry.service';

export class ReconAgent implements SecurityAgent {
  name = 'ReconAgent';
  version = '1.0.0';
  role = 'Domain & Infrastructure Reconnaissance';
  capabilities = ['DNS_ENUM', 'PORT_SCAN', 'BANNER_AUDIT'];
  requiredScopeTypes = ['RECON', 'PORT_SCAN'];
  allowedTestTypes = ['RECON', 'PORT_SCAN'];
  riskLevel = 'PASSIVE' as const;

  async run(context: AgentContext): Promise<AgentResult> {
    const actionId = `agent-recon-${crypto.randomBytes(4).toString('hex')}`;

    // 1. Gate execution with ScopeGuard
    const scopeCheck = await ScopeGuardService.check({
      engagementId: context.engagementId,
      actionId,
      targetHost: context.target,
      requestedTestType: 'RECON',
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
        observation: `ScopeGuard blocked ReconAgent: ${scopeCheck.reason}`,
        error: scopeCheck.decision
      };
    }

    // 2. Select and invoke adapter
    const adapter = CapabilityRegistryService.getAdapter('python_recon_worker');
    if (!adapter) {
      return {
        agentName: this.name,
        actionId,
        target: context.target,
        success: false,
        decision: 'FAILED',
        observation: 'PythonReconWorkerAdapter not registered',
        error: 'ADAPTER_NOT_FOUND'
      };
    }

    const res = await adapter.execute({
      actionId,
      engagementId: context.engagementId,
      target: context.target,
      testType: 'RECON',
      operation: 'RECON_AUDIT',
      timeoutMs: 15000
    });

    return {
      agentName: this.name,
      actionId,
      target: context.target,
      success: res.success,
      decision: res.decision,
      observation: res.observation,
      evidenceData: res.rawOutput,
      discoveredNodes: [
        { type: 'IP', key: context.target, label: context.target },
        { type: 'PORT', key: `${context.target}:80`, label: 'Port 80/tcp' },
        { type: 'PORT', key: `${context.target}:443`, label: 'Port 443/tcp' }
      ],
      discoveredEdges: [
        { from: context.target, to: `${context.target}:80`, type: 'EXPOSES' },
        { from: context.target, to: `${context.target}:443`, type: 'EXPOSES' }
      ],
      reproductionSteps: res.reproductionSteps
    };
  }
}
