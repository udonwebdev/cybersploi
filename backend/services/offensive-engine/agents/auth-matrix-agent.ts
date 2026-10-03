import * as crypto from 'crypto';
import { SecurityAgent, AgentContext, AgentResult } from './agent-interface';
import { ScopeGuardService } from '../../scope-guard/scope-guard.service';
import { AuthMatrixService } from '../auth-matrix.service';

export class AuthMatrixAgent implements SecurityAgent {
  name = 'AuthMatrixAgent';
  version = '1.0.0';
  role = 'Multi-Role Authorization & IDOR Auditor';
  capabilities = ['ROLE_PERMUTATION', 'IDOR_TEST', 'PRIV_ESC_CHECK'];
  requiredScopeTypes = ['AUTH_TEST', 'AUTH', 'IDOR'];
  allowedTestTypes = ['AUTH_TEST', 'AUTH', 'IDOR'];
  riskLevel = 'MEDIUM' as const;

  async run(context: AgentContext): Promise<AgentResult> {
    const actionId = `agent-auth-${crypto.randomBytes(4).toString('hex')}`;

    const scopeCheck = await ScopeGuardService.check({
      engagementId: context.engagementId,
      actionId,
      targetHost: context.target,
      requestedTestType: 'AUTH_TEST',
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
        observation: `ScopeGuard blocked AuthMatrixAgent: ${scopeCheck.reason}`,
        error: scopeCheck.decision
      };
    }

    const op = context.parameters?.operation || 'GET /api/v1/users/admin-data';
    const role = context.parameters?.role || 'GUEST';

    const evalResult = await AuthMatrixService.evaluateAccess({
      engagementId: context.engagementId,
      operation: op,
      role,
      declaredExpected: 'DENIED',
      observed: context.parameters?.observed || 'DENIED',
      target: context.target
    });

    return {
      agentName: this.name,
      actionId,
      target: context.target,
      success: true,
      decision: evalResult.result === 'DISCREPANCY' ? 'DISCREPANCY_FOUND' : 'MATCH',
      observation: `Auth evaluation for ${role} on ${op}: Result = ${evalResult.result}`,
      discoveredNodes: [
        { type: 'ROLE', key: role, label: `Role: ${role}` },
        { type: 'ENDPOINT', key: op, label: op }
      ],
      discoveredEdges: [
        { from: role, to: op, type: evalResult.result === 'DISCREPANCY' ? 'AUTHORIZES' : 'DISPROVES' }
      ],
      reproductionSteps: `Execute ${op} with Role: ${role}`
    };
  }
}
