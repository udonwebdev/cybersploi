import { SecurityAgent } from './agent-interface';
import { ReconAgent } from './recon-agent';
import { WebMappingAgent } from './web-mapping-agent';
import { AuthMatrixAgent } from './auth-matrix-agent';
import { RetestAgent } from './retest-agent';

export * from './agent-interface';
export * from './recon-agent';
export * from './web-mapping-agent';
export * from './auth-matrix-agent';
export * from './retest-agent';

export class AgentCoordinatorService {
  private static agents: Map<string, SecurityAgent> = new Map();

  static {
    this.registerAgent(new ReconAgent());
    this.registerAgent(new WebMappingAgent());
    this.registerAgent(new AuthMatrixAgent());
    this.registerAgent(new RetestAgent());
  }

  public static registerAgent(agent: SecurityAgent) {
    this.agents.set(agent.name, agent);
  }

  public static getAgent(name: string): SecurityAgent | undefined {
    return this.agents.get(name);
  }

  public static listAgents(): SecurityAgent[] {
    return Array.from(this.agents.values());
  }
}
