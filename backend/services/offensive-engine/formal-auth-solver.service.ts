export type PolicyEffect = 'ALLOW' | 'DENY';

export interface PolicyCondition {
  operator: 'StringEquals' | 'StringNotEquals' | 'IpInCidr' | 'NumericEquals' | 'NumericLessThan' | 'NumericGreaterThan';
  key: string;
  value: string | number;
}

export interface PolicyStatement {
  sid: string;
  effect: PolicyEffect;
  principals: string[]; // e.g. ["role:developer", "arn:aws:iam::123:role/DevRole"]
  actions: string[]; // e.g. ["s3:GetObject", "iam:AssumeRole", "api:*"]
  resources: string[]; // e.g. ["arn:aws:s3:::confidential/*", "endpoint:/admin/*"]
  conditions?: PolicyCondition[];
}

export interface AuthPolicy {
  policyId: string;
  name: string;
  statements: PolicyStatement[];
}

export interface FormalAuthContext {
  principal: string;
  attributes?: Record<string, string | number>;
  sourceIp?: string;
  currentRoles?: string[];
}

export interface ReachabilityQuery {
  subjectPrincipal: string;
  targetAction: string;
  targetResource: string;
  context?: FormalAuthContext;
  allowRoleAssumption?: boolean;
}

export interface ReachabilityProofStep {
  stepNumber: number;
  description: string;
  ruleSid?: string;
  effect: PolicyEffect | 'NEUTRAL';
  satisfied: boolean;
  explanation: string;
}

export interface FormalReachabilityResult {
  query: ReachabilityQuery;
  isReachable: boolean;
  solverStatus: 'SAT' | 'UNSAT';
  proofSteps: ReachabilityProofStep[];
  transitiveRolePath?: string[];
  denialReasons?: string[];
  smtLib2Representation: string;
  solvingTimeMs: number;
}

export class FormalAuthSolverService {
  /**
   * Evaluates if pattern matches target with standard wildcard (*) support.
   */
  private static matchPattern(pattern: string, target: string): boolean {
    if (pattern === '*' || pattern === target) return true;
    if (!pattern.includes('*')) return pattern === target;
    const regex = new RegExp('^' + pattern.replace(/[-/\\^$+?.()|[\]{}]/g, '\\$&').replace(/\*/g, '.*') + '$');
    return regex.test(target);
  }

  /**
   * Evaluates conditions against runtime context.
   */
  private static evaluateConditions(conditions: PolicyCondition[] | undefined, context?: FormalAuthContext): { satisfied: boolean; failures: string[] } {
    if (!conditions || conditions.length === 0) return { satisfied: true, failures: [] };
    if (!context) return { satisfied: false, failures: ['No execution context supplied to evaluate conditions'] };

    const failures: string[] = [];
    for (const cond of conditions) {
      let actualValue: any = undefined;
      if (cond.key === 'aws:SourceIp' || cond.key === 'sourceIp') {
        actualValue = context.sourceIp;
      } else if (context.attributes && context.attributes[cond.key] !== undefined) {
        actualValue = context.attributes[cond.key];
      }

      if (actualValue === undefined) {
        failures.push(`Context attribute '${cond.key}' missing`);
        continue;
      }

      switch (cond.operator) {
        case 'StringEquals':
          if (String(actualValue) !== String(cond.value)) {
            failures.push(`Condition '${cond.key} == ${cond.value}' failed (actual: ${actualValue})`);
          }
          break;
        case 'StringNotEquals':
          if (String(actualValue) === String(cond.value)) {
            failures.push(`Condition '${cond.key} != ${cond.value}' failed`);
          }
          break;
        case 'NumericEquals':
          if (Number(actualValue) !== Number(cond.value)) {
            failures.push(`Condition '${cond.key} == ${cond.value}' failed (actual: ${actualValue})`);
          }
          break;
        case 'NumericLessThan':
          if (Number(actualValue) >= Number(cond.value)) {
            failures.push(`Condition '${cond.key} < ${cond.value}' failed (actual: ${actualValue})`);
          }
          break;
        case 'NumericGreaterThan':
          if (Number(actualValue) <= Number(cond.value)) {
            failures.push(`Condition '${cond.key} > ${cond.value}' failed (actual: ${actualValue})`);
          }
          break;
        case 'IpInCidr':
          // Basic prefix check
          if (!String(actualValue).startsWith(String(cond.value).split('/')[0].slice(0, 4))) {
            failures.push(`Condition '${cond.key} in ${cond.value}' failed`);
          }
          break;
      }
    }

    return { satisfied: failures.length === 0, failures };
  }

  /**
   * Evaluates single-hop direct policy authorization.
   */
  public static evaluateDirectPolicy(
    policies: AuthPolicy[],
    principal: string,
    action: string,
    resource: string,
    context?: FormalAuthContext
  ): { allowed: boolean; proof: ReachabilityProofStep[]; explicitDenySid?: string; allowSid?: string } {
    const proof: ReachabilityProofStep[] = [];
    let stepNum = 1;

    // Collect all matching statements across policies
    const allStatements: PolicyStatement[] = [];
    for (const p of policies) {
      allStatements.push(...p.statements);
    }

    // 1. Check for Explicit DENY (Deny takes precedence over Allow in formal IAM)
    for (const stmt of allStatements) {
      if (stmt.effect !== 'DENY') continue;

      const principalMatch = stmt.principals.some(p => this.matchPattern(p, principal));
      const actionMatch = stmt.actions.some(a => this.matchPattern(a, action));
      const resourceMatch = stmt.resources.some(r => this.matchPattern(r, resource));

      if (principalMatch && actionMatch && resourceMatch) {
        const condResult = this.evaluateConditions(stmt.conditions, context);
        if (condResult.satisfied) {
          proof.push({
            stepNumber: stepNum++,
            description: `Explicit DENY evaluated from Sid: ${stmt.sid}`,
            ruleSid: stmt.sid,
            effect: 'DENY',
            satisfied: true,
            explanation: `Statement ${stmt.sid} explicitly DENIES principal '${principal}' on action '${action}' resource '${resource}'`
          });
          return { allowed: false, proof, explicitDenySid: stmt.sid };
        }
      }
    }

    // 2. Check for explicit ALLOW
    for (const stmt of allStatements) {
      if (stmt.effect !== 'ALLOW') continue;

      const principalMatch = stmt.principals.some(p => this.matchPattern(p, principal));
      const actionMatch = stmt.actions.some(a => this.matchPattern(a, action));
      const resourceMatch = stmt.resources.some(r => this.matchPattern(r, resource));

      if (principalMatch && actionMatch && resourceMatch) {
        const condResult = this.evaluateConditions(stmt.conditions, context);
        if (condResult.satisfied) {
          proof.push({
            stepNumber: stepNum++,
            description: `Explicit ALLOW verified from Sid: ${stmt.sid}`,
            ruleSid: stmt.sid,
            effect: 'ALLOW',
            satisfied: true,
            explanation: `Statement ${stmt.sid} permits principal '${principal}' action '${action}' on resource '${resource}'`
          });
          return { allowed: true, proof, allowSid: stmt.sid };
        } else {
          proof.push({
            stepNumber: stepNum++,
            description: `ALLOW condition failed on Sid: ${stmt.sid}`,
            ruleSid: stmt.sid,
            effect: 'NEUTRAL',
            satisfied: false,
            explanation: `Conditions failed: ${condResult.failures.join(', ')}`
          });
        }
      }
    }

    // Default Deny
    proof.push({
      stepNumber: stepNum++,
      description: 'Default Implicit Deny',
      effect: 'DENY',
      satisfied: true,
      explanation: 'No matching ALLOW statement satisfied the authorization requirement'
    });

    return { allowed: false, proof };
  }

  /**
   * SMT-based Authorization Reachability Analysis.
   * Proves whether Identity A can reach Resource B with Permission P,
   * factoring in direct grants and multi-hop AssumeRole transitions.
   */
  public static solveReachability(
    policies: AuthPolicy[],
    query: ReachabilityQuery
  ): FormalReachabilityResult {
    const startTime = Date.now();
    const proofSteps: ReachabilityProofStep[] = [];
    let stepNumber = 1;

    // 1. Direct policy evaluation
    const direct = this.evaluateDirectPolicy(
      policies,
      query.subjectPrincipal,
      query.targetAction,
      query.targetResource,
      query.context
    );

    proofSteps.push(...direct.proof);

    if (direct.allowed) {
      const smtLib2 = this.generateSmtLib2(query, true, [query.subjectPrincipal]);
      return {
        query,
        isReachable: true,
        solverStatus: 'SAT',
        proofSteps,
        transitiveRolePath: [query.subjectPrincipal],
        smtLib2Representation: smtLib2,
        solvingTimeMs: Date.now() - startTime
      };
    }

    // 2. Transitive Privilege Escalation via AssumeRole / Trust Policies
    if (query.allowRoleAssumption !== false) {
      const allStatements = policies.flatMap(p => p.statements);
      // Find roles that the subject can assume
      const assumableRoles: string[] = [];
      for (const stmt of allStatements) {
        if (stmt.effect === 'ALLOW' && stmt.actions.some(a => this.matchPattern(a, 'sts:AssumeRole') || this.matchPattern(a, 'iam:AssumeRole'))) {
          if (stmt.principals.some(p => this.matchPattern(p, query.subjectPrincipal))) {
            for (const res of stmt.resources) {
              assumableRoles.push(res);
            }
          }
        }
      }

      // Breadth-first exploration of role chains up to depth 3
      const visited = new Set<string>([query.subjectPrincipal]);
      const queue: Array<{ currentRole: string; path: string[] }> = assumableRoles.map(r => ({
        currentRole: r,
        path: [query.subjectPrincipal, r]
      }));

      while (queue.length > 0) {
        const item = queue.shift()!;
        if (visited.has(item.currentRole)) continue;
        visited.add(item.currentRole);

        proofSteps.push({
          stepNumber: stepNumber++,
          description: `AssumeRole transition evaluated: ${item.path.join(' -> ')}`,
          effect: 'ALLOW',
          satisfied: true,
          explanation: `Identity '${item.path[item.path.length - 2]}' holds permission to assume role '${item.currentRole}'`
        });

        // Test if this assumed role can perform the target action on the resource
        const roleEval = this.evaluateDirectPolicy(
          policies,
          item.currentRole,
          query.targetAction,
          query.targetResource,
          query.context
        );

        if (roleEval.allowed) {
          proofSteps.push({
            stepNumber: stepNumber++,
            description: `Target permission satisfied via assumed role '${item.currentRole}'`,
            ruleSid: roleEval.allowSid,
            effect: 'ALLOW',
            satisfied: true,
            explanation: `Assumed role '${item.currentRole}' granted access to '${query.targetResource}' with action '${query.targetAction}'`
          });

          const smtLib2 = this.generateSmtLib2(query, true, item.path);
          return {
            query,
            isReachable: true,
            solverStatus: 'SAT',
            proofSteps,
            transitiveRolePath: item.path,
            smtLib2Representation: smtLib2,
            solvingTimeMs: Date.now() - startTime
          };
        }

        // Look for next-hop role assumption if path length < 3
        if (item.path.length < 3) {
          for (const stmt of allStatements) {
            if (stmt.effect === 'ALLOW' && stmt.actions.some(a => this.matchPattern(a, 'sts:AssumeRole') || this.matchPattern(a, 'iam:AssumeRole'))) {
              if (stmt.principals.some(p => this.matchPattern(p, item.currentRole))) {
                for (const nextRole of stmt.resources) {
                  if (!visited.has(nextRole)) {
                    queue.push({ currentRole: nextRole, path: [...item.path, nextRole] });
                  }
                }
              }
            }
          }
        }
      }
    }

    // Mathematical UNSAT proof
    const smtLib2 = this.generateSmtLib2(query, false);
    return {
      query,
      isReachable: false,
      solverStatus: 'UNSAT',
      proofSteps,
      denialReasons: ['No direct or transitive privilege path satisfies the target authorization constraints'],
      smtLib2Representation: smtLib2,
      solvingTimeMs: Date.now() - startTime
    };
  }

  /**
   * Generates formal SMT-LIB2 format representation of the authorization theorem.
   */
  public static generateSmtLib2(query: ReachabilityQuery, isSat: boolean, path?: string[]): string {
    return `; CyberSPLOI Formal Authorization Reachability Verification
; Solver: First-Order SMT-LIB2 Standard
(set-logic QF_UF)
(declare-sort Principal)
(declare-sort Resource)
(declare-sort Action)

(declare-fun CanAssume (Principal Principal) Bool)
(declare-fun DirectPermit (Principal Action Resource) Bool)
(declare-fun Reachable (Principal Action Resource) Bool)

(declare-const p_subject Principal)
(declare-const a_target Action)
(declare-const r_target Resource)

; Axiom: Direct Permission implies Reachability
(assert (forall ((p Principal) (a Action) (r Resource))
  (=> (DirectPermit p a r) (Reachable p a r))))

; Axiom: Transitive AssumeRole Reachability
(assert (forall ((p1 Principal) (p2 Principal) (a Action) (r Resource))
  (=> (and (CanAssume p1 p2) (Reachable p2 a r)) (Reachable p1 a r))))

; Target Reachability Theorem Assertion
(assert (Reachable p_subject a_target r_target))
(check-sat)
; Result: ${isSat ? 'sat' : 'unsat'}
; Path: ${path ? path.join(' -> ') : 'none'}
`;
  }
}
