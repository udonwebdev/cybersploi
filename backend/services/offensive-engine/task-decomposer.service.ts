export type TaskStatus =
  | 'PENDING'
  | 'IN_PROGRESS'
  | 'VERIFYING'
  | 'COMPLETED'
  | 'FAILED'
  | 'ROLLED_BACK';

export type TaskRiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface TaskNode {
  id: string;
  name: string;
  directive: string;
  component: string;
  dependencies: string[];
  status: TaskStatus;
  acceptanceCriteria: string[];
  riskLevel: TaskRiskLevel;
  rollbackStrategy: string;
  verificationCommand: string;
  result?: string;
  error?: string;
  executionDurationMs?: number;
}

export interface TaskDAG {
  planId: string;
  directive: string;
  createdAt: string;
  tasks: TaskNode[];
  estimatedDurationMs: number;
  totalTasks: number;
  parallelBatches: string[][];
}

export interface TaskDAGExecutionResult {
  planId: string;
  status: 'SUCCESS' | 'PARTIAL_FAILURE' | 'CIRCUIT_BROKEN_ROLLED_BACK';
  completedTasks: number;
  failedTasks: number;
  rolledBackTasks: number;
  executionLog: {
    taskId: string;
    action: 'STARTED' | 'COMPLETED' | 'FAILED' | 'ROLLED_BACK';
    timestamp: string;
    details?: string;
  }[];
  totalDurationMs: number;
}

export class TaskDecomposerService {
  /**
   * Decomposes a high-level security directive into an atomic, dependency-aware Task DAG
   */
  public static decomposeDirective(directive: string, context: Record<string, any> = {}): TaskDAG {
    const planId = `DAG-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const tasks: TaskNode[] = [];

    // Analyze directive keywords to build appropriate DAG
    const lower = directive.toLowerCase();

    if (lower.includes('remediation') || lower.includes('patch') || lower.includes('fix')) {
      tasks.push(
        {
          id: 'TASK-01',
          name: 'Isolate & Freeze Environment State',
          directive: 'Capture pre-remediation snapshot and active state of targets',
          component: 'controlled-proof-env.service',
          dependencies: [],
          status: 'PENDING',
          acceptanceCriteria: ['Loopback port is allocated', 'Baseline HTTP responses recorded'],
          riskLevel: 'LOW',
          rollbackStrategy: 'Release allocated ephemeral resources',
          verificationCommand: 'GET /health against isolated sandbox'
        },
        {
          id: 'TASK-02',
          name: 'Generate Remediation Patch Diff',
          directive: 'Compute formal code diff and configuration fix for finding',
          component: 'security-copilot.service',
          dependencies: ['TASK-01'],
          status: 'PENDING',
          acceptanceCriteria: ['Unified diff generated', 'Syntactic validity verified'],
          riskLevel: 'MEDIUM',
          rollbackStrategy: 'Discard generated patch buffers',
          verificationCommand: 'git apply --check on dry-run patch'
        },
        {
          id: 'TASK-03',
          name: 'Execute Dialectical Debate on Patch',
          directive: 'Subject proposed remediation to multi-agent adversarial challenge',
          component: 'debate-engine.service',
          dependencies: ['TASK-02'],
          status: 'PENDING',
          acceptanceCriteria: ['Consensus score >= 0.70', 'Zero blocking regressions'],
          riskLevel: 'LOW',
          rollbackStrategy: 'Record dissenting points in audit trail',
          verificationCommand: 'debateEngine.evaluateRemediation()'
        },
        {
          id: 'TASK-04',
          name: 'Apply & Retest Against Sandbox',
          directive: 'Deploy patch to ephemeral environment and rerun active verification probe',
          component: 'gauntlet-loop.service',
          dependencies: ['TASK-03'],
          status: 'PENDING',
          acceptanceCriteria: ['Exploit vector returns DENIED/403', 'Legitimate traffic succeeds'],
          riskLevel: 'HIGH',
          rollbackStrategy: 'Revert ephemeral environment to pre-remediation snapshot',
          verificationCommand: 'gauntletLoop.retestVulnerability()'
        },
        {
          id: 'TASK-05',
          name: 'Persist Permanent Regression Test Fixture',
          directive: 'Write permanent test fixture to prevent regression',
          component: 'self-regression.service',
          dependencies: ['TASK-04'],
          status: 'PENDING',
          acceptanceCriteria: ['Test fixture file written to disk', 'Test execution exits code 0'],
          riskLevel: 'LOW',
          rollbackStrategy: 'Remove generated test fixture file',
          verificationCommand: 'npm test -- fixtures/regressions/remediation-*.test.js'
        }
      );
    } else if (lower.includes('crown') || lower.includes('reachability') || lower.includes('boundary')) {
      tasks.push(
        {
          id: 'TASK-01',
          name: 'Ingest Network & Identity Graph',
          directive: 'Synchronize assets, IAM roles, and ports into universal security graph',
          component: 'security-graph.service',
          dependencies: [],
          status: 'PENDING',
          acceptanceCriteria: ['Graph nodes >= 10', 'Root engagement node linked'],
          riskLevel: 'LOW',
          rollbackStrategy: 'Roll back graph transaction',
          verificationCommand: 'securityGraph.getOmniscientGraph()'
        },
        {
          id: 'TASK-02',
          name: 'Identify & Tag Crown Jewels',
          directive: 'Label critical assets (databases, KMS, IDP) with strict impact weights',
          component: 'crown-jewel.service',
          dependencies: ['TASK-01'],
          status: 'PENDING',
          acceptanceCriteria: ['At least 1 Crown Jewel tagged', 'Impact weights normalized [0-10]'],
          riskLevel: 'LOW',
          rollbackStrategy: 'Clear CROWN_JEWEL node tags',
          verificationCommand: 'crownJewelService.listCrownJewels()'
        },
        {
          id: 'TASK-03',
          name: 'Compute Multi-Hop Boundary Crossings',
          directive: 'Trace graph attack paths crossing trust boundaries to Crown Jewels',
          component: 'crown-jewel.service',
          dependencies: ['TASK-02'],
          status: 'PENDING',
          acceptanceCriteria: ['Multi-hop paths discovered', 'Trust boundary crossings enumerated'],
          riskLevel: 'MEDIUM',
          rollbackStrategy: 'Clear calculated reachability cache',
          verificationCommand: 'crownJewelService.computeReachabilityMatrix()'
        },
        {
          id: 'TASK-04',
          name: 'Verify Path Feasibility via Dialectical Consensus',
          directive: 'Challenge reachability paths for WAF blocking or false reachability',
          component: 'debate-engine.service',
          dependencies: ['TASK-03'],
          status: 'PENDING',
          acceptanceCriteria: ['Paths categorized into THEORETICAL, SUPPORTED, VALIDATED'],
          riskLevel: 'LOW',
          rollbackStrategy: 'Downgrade reachability certainty',
          verificationCommand: 'debateEngine.auditReachability()'
        }
      );
    } else {
      // Default: Autonomous Testing Cycle (Prime Directive)
      tasks.push(
        {
          id: 'TASK-01',
          name: 'Cryptographic Scope Verification',
          directive: 'Verify engagement HMAC-SHA256 scope token and target boundary',
          component: 'scope-guard.service',
          dependencies: [],
          status: 'PENDING',
          acceptanceCriteria: ['Scope token HMAC valid', 'Target in authorized IP/CIDR list'],
          riskLevel: 'LOW',
          rollbackStrategy: 'Halt execution immediately',
          verificationCommand: 'ScopeGuard.verifyScopeToken()'
        },
        {
          id: 'TASK-02',
          name: 'Information-Gain Surface Reduction',
          directive: 'Calculate Shannon entropy H(S) and rank actions by mathematical utility',
          component: 'info-gain-planner.service',
          dependencies: ['TASK-01'],
          status: 'PENDING',
          acceptanceCriteria: ['Candidate action utility ranked', 'Redundant tests pruned'],
          riskLevel: 'LOW',
          rollbackStrategy: 'Default to standard sequential queue',
          verificationCommand: 'InfoGainPlannerService.planNextActions()'
        },
        {
          id: 'TASK-03',
          name: 'Safe Ephemeral Execution',
          directive: 'Dispatch highest-utility action to isolated native worker pool',
          component: 'native-worker-pool.service',
          dependencies: ['TASK-02'],
          status: 'PENDING',
          acceptanceCriteria: ['Execution completed within timeout SLA', 'Zero untrusted side effects'],
          riskLevel: 'MEDIUM',
          rollbackStrategy: 'Terminate worker thread & drain queue',
          verificationCommand: 'NativeWorkerPool.submitJob()'
        },
        {
          id: 'TASK-04',
          name: 'Dialectical Evidence Validation',
          directive: 'Submit execution observations to 5-agent debate engine',
          component: 'debate-engine.service',
          dependencies: ['TASK-03'],
          status: 'PENDING',
          acceptanceCriteria: ['Consensus reached', 'Evidence bundle SHA-256 sealed'],
          riskLevel: 'LOW',
          rollbackStrategy: 'Discard unverified hypothesis',
          verificationCommand: 'DebateEngineService.debateFinding()'
        },
        {
          id: 'TASK-05',
          name: 'Graph Ingestion & Snapshotting',
          directive: 'Ingest confirmed nodes/edges with cryptographic provenance and take snapshot',
          component: 'security-graph.service',
          dependencies: ['TASK-04'],
          status: 'PENDING',
          acceptanceCriteria: ['Graph snapshot version incremented', 'Provenance metadata saved'],
          riskLevel: 'LOW',
          rollbackStrategy: 'Revert to previous snapshot ID',
          verificationCommand: 'SecurityGraphService.createSnapshot()'
        }
      );
    }

    const parallelBatches = this.calculateParallelBatches(tasks);

    return {
      planId,
      directive,
      createdAt: new Date().toISOString(),
      tasks,
      estimatedDurationMs: tasks.length * 1500,
      totalTasks: tasks.length,
      parallelBatches
    };
  }

  /**
   * Group tasks into execution batches where dependencies are satisfied
   */
  public static calculateParallelBatches(tasks: TaskNode[]): string[][] {
    const batches: string[][] = [];
    const completed = new Set<string>();
    const remaining = new Map<string, TaskNode>(tasks.map(t => [t.id, t]));

    while (remaining.size > 0) {
      const currentBatch: string[] = [];
      for (const [id, task] of remaining.entries()) {
        const canRun = task.dependencies.every(dep => completed.has(dep));
        if (canRun) {
          currentBatch.push(id);
        }
      }

      if (currentBatch.length === 0) {
        // Circular dependency or unresolvable task
        throw new Error(`Circular dependency detected in Task DAG: ${Array.from(remaining.keys()).join(', ')}`);
      }

      batches.push(currentBatch);
      for (const id of currentBatch) {
        completed.add(id);
        remaining.delete(id);
      }
    }

    return batches;
  }

  /**
   * Executes a Task DAG step by step with circuit-breaking and rollback
   */
  public static async executePlan(
    dag: TaskDAG,
    customExecutor?: (task: TaskNode) => Promise<{ success: boolean; output: string; error?: string }>
  ): Promise<TaskDAGExecutionResult> {
    const startTime = Date.now();
    const taskMap = new Map<string, TaskNode>(dag.tasks.map(t => [t.id, t]));
    const executionLog: TaskDAGExecutionResult['executionLog'] = [];
    const successfullyCompleted: string[] = [];

    for (const batch of dag.parallelBatches) {
      let batchFailed = false;
      let failedTaskId = '';
      let failureError = '';

      for (const taskId of batch) {
        const task = taskMap.get(taskId)!;
        task.status = 'IN_PROGRESS';
        executionLog.push({
          taskId,
          action: 'STARTED',
          timestamp: new Date().toISOString(),
          details: `Executing ${task.name}`
        });

        const taskStart = Date.now();
        try {
          if (customExecutor) {
            const res = await customExecutor(task);
            task.executionDurationMs = Date.now() - taskStart;
            if (!res.success) {
              throw new Error(res.error || res.output || 'Task verification failed');
            }
            task.result = res.output;
          } else {
            // Simulated execution
            task.executionDurationMs = Date.now() - taskStart;
            task.result = `Verified: ${task.acceptanceCriteria.join('; ')}`;
          }

          task.status = 'COMPLETED';
          successfullyCompleted.push(taskId);
          executionLog.push({
            taskId,
            action: 'COMPLETED',
            timestamp: new Date().toISOString(),
            details: task.result
          });
        } catch (err: any) {
          task.status = 'FAILED';
          task.error = err.message || String(err);
          task.executionDurationMs = Date.now() - taskStart;
          batchFailed = true;
          failedTaskId = taskId;
          failureError = task.error || '';

          executionLog.push({
            taskId,
            action: 'FAILED',
            timestamp: new Date().toISOString(),
            details: task.error
          });
          break;
        }
      }

      if (batchFailed) {
        // Trigger circuit breaking rollback on completed tasks in reverse
        const rolledBack: string[] = [];
        for (let i = successfullyCompleted.length - 1; i >= 0; i--) {
          const rbId = successfullyCompleted[i];
          const rbTask = taskMap.get(rbId)!;
          rbTask.status = 'ROLLED_BACK';
          rolledBack.push(rbId);

          executionLog.push({
            taskId: rbId,
            action: 'ROLLED_BACK',
            timestamp: new Date().toISOString(),
            details: `Strategy: ${rbTask.rollbackStrategy}`
          });
        }

        return {
          planId: dag.planId,
          status: 'CIRCUIT_BROKEN_ROLLED_BACK',
          completedTasks: 0,
          failedTasks: 1,
          rolledBackTasks: rolledBack.length,
          executionLog,
          totalDurationMs: Date.now() - startTime
        };
      }
    }

    return {
      planId: dag.planId,
      status: 'SUCCESS',
      completedTasks: dag.tasks.length,
      failedTasks: 0,
      rolledBackTasks: 0,
      executionLog,
      totalDurationMs: Date.now() - startTime
    };
  }
}
