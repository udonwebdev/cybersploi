import { spawn } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import { ApprovedAction, ScopeGuard } from '../scope-guard/scope-guard.service';
import { RedisEventBus } from './redis-events.service';
import {
  NativeWorkerPoolService,
  JobContract,
  WorkerExecutionResult,
  WorkerPoolMetrics,
  WorkerOperationType
} from './native-worker-pool.service';

export interface StructuredWorkerResult {
  status: 'SUCCESS' | 'PARTIAL' | 'FAILED' | 'TIMEOUT' | 'REJECTED';
  target: string;
  action: string;
  correlationId: string;
  observations: Array<{
    category: string;
    finding: string;
    severity?: string;
    data?: any;
    isHypothesis?: boolean;
    isConfirmed?: boolean;
  }>;
  requests: Array<{ url: string; method: string; timestamp: number; payloadSize?: number }>;
  responses: Array<{ url: string; status: number; headers?: Record<string, string>; latencyMs?: number; bodyPreview?: string }>;
  timings: Record<string, number>;
  errors: string[];
  evidence?: any;
  auditSignature?: string;
}

export class WorkerClientService {
  private static workerPool: NativeWorkerPoolService = NativeWorkerPoolService.getInstance();

  /**
   * Dispatches a structured job contract directly to the native worker pool.
   */
  public static async submitNativeJob(job: JobContract): Promise<WorkerExecutionResult> {
    return this.workerPool.submitJob(job);
  }

  /**
   * Retrieves operational metrics from the persistent worker pool.
   */
  public static getPoolMetrics(): WorkerPoolMetrics {
    return this.workerPool.getMetrics();
  }

  /**
   * Resolves the python executable path dynamically if fallback is needed.
   */
  private static getPythonExecutable(): string {
    const candidatePaths = [
      path.resolve(__dirname, '../../../../.venv/Scripts/python.exe'),
      path.resolve(__dirname, '../../../.venv/Scripts/python.exe'),
      path.resolve(process.cwd(), '../.venv/Scripts/python.exe'),
      path.resolve(process.cwd(), '.venv/Scripts/python.exe'),
      path.resolve(__dirname, '../../../../.venv/bin/python'),
      path.resolve(__dirname, '../../../.venv/bin/python'),
      path.resolve(process.cwd(), '../.venv/bin/python'),
      path.resolve(process.cwd(), '.venv/bin/python')
    ];

    for (const p of candidatePaths) {
      if (fs.existsSync(p)) return p;
    }
    return 'python';
  }

  private static getWorkerScript(): string {
    const candidateWorkerScripts = [
      path.resolve(__dirname, '../../../../workers/python_workers/recon_worker.py'),
      path.resolve(__dirname, '../../../workers/python_workers/recon_worker.py'),
      path.resolve(process.cwd(), '../workers/python_workers/recon_worker.py'),
      path.resolve(process.cwd(), 'workers/python_workers/recon_worker.py')
    ];

    for (const ws of candidateWorkerScripts) {
      if (fs.existsSync(ws)) return ws;
    }
    return candidateWorkerScripts[0];
  }

  /**
   * Dispatches an approved security action to workers with strict cryptographic verification.
   * STRICT ARCHITECTURAL INVARIANT:
   * A worker must NEVER receive an arbitrary target without an ApprovedAction decision from ScopeGuard.
   */
  public static async executeJob(
    approvedAction: ApprovedAction,
    options?: {
      timeoutMs?: number;
      authContext?: any;
      parameters?: any;
      engineMode?: 'NATIVE_POOL' | 'LEGACY_PROCESS' | 'AUTO';
    }
  ): Promise<StructuredWorkerResult> {
    // 1. Verify ScopeGuard approval token
    const isSignatureValid = ScopeGuard.verifyApprovedAction(approvedAction);
    if (!isSignatureValid) {
      throw new Error('ARCHITECTURAL_VIOLATION: Attempted to execute worker with forged, invalid, or expired ApprovedAction token. Target rejected.');
    }

    const correlationId = `job_${approvedAction.actionId}`;
    const timeoutMs = options?.timeoutMs || 15000;
    const mode = options?.engineMode || 'AUTO';

    const targetWithPort = approvedAction.targetPort && !approvedAction.target.includes(':')
      ? `${approvedAction.target}:${approvedAction.targetPort}`
      : approvedAction.target;

    const jobPayload = {
      action: approvedAction.testType,
      target: targetWithPort,
      authContext: options?.authContext || null,
      scopeDecision: approvedAction.scopeDecision,
      correlationId,
      parameters: options?.parameters || {}
    };

    // Emit live dispatch event
    RedisEventBus.publish({
      engagementId: approvedAction.engagementId,
      actionId: approvedAction.actionId,
      correlationId,
      timestamp: new Date().toISOString(),
      severity: 'INFO',
      TARGET: approvedAction.target,
      SESSION: correlationId,
      ACTION: approvedAction.testType,
      REQUEST: jobPayload,
      OBSERVATION: `Dispatched approved job to worker pool for target ${approvedAction.target}`,
      DECISION: 'EXECUTING',
      NEXT_TEST: 'WAIT_FOR_RESULT'
    });

    // Native High-Performance Worker Pool Path
    if (mode === 'NATIVE_POOL' || mode === 'AUTO') {
      try {
        const opType: WorkerOperationType = ['RECON', 'MAPPING', 'AUTH', 'FUZZ', 'POC', 'INJECTION', 'SIMULATION'].includes(approvedAction.testType)
          ? (approvedAction.testType as WorkerOperationType)
          : 'RECON';

        const nativeJob: JobContract = {
          jobId: approvedAction.actionId,
          engagementId: approvedAction.engagementId,
          authorizedTargetScope: {
            target: approvedAction.target,
            targetPort: approvedAction.targetPort,
            targetProtocol: approvedAction.targetProtocol || 'http',
            scopeDecision: 'ALLOWED',
            token: approvedAction.token,
            expiresAt: approvedAction.expiresAt,
            engagementId: approvedAction.engagementId
          },
          operationType: opType,
          timeout: timeoutMs,
          concurrencyLimit: 10,
          resultSchema: 'WorkerExecutionResult/1.0',
          parameters: options?.parameters || {},
          createdAt: new Date().toISOString(),
          status: 'PENDING'
        };

        const nativeResult = await this.workerPool.submitJob(nativeJob);

        const structured: StructuredWorkerResult = {
          status: nativeResult.status,
          target: nativeResult.target,
          action: approvedAction.testType,
          correlationId,
          observations: nativeResult.observations.map(o => ({
            category: o.category,
            finding: o.finding,
            severity: o.severity || 'INFO',
            data: o.data,
            isHypothesis: o.isHypothesis,
            isConfirmed: o.isConfirmed
          })),
          requests: nativeResult.requests,
          responses: nativeResult.responses,
          timings: nativeResult.timings,
          errors: nativeResult.errors,
          auditSignature: nativeResult.auditSignature
        };

        RedisEventBus.publish({
          engagementId: approvedAction.engagementId,
          actionId: approvedAction.actionId,
          correlationId,
          timestamp: new Date().toISOString(),
          severity: structured.status === 'SUCCESS' ? 'INFO' : 'WARN',
          TARGET: approvedAction.target,
          SESSION: correlationId,
          ACTION: approvedAction.testType,
          RESPONSE: structured,
          OBSERVATION: `Native worker finished with status '${structured.status}', ${structured.observations.length} observations (latency: ${nativeResult.timings.totalMs}ms)`,
          DECISION: structured.status === 'SUCCESS' ? 'PROCESSED' : 'RETRY_OR_FAIL',
          NEXT_TEST: 'NEXT_PHASE'
        });

        return structured;
      } catch (poolErr: any) {
        if (mode === 'NATIVE_POOL') {
          throw poolErr;
        }
        // If AUTO and failed, fall through to fallback process
      }
    }

    // Process-per-test fallback execution
    const pythonBin = this.getPythonExecutable();
    const workerScript = this.getWorkerScript();

    return new Promise((resolve) => {
      let stdoutData = '';
      let stderrData = '';
      let hasTimedOut = false;

      const proc = spawn(pythonBin, [workerScript], {
        cwd: path.dirname(workerScript),
        env: { ...process.env, PYTHONUNBUFFERED: '1' }
      });

      try {
        proc.stdin.write(JSON.stringify(jobPayload));
        proc.stdin.end();
      } catch {}

      const timer = setTimeout(() => {
        hasTimedOut = true;
        try { proc.kill('SIGKILL'); } catch {}
        const timeoutResult: StructuredWorkerResult = {
          status: 'TIMEOUT',
          target: approvedAction.target,
          action: approvedAction.testType,
          correlationId,
          observations: [],
          requests: [],
          responses: [],
          timings: { elapsed_ms: timeoutMs },
          errors: [`Worker exceeded execution timeout of ${timeoutMs}ms`]
        };

        RedisEventBus.publish({
          engagementId: approvedAction.engagementId,
          actionId: approvedAction.actionId,
          correlationId,
          timestamp: new Date().toISOString(),
          severity: 'WARN',
          TARGET: approvedAction.target,
          SESSION: correlationId,
          ACTION: approvedAction.testType,
          DECISION: 'TIMEOUT',
          OBSERVATION: `Worker timed out after ${timeoutMs}ms`,
          NEXT_TEST: 'HANDLE_TIMEOUT'
        });

        resolve(timeoutResult);
      }, timeoutMs);

      proc.stdout.on('data', (chunk) => { stdoutData += chunk.toString(); });
      proc.stderr.on('data', (chunk) => { stderrData += chunk.toString(); });

      proc.on('close', async (code) => {
        if (hasTimedOut) return;
        clearTimeout(timer);

        let parsedResult: StructuredWorkerResult;
        try {
          parsedResult = JSON.parse(stdoutData.trim());
        } catch {
          parsedResult = {
            status: 'FAILED',
            target: approvedAction.target,
            action: approvedAction.testType,
            correlationId,
            observations: [],
            requests: [],
            responses: [],
            timings: {},
            errors: [stderrData || `Worker exited with non-zero code ${code} and non-JSON output`]
          };
        }

        RedisEventBus.publish({
          engagementId: approvedAction.engagementId,
          actionId: approvedAction.actionId,
          correlationId,
          timestamp: new Date().toISOString(),
          severity: parsedResult.status === 'SUCCESS' ? 'INFO' : 'WARN',
          TARGET: approvedAction.target,
          SESSION: correlationId,
          ACTION: approvedAction.testType,
          RESPONSE: parsedResult,
          OBSERVATION: `Worker finished with status '${parsedResult.status}', ${parsedResult.observations.length} observations`,
          DECISION: parsedResult.status === 'SUCCESS' ? 'PROCESSED' : 'RETRY_OR_FAIL',
          NEXT_TEST: 'NEXT_PHASE'
        });

        resolve(parsedResult);
      });

      proc.on('error', (err) => {
        if (hasTimedOut) return;
        clearTimeout(timer);
        resolve({
          status: 'FAILED',
          target: approvedAction.target,
          action: approvedAction.testType,
          correlationId,
          observations: [],
          requests: [],
          responses: [],
          timings: {},
          errors: [`Worker process error: ${err.message}`]
        });
      });
    });
  }
}
