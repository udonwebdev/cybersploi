import * as http from 'http';
import * as https from 'https';
import * as os from 'os';
import {
  JobContract,
  JobContractValidator,
  WorkerExecutionResult,
  WorkerExecutionObservation
} from './worker-contract';

export interface WorkerPoolMetrics {
  totalDispatched: number;
  totalCompleted: number;
  totalRejected: number;
  totalFailed: number;
  activeWorkers: number;
  queuedJobs: number;
  workerSaturation: number; // 0.0 - 1.0
  p50DispatchLatencyMs: number;
  p95DispatchLatencyMs: number;
  p99DispatchLatencyMs: number;
  requestsPerSecond: number;
  bytesProcessed: number;
  cpuUtilizationPercent: number;
  memoryUtilizationMb: number;
}

export interface NativeWorkerPoolConfig {
  workerCount?: number;
  maxQueueDepth?: number;
  defaultTimeoutMs?: number;
  enableConnectionPooling?: boolean;
}

interface QueuedJobItem {
  job: JobContract;
  enqueuedAt: number;
  resolve: (result: WorkerExecutionResult) => void;
  reject: (err: any) => void;
}

export class NativeWorkerPool {
  private static instance: NativeWorkerPool | null = null;
  private workerCount: number;
  private maxQueueDepth: number;
  private defaultTimeoutMs: number;
  private activeJobsCount: number = 0;
  private queue: QueuedJobItem[] = [];
  private cancelledJobIds: Set<string> = new Set();

  private httpAgent: http.Agent;
  private httpsAgent: https.Agent;

  // Telemetry metrics
  private dispatchLatencies: number[] = [];
  private totalDispatched: number = 0;
  private totalCompleted: number = 0;
  private totalRejected: number = 0;
  private totalFailed: number = 0;
  private totalBytesProcessed: number = 0;
  private windowRequestsCount: number = 0;
  private rpsIntervalTimer: NodeJS.Timeout | null = null;
  private currentRps: number = 0;

  constructor(config: NativeWorkerPoolConfig = {}) {
    this.workerCount = config.workerCount || Math.max(2, os.cpus().length);
    this.maxQueueDepth = config.maxQueueDepth || 5000;
    this.defaultTimeoutMs = config.defaultTimeoutMs || 15000;

    // High-performance connection pooling with persistent keep-alive
    this.httpAgent = new http.Agent({
      keepAlive: true,
      maxSockets: 64,
      maxFreeSockets: 32,
      timeout: 10000
    });

    this.httpsAgent = new https.Agent({
      keepAlive: true,
      maxSockets: 64,
      maxFreeSockets: 32,
      timeout: 10000,
      rejectUnauthorized: false // Lab environment certificates
    });

    // Start background RPS meter
    this.rpsIntervalTimer = setInterval(() => {
      this.currentRps = this.windowRequestsCount;
      this.windowRequestsCount = 0;
    }, 1000);
    if (this.rpsIntervalTimer.unref) this.rpsIntervalTimer.unref();
  }

  public static getInstance(config?: NativeWorkerPoolConfig): NativeWorkerPool {
    if (!NativeWorkerPool.instance) {
      NativeWorkerPool.instance = new NativeWorkerPool(config);
    }
    return NativeWorkerPool.instance;
  }

  /**
   * Cancel an in-flight or queued job.
   */
  public cancelJob(jobId: string): boolean {
    this.cancelledJobIds.add(jobId);
    return true;
  }

  /**
   * Dispatches a job contract to the persistent worker pool.
   */
  public async submitJob(job: JobContract): Promise<WorkerExecutionResult> {
    const enqueueTime = Date.now();

    // 1. Strict zero-trust authorization scope check before queueing
    const validation = JobContractValidator.validate(job);
    if (!validation.valid) {
      this.totalRejected++;
      const rejectedResult: WorkerExecutionResult = {
        jobId: job.jobId,
        workerId: 'scope_gate_verifier',
        engagementId: job.engagementId,
        status: 'REJECTED',
        target: job.authorizedTargetScope?.target || 'unknown',
        operation: job.operationType,
        observations: [],
        requests: [],
        responses: [],
        timings: { queueTimeMs: 0, executionTimeMs: 0, totalMs: 0 },
        errors: [`SECURITY_SCOPE_VIOLATION: ${validation.reason}`],
        rawBytesProcessed: 0,
        auditSignature: ''
      };
      rejectedResult.auditSignature = JobContractValidator.signResult(rejectedResult);
      return rejectedResult;
    }

    // 2. Enforce bounded concurrency queue backpressure
    if (this.queue.length >= this.maxQueueDepth) {
      this.totalRejected++;
      throw new Error(`WORKER_POOL_SATURATED: Queue depth limit (${this.maxQueueDepth}) exceeded`);
    }

    this.totalDispatched++;

    return new Promise<WorkerExecutionResult>((resolve, reject) => {
      this.queue.push({
        job,
        enqueuedAt: enqueueTime,
        resolve,
        reject
      });
      this.processNext();
    });
  }

  private processNext(): void {
    if (this.activeJobsCount >= this.workerCount || this.queue.length === 0) {
      return;
    }

    const item = this.queue.shift();
    if (!item) return;

    this.activeJobsCount++;
    const queueTimeMs = Date.now() - item.enqueuedAt;
    this.recordDispatchLatency(queueTimeMs);

    const workerId = `native_worker_${(this.activeJobsCount % this.workerCount) + 1}`;

    this.executeWorkerTask(item.job, workerId, queueTimeMs)
      .then((res) => {
        this.activeJobsCount--;
        this.totalCompleted++;
        item.resolve(res);
        this.processNext();
      })
      .catch((err) => {
        this.activeJobsCount--;
        this.totalFailed++;
        const failResult: WorkerExecutionResult = {
          jobId: item.job.jobId,
          workerId,
          engagementId: item.job.engagementId,
          status: 'FAILED',
          target: item.job.authorizedTargetScope.target,
          operation: item.job.operationType,
          observations: [],
          requests: [],
          responses: [],
          timings: { queueTimeMs, executionTimeMs: 0, totalMs: queueTimeMs },
          errors: [err.message || 'Worker execution exception'],
          rawBytesProcessed: 0,
          auditSignature: ''
        };
        failResult.auditSignature = JobContractValidator.signResult(failResult);
        item.resolve(failResult);
        this.processNext();
      });
  }

  private async executeWorkerTask(
    job: JobContract,
    workerId: string,
    queueTimeMs: number
  ): Promise<WorkerExecutionResult> {
    const startTime = Date.now();
    const timeoutMs = job.timeout || this.defaultTimeoutMs;

    if (this.cancelledJobIds.has(job.jobId)) {
      this.cancelledJobIds.delete(job.jobId);
      return {
        jobId: job.jobId,
        workerId,
        engagementId: job.engagementId,
        status: 'TIMEOUT',
        target: job.authorizedTargetScope.target,
        operation: job.operationType,
        observations: [],
        requests: [],
        responses: [],
        timings: { queueTimeMs, executionTimeMs: 0, totalMs: queueTimeMs },
        errors: ['Job was cancelled before execution started'],
        rawBytesProcessed: 0,
        auditSignature: ''
      };
    }

    const target = job.authorizedTargetScope.target;
    const targetPort = job.authorizedTargetScope.targetPort;
    const protocol = job.authorizedTargetScope.targetProtocol || 'http';
    const hostWithPort = targetPort && !target.includes(':') ? `${target}:${targetPort}` : target;
    const url = hostWithPort.startsWith('http') ? hostWithPort : `${protocol}://${hostWithPort}`;

    const requests: WorkerExecutionResult['requests'] = [];
    const responses: WorkerExecutionResult['responses'] = [];
    const observations: WorkerExecutionObservation[] = [];
    const errors: string[] = [];
    let bytesProcessed = 0;

    try {
      // Execute targeted security probe using connection-pooled HTTP agent
      const endpoint = job.parameters?.path || (job.operationType === 'RECON' ? '/' : '/api');
      const targetUrl = new URL(endpoint, url);
      const reqTimestamp = Date.now();

      requests.push({
        url: targetUrl.href,
        method: job.parameters?.method || 'GET',
        timestamp: reqTimestamp,
        payloadSize: job.parameters?.payload ? Buffer.byteLength(job.parameters.payload) : 0
      });

      this.windowRequestsCount++;

      const probeResult = await this.performHttpProbe(targetUrl, {
        method: job.parameters?.method || 'GET',
        headers: job.parameters?.headers || {},
        body: job.parameters?.payload,
        timeoutMs
      });

      bytesProcessed += probeResult.bodyBytes;
      this.totalBytesProcessed += probeResult.bodyBytes;

      responses.push({
        url: targetUrl.href,
        status: probeResult.statusCode,
        latencyMs: probeResult.latencyMs,
        headers: probeResult.headers,
        bodyPreview: probeResult.bodyPreview
      });

      // Semantic observation mapping
      if (probeResult.statusCode >= 200 && probeResult.statusCode < 400) {
        observations.push({
          category: 'SERVICE_DETECTION',
          finding: `Target service responsive: HTTP ${probeResult.statusCode}`,
          severity: 'INFO',
          isConfirmed: true,
          data: { headers: probeResult.headers, server: probeResult.headers['server'] }
        });
      }

      // Check for security headers or exposure in response
      if (probeResult.headers['x-imds-token'] || probeResult.bodyPreview.includes('AccessKeyId') || probeResult.bodyPreview.includes('SecurityCredentials')) {
        observations.push({
          category: 'CREDENTIAL_EXPOSURE',
          finding: 'Simulated cloud credential reference observed in response',
          severity: 'CRITICAL',
          isConfirmed: true,
          data: { match: 'simulated_imds_credential_exposure' }
        });
      }

      if (probeResult.statusCode === 500) {
        observations.push({
          category: 'SERVER_ERROR',
          finding: 'Target returned HTTP 500 internal error',
          severity: 'LOW',
          isHypothesis: true,
          data: { errorPreview: probeResult.bodyPreview.slice(0, 200) }
        });
      }
    } catch (reqErr: any) {
      errors.push(reqErr.message || 'Probe failure');
    }

    const executionTimeMs = Date.now() - startTime;
    const totalMs = queueTimeMs + executionTimeMs;

    const result: WorkerExecutionResult = {
      jobId: job.jobId,
      workerId,
      engagementId: job.engagementId,
      status: errors.length > 0 && responses.length === 0 ? 'FAILED' : 'SUCCESS',
      target: job.authorizedTargetScope.target,
      operation: job.operationType,
      observations,
      requests,
      responses,
      timings: {
        queueTimeMs,
        executionTimeMs,
        totalMs
      },
      errors,
      rawBytesProcessed: bytesProcessed,
      auditSignature: ''
    };

    result.auditSignature = JobContractValidator.signResult(result);
    return result;
  }

  private performHttpProbe(
    targetUrl: URL,
    options: {
      method: string;
      headers: Record<string, string>;
      body?: string;
      timeoutMs: number;
    }
  ): Promise<{
    statusCode: number;
    latencyMs: number;
    headers: Record<string, string>;
    bodyPreview: string;
    bodyBytes: number;
  }> {
    return new Promise((resolve, reject) => {
      const isHttps = targetUrl.protocol === 'https:';
      const agent = isHttps ? this.httpsAgent : this.httpAgent;
      const client = isHttps ? https : http;
      const startTime = Date.now();

      const req = client.request(
        targetUrl,
        {
          method: options.method,
          headers: {
            'User-Agent': 'CyberSPLOI-Worker-Engine/3.0',
            ...options.headers
          },
          agent,
          timeout: options.timeoutMs
        },
        (res) => {
          const chunks: Buffer[] = [];
          let totalBytes = 0;

          res.on('data', (chunk: Buffer) => {
            chunks.push(chunk);
            totalBytes += chunk.length;
          });

          res.on('end', () => {
            const latencyMs = Date.now() - startTime;
            const fullBuffer = Buffer.concat(chunks);
            const bodyPreview = fullBuffer.toString('utf8', 0, Math.min(2048, fullBuffer.length));

            const cleanHeaders: Record<string, string> = {};
            for (const [k, v] of Object.entries(res.headers)) {
              if (v) cleanHeaders[k] = Array.isArray(v) ? v.join(', ') : v;
            }

            resolve({
              statusCode: res.statusCode || 0,
              latencyMs,
              headers: cleanHeaders,
              bodyPreview,
              bodyBytes: totalBytes
            });
          });
        }
      );

      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`Probe timeout after ${options.timeoutMs}ms`));
      });

      req.on('error', (err) => {
        reject(err);
      });

      if (options.body) {
        req.write(options.body);
      }
      req.end();
    });
  }

  private recordDispatchLatency(latencyMs: number): void {
    this.dispatchLatencies.push(latencyMs);
    if (this.dispatchLatencies.length > 1000) {
      this.dispatchLatencies.shift();
    }
  }

  public getMetrics(): WorkerPoolMetrics {
    const sorted = [...this.dispatchLatencies].sort((a, b) => a - b);
    const p50 = sorted[Math.floor(sorted.length * 0.5)] || 0;
    const p95 = sorted[Math.floor(sorted.length * 0.95)] || 0;
    const p99 = sorted[Math.floor(sorted.length * 0.99)] || 0;

    const mem = process.memoryUsage();

    return {
      totalDispatched: this.totalDispatched,
      totalCompleted: this.totalCompleted,
      totalRejected: this.totalRejected,
      totalFailed: this.totalFailed,
      activeWorkers: this.activeJobsCount,
      queuedJobs: this.queue.length,
      workerSaturation: Math.min(1.0, this.activeJobsCount / Math.max(1, this.workerCount)),
      p50DispatchLatencyMs: p50,
      p95DispatchLatencyMs: p95,
      p99DispatchLatencyMs: p99,
      requestsPerSecond: this.currentRps,
      bytesProcessed: this.totalBytesProcessed,
      cpuUtilizationPercent: os.loadavg ? Math.round(os.loadavg()[0] * 10) : 10,
      memoryUtilizationMb: Math.round(mem.rss / (1024 * 1024))
    };
  }

  public destroy(): void {
    if (this.rpsIntervalTimer) {
      clearInterval(this.rpsIntervalTimer);
      this.rpsIntervalTimer = null;
    }
    this.httpAgent.destroy();
    this.httpsAgent.destroy();
    NativeWorkerPool.instance = null;
  }
}
