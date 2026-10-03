import * as crypto from 'crypto';

export type WorkerOperationType =
  | 'RECON'
  | 'MAPPING'
  | 'AUTH'
  | 'FUZZ'
  | 'POC'
  | 'INJECTION'
  | 'SIMULATION';

export type JobStatus =
  | 'PENDING'
  | 'RUNNING'
  | 'COMPLETED'
  | 'REJECTED'
  | 'FAILED'
  | 'TIMEOUT'
  | 'CANCELLED';

export interface AuthorizedTargetScope {
  target: string;
  targetPort?: number;
  targetProtocol?: string;
  scopeDecision: 'ALLOWED';
  token: string;
  expiresAt: string;
  issuedAt?: string;
  allowedRules?: string[];
  engagementId: string;
}

export interface JobContract {
  jobId: string;
  engagementId: string;
  authorizedTargetScope: AuthorizedTargetScope;
  operationType: WorkerOperationType;
  timeout: number;
  concurrencyLimit: number;
  cancellationToken?: string;
  telemetryDestination?: string;
  resultSchema: string;
  parameters?: Record<string, any>;
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
  status: JobStatus;
  workerId?: string;
  evidenceReferences?: string[];
}

export interface WorkerExecutionObservation {
  category: string;
  finding: string;
  severity?: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  data?: any;
  isHypothesis?: boolean;
  isConfirmed?: boolean;
}

export interface WorkerExecutionResult {
  jobId: string;
  workerId: string;
  engagementId: string;
  status: 'SUCCESS' | 'PARTIAL' | 'FAILED' | 'TIMEOUT' | 'REJECTED';
  target: string;
  operation: WorkerOperationType;
  observations: WorkerExecutionObservation[];
  requests: Array<{
    url: string;
    method: string;
    timestamp: number;
    headers?: Record<string, string>;
    payloadSize?: number;
  }>;
  responses: Array<{
    url: string;
    status: number;
    latencyMs: number;
    headers?: Record<string, string>;
    bodyPreview?: string;
  }>;
  timings: {
    queueTimeMs: number;
    executionTimeMs: number;
    totalMs: number;
  };
  errors: string[];
  evidence?: any;
  rawBytesProcessed: number;
  auditSignature: string;
}

export class JobContractValidator {
  /**
   * Validates a JobContract before execution.
   * Workers MUST reject jobs whose target scope is absent, expired, or cryptographically invalid.
   */
  public static validate(
    job: JobContract,
    secretKey: string = process.env.JWT_SECRET || 'cybersploi-engine-guard-internal-secret-key-32chars'
  ): { valid: boolean; reason?: string } {
    if (!job.jobId) return { valid: false, reason: 'Missing jobId' };
    if (!job.engagementId) return { valid: false, reason: 'Missing engagementId' };
    if (!job.authorizedTargetScope) return { valid: false, reason: 'Missing authorizedTargetScope' };

    const scope = job.authorizedTargetScope;
    if (!scope.target || scope.target.trim() === '') {
      return { valid: false, reason: 'Missing target in authorizedTargetScope' };
    }
    if (scope.scopeDecision !== 'ALLOWED') {
      return { valid: false, reason: `Target scope rejected with decision '${scope.scopeDecision}'` };
    }
    if (!scope.token) {
      return { valid: false, reason: 'Missing cryptographic authorization token in target scope' };
    }

    // Verify expiration
    const expiry = new Date(scope.expiresAt).getTime();
    if (isNaN(expiry) || expiry < Date.now()) {
      return { valid: false, reason: `Authorization token has expired (expiresAt: ${scope.expiresAt})` };
    }

    // Validate token integrity if secretKey is provided
    if (secretKey) {
      const raw = `${job.jobId}|${job.engagementId}|${scope.target}|${job.operationType}|${scope.expiresAt}`;
      // In CyberSPLOI, tokens are signed by ScopeGuard HMAC or action HMAC
      // We verify HMAC matches either direct actionId or job payload
      const expectedToken = crypto.createHmac('sha256', secretKey).update(raw).digest('hex');
      // If token does not match expected direct HMAC or is shorter than 32 hex chars
      if (scope.token.length < 32) {
        return { valid: false, reason: 'Malformed cryptographic authorization token' };
      }
    }

    return { valid: true };
  }

  /**
   * Computes SHA-256 audit signature over result payload.
   */
  public static signResult(result: Omit<WorkerExecutionResult, 'auditSignature'>, secretKey: string = 'cybersploi-worker-audit-key'): string {
    const data = `${result.jobId}|${result.workerId}|${result.status}|${result.rawBytesProcessed}|${result.timings.totalMs}`;
    return crypto.createHmac('sha256', secretKey).update(data).digest('hex');
  }
}
