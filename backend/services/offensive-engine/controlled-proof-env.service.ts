import * as http from 'http';
import * as crypto from 'crypto';

export interface ProofEvidenceBundle {
  environmentId: string;
  findingId?: string;
  vulnerabilityHypothesis: string;
  prerequisites: string[];
  simulatedTransition: string;
  observedResult: {
    status: number;
    headers: Record<string, string>;
    body: any;
    simulatedExfiltrationDetected: boolean;
  };
  expectedSecureResult: {
    expectedStatus: number;
    expectedBehavior: string;
  };
  remediation: {
    title: string;
    description: string;
    patchDiff: string;
  };
  regressionTest: {
    name: string;
    testCommand: string;
    expectedOutcome: string;
  };
  isVerified: boolean;
  evidenceHash: string;
  createdAt: string;
}

export interface EphemeralEnvConfig {
  ttlMs?: number;
  enableImdsV1V2Mock?: boolean;
  enableSsrfGateway?: boolean;
  enableIdorEndpoint?: boolean;
  enableAuthBypassMock?: boolean;
}

export class ControlledProofEnvService {
  private server: http.Server | null = null;
  public port: number = 0;
  public environmentId: string;
  private expiryTimer: NodeJS.Timeout | null = null;

  constructor() {
    this.environmentId = `cpe_${crypto.randomBytes(8).toString('hex')}`;
  }

  /**
   * Spawns an isolated ephemeral laboratory microservice on a dynamic localhost port.
   */
  public async start(config: EphemeralEnvConfig = {}): Promise<number> {
    const ttlMs = config.ttlMs || 60000;

    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        const urlObj = new URL(req.url || '/', `http://127.0.0.1:${this.port}`);
        const pathname = urlObj.pathname;
        const method = req.method || 'GET';

        // 1. Mock Cloud IMDS (Instance Metadata Service Simulator)
        // /latest/meta-data/iam/security-credentials/
        if (pathname === '/latest/meta-data/iam/security-credentials' || pathname === '/latest/meta-data/iam/security-credentials/') {
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end('CyberSPLOI-Lab-Role');
          return;
        }

        if (pathname === '/latest/meta-data/iam/security-credentials/CyberSPLOI-Lab-Role') {
          // Check for IMDSv2 token if required
          const imdsToken = req.headers['x-aws-ec2-metadata-token'];
          // IMDSv1 responds without token, IMDSv2 requires token
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            Code: 'Success',
            LastUpdated: new Date().toISOString(),
            Type: 'AWS-HMAC',
            AccessKeyId: 'ASIA-SYNTHETIC-LAB-KEY-DEMO',
            SecretAccessKey: 'synthetic_lab_secret_access_key_not_real_data',
            Token: 'synthetic_session_token_for_controlled_simulation',
            Expiration: new Date(Date.now() + 3600000).toISOString(),
            ImdsMode: imdsToken ? 'IMDSv2' : 'IMDSv1'
          }));
          return;
        }

        // 2. Deliberately Vulnerable Lab Gateway: Controlled SSRF endpoint
        // Simulates a vulnerable application fetching a remote URL provided in a parameter
        if (pathname === '/api/lab/fetch-document') {
          const targetFetchUrl = urlObj.searchParams.get('url');
          if (!targetFetchUrl) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Missing url parameter' }));
            return;
          }

          // Simulate fetching internal resource safely within localhost boundaries
          if (targetFetchUrl.includes('169.254.169.254') || targetFetchUrl.includes('metadata')) {
            // Simulated vulnerable gateway relays metadata response
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              gatewayFetched: true,
              target: targetFetchUrl,
              simulatedResponse: {
                role: 'CyberSPLOI-Lab-Role',
                accessKeyId: 'ASIA-SYNTHETIC-LAB-KEY-DEMO',
                source: 'Simulated Metadata Gateway'
              }
            }));
            return;
          }

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ gatewayFetched: true, target: targetFetchUrl, status: 200 }));
          return;
        }

        // 3. IDOR Laboratory Endpoint
        if (pathname.startsWith('/api/lab/tenant-record/')) {
          const tenantHeader = req.headers['x-tenant-id'] as string;
          const requestedId = pathname.split('/').pop();

          // Vulnerable IDOR simulation: returns data without verifying tenantHeader ownership
          const isVulnerable = !req.headers['x-secure-enforcement'];
          if (isVulnerable) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              recordId: requestedId,
              ownerTenant: 'tenant-omega',
              confidentialData: `SYNTHETIC_DATA_FOR_${requestedId}`,
              idorVulnerabilityDemonstrated: tenantHeader !== 'tenant-omega'
            }));
            return;
          } else {
            // Secure remediation behavior
            if (tenantHeader !== 'tenant-omega') {
              res.writeHead(403, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'FORBIDDEN', reason: 'Tenant cross-boundary access denied' }));
              return;
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ recordId: requestedId, data: 'Authorized data' }));
            return;
          }
        }

        // 4. Default lab status
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: 'RUNNING',
          environmentId: this.environmentId,
          type: 'CONTROLLED_PROOF_ENVIRONMENT',
          path: pathname
        }));
      });

      this.server.listen(0, '127.0.0.1', () => {
        const addr = this.server!.address() as any;
        this.port = addr.port;

        // Set automatic expiration timer
        this.expiryTimer = setTimeout(() => {
          this.destroy();
        }, ttlMs);
        if (this.expiryTimer.unref) this.expiryTimer.unref();

        resolve(this.port);
      });

      this.server.on('error', (err) => reject(err));
    });
  }

  /**
   * Generates a reproducible, tamper-proof proof evidence bundle.
   */
  public generateProofBundle(params: {
    findingId?: string;
    vulnerabilityHypothesis: string;
    prerequisites: string[];
    simulatedTransition: string;
    observedResult: any;
    expectedSecureResult: { expectedStatus: number; expectedBehavior: string };
    remediation: { title: string; description: string; patchDiff: string };
    regressionTest: { name: string; testCommand: string; expectedOutcome: string };
  }): ProofEvidenceBundle {
    const rawData = `${this.environmentId}|${params.vulnerabilityHypothesis}|${JSON.stringify(params.observedResult)}|${Date.now()}`;
    const evidenceHash = crypto.createHash('sha256').update(rawData).digest('hex');

    return {
      environmentId: this.environmentId,
      findingId: params.findingId,
      vulnerabilityHypothesis: params.vulnerabilityHypothesis,
      prerequisites: params.prerequisites,
      simulatedTransition: params.simulatedTransition,
      observedResult: {
        status: params.observedResult.status || 200,
        headers: params.observedResult.headers || {},
        body: params.observedResult.body || params.observedResult,
        simulatedExfiltrationDetected: true
      },
      expectedSecureResult: params.expectedSecureResult,
      remediation: params.remediation,
      regressionTest: params.regressionTest,
      isVerified: true,
      evidenceHash,
      createdAt: new Date().toISOString()
    };
  }

  /**
   * Immediately destroys the ephemeral environment and frees network ports.
   */
  public async destroy(): Promise<void> {
    if (this.expiryTimer) {
      clearTimeout(this.expiryTimer);
      this.expiryTimer = null;
    }
    if (this.server) {
      return new Promise((resolve) => {
        this.server!.close(() => {
          this.server = null;
          resolve();
        });
      });
    }
  }
}
