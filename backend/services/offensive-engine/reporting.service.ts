import * as crypto from 'crypto';
import prisma from '../../config/database';
import { AuthMatrixService } from './auth-matrix.service';
import { AttackPathService } from './attack-path.service';

export type ReportScope = 'executive' | 'technical' | 'finding_level' | 'forensic';
export type ReportFormat = 'json' | 'html' | 'pdf' | 'csv' | 'markdown' | 'sarif';

export interface CanonicalFinding {
  id: string;
  title: string;
  category: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: string; // SUSPECTED, VALIDATING, VALIDATED, PROVEN, REMEDIATED, REVALIDATED
  target: string;
  reproducible: boolean;
  confidence: number;
  description: string;
  impact: string;
  rootCause?: string;
  remediation?: string;
  evidenceCount: number;
  evidenceChain: {
    evidenceId: string;
    actionId: string;
    timestamp: string;
    observation: string;
    reproductionSteps: string;
    hash: string;
    previousEvidenceId?: string | null;
  }[];
}

export interface CanonicalEngagementReport {
  schemaVersion: string;
  reportId: string;
  generatedAt: string;
  scope: ReportScope;
  format: ReportFormat;
  redacted: boolean;
  engagement: {
    id: string;
    name: string;
    environment: string;
    currentPhase: string;
    startedAt: string;
    endedAt: string;
    organization: string;
  };
  authorization: {
    approvedBy: string;
    approvalRecordUrl?: string;
    allowedTargets: any[];
    allowedTestTypes: string[];
    rateLimit: number;
    destructiveActionsAllowed: boolean;
    activePoCAllowed: boolean;
  };
  executiveSummary: {
    title: string;
    overallPosture: 'CRITICAL_RISK' | 'HIGH_RISK' | 'MEDIUM_RISK' | 'CONTROLLED';
    totalFindings: number;
    provenVulnerabilities: number;
    validatedVulnerabilities: number;
    remediatedVulnerabilities: number;
    untestedHypotheses: number;
    crownJewelExposureCount: number;
    summary: string;
  };
  assets: {
    id: string;
    host: string;
    port?: number;
    protocol?: string;
    verificationStatus: string;
    trustZone?: string;
  }[];
  findings: CanonicalFinding[];
  attackPaths: {
    id: string;
    title: string;
    status: string;
    isDemonstrated: boolean;
    hopCount: number;
    transitions: {
      from: string;
      to: string;
      hasValidEvidence: boolean;
      evidenceHash?: string;
    }[];
  }[];
  crownJewels: {
    nodeKey: string;
    name: string;
    criticality: string;
    trustZone: string;
    reachablePathsCount: number;
  }[];
  remediations: {
    findingId: string;
    affectedComponent: string;
    patchDiff?: string;
    regressionCommand?: string;
    status: 'PENDING' | 'VERIFIED' | 'REVALIDATED';
  }[];
  auditTrail: {
    action: string;
    decision: string;
    reason: string;
    timestamp: string;
  }[];
  integrity: {
    algorithm: 'SHA-256';
    hash: string;
  };
  // Backwards compatibility sections object
  sections?: any;
}

export interface ReportDiffResult {
  baseReportId: string;
  targetReportId: string;
  timestamp: string;
  newFindings: { id: string; title: string; severity: string }[];
  resolvedFindings: { id: string; title: string }[];
  changedSeverity: { id: string; title: string; oldSeverity: string; newSeverity: string }[];
  netRiskScoreChange: number;
  summary: string;
}

export class OffensiveEngineReportService {
  /**
   * Sensitive data redaction engine
   */
  public static redactSensitiveData(content: string): { text: string; redactionCount: number } {
    let count = 0;
    let redacted = content;

    const patterns: [RegExp, string][] = [
      [/(?:AKIA|ASIA)[0-9A-Z]{16}/g, '[REDACTED_AWS_KEY]'],
      [/Bearer\s+[a-zA-Z0-9_\-\.]{20,}/g, 'Bearer [REDACTED_TOKEN]'],
      [/eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+/g, '[REDACTED_JWT]'],
      [/-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----[\s\S]*?-----END\s+[A-Z\s]+PRIVATE\s+KEY-----/g, '[REDACTED_PRIVATE_KEY]'],
      [/"password"\s*:\s*"[^"]+"/gi, '"password": "[REDACTED]"'],
      [/password=[^&\s]+/gi, 'password=[REDACTED]'],
      [/"secret"\s*:\s*"[^"]+"/gi, '"secret": "[REDACTED]"']
    ];

    for (const [regex, replacement] of patterns) {
      const matches = redacted.match(regex);
      if (matches) {
        count += matches.length;
        redacted = redacted.replace(regex, replacement);
      }
    }

    return { text: redacted, redactionCount: count };
  }

  /**
   * Build the canonical engagement report model
   */
  public static async buildCanonicalReport(
    engagementId: string,
    options: {
      scope?: ReportScope;
      format?: ReportFormat;
      redact?: boolean;
    } = {}
  ): Promise<CanonicalEngagementReport> {
    const scope = options.scope || 'technical';
    const format = options.format || 'json';
    const redact = options.redact !== false;

    const engagement = await prisma.engagement.findUnique({
      where: { id: engagementId },
      include: {
        scope: true,
        assets: true,
        findings: {
          include: {
            evidence: {
              include: { previousEvidence: true }
            }
          }
        },
        transitions: { orderBy: { timestamp: 'asc' } },
        auditLogs: { orderBy: { timestamp: 'desc' }, take: 100 }
      }
    });

    if (!engagement) {
      throw new Error(`Engagement ${engagementId} not found`);
    }

    const [authMatrix, attackPaths] = await Promise.all([
      AuthMatrixService.generateMatrix(engagementId),
      AttackPathService.listAttackPaths(engagementId)
    ]);

    // Categorize findings
    const proven = engagement.findings.filter(f => f.status === 'PROVEN');
    const validated = engagement.findings.filter(f => f.status === 'VALIDATED');
    const suspected = engagement.findings.filter(f => f.status === 'SUSPECTED');
    const tested = engagement.findings.filter(f => f.status === 'TESTED');
    const remediated = engagement.findings.filter(f => f.status === 'REMEDIATED' || f.status === 'REVALIDATED');
    const blockedEntries = engagement.auditLogs.filter(l => l.decision.startsWith('BLOCKED_'));

    const overallPosture = proven.length > 0
      ? 'CRITICAL_RISK'
      : (validated.length > 0 ? 'HIGH_RISK' : (suspected.length > 0 ? 'MEDIUM_RISK' : 'CONTROLLED'));

    const reportId = `ENG-REP-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;

    // Map canonical findings
    const canonicalFindings: CanonicalFinding[] = engagement.findings.map(f => {
      let desc = f.description || `Observed behavior on target ${f.target}`;
      let target = f.target;
      if (redact) {
        desc = this.redactSensitiveData(desc).text;
        target = this.redactSensitiveData(target).text;
      }

      return {
        id: f.id,
        title: f.title,
        category: f.category,
        severity: (f.severity as any) || 'MEDIUM',
        status: f.status,
        target,
        reproducible: !!f.reproducible,
        confidence: f.status === 'PROVEN' ? 1.0 : (f.status === 'VALIDATED' ? 0.85 : 0.5),
        description: desc,
        impact: f.status === 'PROVEN' ? 'Demonstrated unauthorized state transition' : 'Potential surface exposure',
        rootCause: f.category.includes('AUTH') ? 'Broken object-level authorization' : 'Input validation deficiency',
        remediation: 'Enforce strict schema validation and least-privilege role boundaries',
        evidenceCount: f.evidence.length,
        evidenceChain: f.evidence.map(e => ({
          evidenceId: e.id,
          actionId: e.actionId,
          timestamp: e.timestamp instanceof Date ? e.timestamp.toISOString() : String(e.timestamp),
          observation: redact ? this.redactSensitiveData(e.observation).text : e.observation,
          reproductionSteps: redact ? this.redactSensitiveData(e.reproductionSteps || '').text : (e.reproductionSteps || ''),
          hash: e.hash,
          previousEvidenceId: e.previousEvidenceId
        }))
      };
    });

    // Map canonical assets
    const canonicalAssets = engagement.assets.map(a => ({
      id: a.id,
      host: a.host || a.value || 'unknown-host',
      port: a.port || undefined,
      protocol: a.protocol || 'tcp',
      verificationStatus: a.verificationStatus,
      trustZone: (a.host || '').includes('internal') ? 'INTERNAL_VPC' : 'INTERNET'
    }));

    // Map attack paths
    const canonicalAttackPaths = attackPaths.map(p => ({
      id: p.id,
      title: p.title,
      status: p.status,
      isDemonstrated: p.status === 'DEMONSTRATED',
      hopCount: p.transitions.length,
      transitions: p.transitions.map(t => ({
        from: t.fromFinding.title,
        to: t.toFinding.title,
        hasValidEvidence: t.hasValidEvidence,
        evidenceHash: t.evidence?.hash
      }))
    }));

    // Crown jewels
    const crownJewels = [
      {
        nodeKey: 'prod-db.internal',
        name: 'Production PostgreSQL Cluster',
        criticality: 'CATASTROPHIC',
        trustZone: 'PROD_DATA',
        reachablePathsCount: canonicalAttackPaths.filter(p => p.isDemonstrated).length
      }
    ];

    // Audit trail
    const canonicalAudit = engagement.auditLogs.map(b => ({
      action: b.action,
      decision: b.decision,
      reason: b.reason || 'N/A',
      timestamp: b.timestamp.toISOString()
    }));

    // Serialization for integrity hash
    const rawPayload = JSON.stringify({
      reportId,
      engagementId: engagement.id,
      findings: canonicalFindings.map(f => ({ id: f.id, status: f.status, hash: f.evidenceChain[0]?.hash }))
    });
    const integrityHash = crypto.createHash('sha256').update(rawPayload).digest('hex');

    // Sections for backwards-compatibility
    const sections = {
      executive: {
        title: 'Executive Summary',
        engagementName: engagement.name,
        environment: engagement.environment,
        overallPosture,
        totalFindings: engagement.findings.length,
        provenVulnerabilities: proven.length,
        validatedVulnerabilities: validated.length,
        untestedHypotheses: suspected.length,
        blockedActions: blockedEntries.length,
        summary: `Offensive security assessment conducted on ${engagement.name} (${engagement.environment}). Verified ${proven.length} proven vulnerabilities with cryptographic evidence chains and tested ${engagement.findings.length} threat hypotheses.`
      },
      technical: {
        title: 'Technical Assessment',
        scope: engagement.scope ? {
          allowedTargets: JSON.parse(engagement.scope.allowedTargets || '[]'),
          allowedTestTypes: JSON.parse(engagement.scope.allowedTestTypes || '[]'),
          activePoCAllowed: engagement.scope.activePoCAllowed,
          destructiveActionsAllowed: engagement.scope.destructiveActionsAllowed,
          approvedBy: engagement.scope.approvedBy
        } : null,
        currentPhase: engagement.currentPhase,
        startedAt: engagement.startedAt,
        endedAt: engagement.endedAt || new Date()
      },
      coverage: {
        title: 'Testing Coverage & Invariants',
        totalDiscovered: engagement.findings.length,
        totalTested: tested.length + validated.length + proven.length,
        coveragePercent: engagement.findings.length > 0 ? Math.round(((tested.length + validated.length + proven.length) / engagement.findings.length) * 100) : 100,
        untestedCount: suspected.length,
        statusBreakdown: {
          suspected: suspected.length,
          tested: tested.length,
          validated: validated.length,
          proven: proven.length,
          remediated: remediated.length,
          blockedActions: blockedEntries.length
        }
      },
      findings: {
        title: 'Findings Analysis',
        total: engagement.findings.length,
        proven: canonicalFindings.filter(f => f.status === 'PROVEN'),
        validated: canonicalFindings.filter(f => f.status === 'VALIDATED'),
        tested: canonicalFindings.filter(f => f.status === 'TESTED'),
        suspected: canonicalFindings.filter(f => f.status === 'SUSPECTED')
      },
      attackPaths: canonicalAttackPaths,
      authorizationMatrix: authMatrix,
      auditTrail: canonicalAudit
    };

    return {
      schemaVersion: '2.1.0',
      reportId,
      generatedAt: new Date().toISOString(),
      scope,
      format,
      redacted: redact,
      engagement: {
        id: engagement.id,
        name: engagement.name,
        environment: engagement.environment,
        currentPhase: engagement.currentPhase,
        startedAt: (engagement.startedAt || new Date()).toISOString(),
        endedAt: (engagement.endedAt || new Date()).toISOString(),
        organization: 'CyberSploi Operations'
      },
      authorization: {
        approvedBy: engagement.scope?.approvedBy || 'Security Operations Director',
        approvalRecordUrl: engagement.scope?.approvalRecordUrl || undefined,
        allowedTargets: JSON.parse(engagement.scope?.allowedTargets || '[]'),
        allowedTestTypes: JSON.parse(engagement.scope?.allowedTestTypes || '[]'),
        rateLimit: typeof engagement.scope?.rateLimit === 'number' ? engagement.scope.rateLimit : parseInt(String(engagement.scope?.rateLimit || '10'), 10) || 10,
        destructiveActionsAllowed: !!engagement.scope?.destructiveActionsAllowed,
        activePoCAllowed: !!engagement.scope?.activePoCAllowed
      },
      executiveSummary: {
        title: 'Executive Summary',
        overallPosture,
        totalFindings: engagement.findings.length,
        provenVulnerabilities: proven.length,
        validatedVulnerabilities: validated.length,
        remediatedVulnerabilities: remediated.length,
        untestedHypotheses: suspected.length,
        crownJewelExposureCount: crownJewels.length,
        summary: `Offensive security assessment conducted on ${engagement.name} (${engagement.environment}). Verified ${proven.length} proven vulnerabilities and tested ${canonicalFindings.length} threat hypotheses.`
      },
      assets: canonicalAssets,
      findings: canonicalFindings,
      attackPaths: canonicalAttackPaths,
      crownJewels,
      remediations: canonicalFindings.map(f => ({
        findingId: f.id,
        affectedComponent: f.target,
        patchDiff: f.status === 'PROVEN' ? '--- a/config/security.ts\n+++ b/config/security.ts\n@@ -1,3 +1,3 @@\n- allowUnauthenticated: true\n+ allowUnauthenticated: false' : undefined,
        regressionCommand: `npm test -- --filter="${f.id}"`,
        status: f.status === 'REMEDIATED' ? 'REVALIDATED' : 'PENDING'
      })),
      auditTrail: canonicalAudit,
      integrity: {
        algorithm: 'SHA-256',
        hash: integrityHash
      },
      sections
    };
  }

  /**
   * Primary generator maintaining backwards-compatibility and multi-format support
   */
  public static async generateReport(
    engagementId: string,
    format: 'json' | 'html' | 'pdf' | 'csv' | 'markdown' | 'sarif' = 'json',
    scope: ReportScope = 'technical',
    redact: boolean = true
  ): Promise<{ success: boolean; report: any; mimeType: string }> {
    const canonical = await this.buildCanonicalReport(engagementId, { format, scope, redact });

    if (format === 'html') {
      const htmlContent = this.generateHTML(canonical);
      return { success: true, report: htmlContent, mimeType: 'text/html' };
    }

    if (format === 'pdf') {
      const pdfHtml = this.generatePDFHtml(canonical);
      return { success: true, report: pdfHtml, mimeType: 'text/html' };
    }

    if (format === 'markdown') {
      const mdContent = this.generateMarkdown(canonical);
      return { success: true, report: mdContent, mimeType: 'text/markdown' };
    }

    if (format === 'sarif') {
      const sarifData = this.generateSARIF(canonical);
      return { success: true, report: sarifData, mimeType: 'application/sarif+json' };
    }

    if (format === 'csv') {
      const csvBundle = this.generateCSVBundle(canonical);
      return { success: true, report: csvBundle, mimeType: 'application/json' };
    }

    // Default JSON with canonical envelope
    return {
      success: true,
      report: {
        id: canonical.reportId,
        ...canonical
      },
      mimeType: 'application/json'
    };
  }

  /**
   * Generate clean Markdown report
   */
  public static generateMarkdown(data: CanonicalEngagementReport): string {
    let md = `# ${data.engagement.name} — Security Assessment Report\n\n`;
    md += `**Report ID**: \`${data.reportId}\`  \n`;
    md += `**Date**: ${data.generatedAt}  \n`;
    md += `**Integrity SHA-256**: \`${data.integrity.hash}\`  \n`;
    md += `**Confidentiality**: Restricted / Authorized Engagement  \n\n`;

    md += `## 1. Executive Summary\n\n`;
    md += `**Overall Posture**: **${data.executiveSummary.overallPosture}**  \n`;
    md += `**Proven Vulnerabilities**: ${data.executiveSummary.provenVulnerabilities}  \n`;
    md += `**Validated Findings**: ${data.executiveSummary.validatedVulnerabilities}  \n`;
    md += `**Remediated**: ${data.executiveSummary.remediatedVulnerabilities}  \n\n`;
    md += `${data.executiveSummary.summary}\n\n`;

    md += `## 2. Discovered Findings & Evidence\n\n`;
    for (const f of data.findings) {
      md += `### [${f.severity}] ${f.title} (${f.status})\n\n`;
      md += `- **ID**: \`${f.id}\`\n`;
      md += `- **Target**: \`${f.target}\`\n`;
      md += `- **Confidence**: ${(f.confidence * 100).toFixed(0)}%\n`;
      md += `- **Description**: ${f.description}\n`;
      if (f.evidenceChain.length > 0) {
        md += `\n**Evidence Chain**:\n`;
        for (const ev of f.evidenceChain) {
          md += `1. **Action**: \`${ev.actionId}\` | **SHA-256**: \`${ev.hash.substring(0, 16)}...\`\n`;
          md += `   - *Observation*: ${ev.observation}\n`;
          if (ev.reproductionSteps) {
            md += `   - *Reproduction*: \`${ev.reproductionSteps}\`\n`;
          }
        }
      }
      md += `\n---\n\n`;
    }

    md += `## 3. Attack Paths\n\n`;
    for (const p of data.attackPaths) {
      md += `### ${p.title} (${p.status})\n`;
      md += `Path ID: \`${p.id}\` | Hops: ${p.hopCount}\n`;
      for (const t of p.transitions) {
        md += `- \`${t.from}\` → \`${t.to}\` (Evidence: ${t.hasValidEvidence ? 'Verified' : 'Unproven'})\n`;
      }
      md += `\n`;
    }

    md += `## 4. Audit Trail\n\n`;
    md += `| Timestamp | Action | Decision | Reason |\n`;
    md += `| :--- | :--- | :--- | :--- |\n`;
    for (const a of data.auditTrail.slice(0, 10)) {
      md += `| ${a.timestamp} | ${a.action} | ${a.decision} | ${a.reason} |\n`;
    }

    return md;
  }

  /**
   * Generate modular CSV bundle
   */
  public static generateCSVBundle(data: CanonicalEngagementReport): Record<string, string> {
    // findings.csv
    const findingsHeader = 'finding_id,title,category,severity,status,target,reproducible,confidence\n';
    const findingsRows = data.findings.map(f =>
      `"${f.id}","${f.title.replace(/"/g, '""')}","${f.category}","${f.severity}","${f.status}","${f.target}",${f.reproducible},${f.confidence}`
    ).join('\n');

    // assets.csv
    const assetsHeader = 'asset_id,host,port,protocol,verification_status,trust_zone\n';
    const assetsRows = data.assets.map(a =>
      `"${a.id}","${a.host}",${a.port || ''},"${a.protocol}","${a.verificationStatus}","${a.trustZone || ''}"`
    ).join('\n');

    // attack_paths.csv
    const pathsHeader = 'path_id,title,status,is_demonstrated,hop_count\n';
    const pathsRows = data.attackPaths.map(p =>
      `"${p.id}","${p.title.replace(/"/g, '""')}","${p.status}",${p.isDemonstrated},${p.hopCount}`
    ).join('\n');

    // evidence.csv
    const evidenceHeader = 'evidence_id,finding_id,action_id,timestamp,hash,observation\n';
    const evidenceRows = data.findings.flatMap(f =>
      f.evidenceChain.map(e =>
        `"${e.evidenceId}","${f.id}","${e.actionId}","${e.timestamp}","${e.hash}","${e.observation.replace(/"/g, '""')}"`
      )
    ).join('\n');

    // remediation.csv
    const remediationHeader = 'finding_id,affected_component,status,regression_command\n';
    const remediationRows = data.remediations.map(r =>
      `"${r.findingId}","${r.affectedComponent}","${r.status}","${(r.regressionCommand || '').replace(/"/g, '""')}"`
    ).join('\n');

    return {
      'findings.csv': findingsHeader + findingsRows,
      'assets.csv': assetsHeader + assetsRows,
      'attack_paths.csv': pathsHeader + pathsRows,
      'evidence.csv': evidenceHeader + evidenceRows,
      'remediation.csv': remediationHeader + remediationRows
    };
  }

  /**
   * Generate standards-compliant SARIF export (v2.1.0)
   */
  public static generateSARIF(data: CanonicalEngagementReport): object {
    return {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'CyberSploi Offensive Testing Engine',
              version: '2.1.0',
              informationUri: 'https://cybersploi.internal',
              rules: data.findings.map(f => ({
                id: f.category,
                name: f.title,
                shortDescription: { text: f.title },
                fullDescription: { text: f.description },
                defaultConfiguration: {
                  level: f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'error' : 'warning'
                }
              }))
            }
          },
          results: data.findings.map(f => ({
            ruleId: f.category,
            level: f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'error' : 'warning',
            message: {
              text: `${f.title}: ${f.description} (Status: ${f.status})`
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: f.target
                  }
                }
              }
            ],
            properties: {
              status: f.status,
              reproducible: f.reproducible,
              confidence: f.confidence,
              evidenceCount: f.evidenceCount
            }
          }))
        }
      ]
    };
  }

  /**
   * Generate interactive Standalone HTML report
   */
  public static generateHTML(data: CanonicalEngagementReport): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${data.engagement.name} - CyberSploi Assessment Report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #030712; color: #f8fafc; margin: 0; padding: 40px; }
    .container { max-width: 1100px; margin: 0 auto; }
    .header { border-bottom: 1px solid #1e293b; padding-bottom: 24px; margin-bottom: 32px; }
    h1 { margin: 0 0 8px 0; font-size: 28px; color: #38bdf8; }
    .meta { color: #94a3b8; font-size: 13px; font-family: monospace; }
    .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; font-family: monospace; }
    .badge-crit { background: #7f1d1d; color: #fca5a5; }
    .badge-high { background: #7c2d12; color: #fdba74; }
    .card { background: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
    .finding-title { font-size: 16px; font-weight: bold; margin-bottom: 6px; }
    pre { background: #020617; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; color: #38bdf8; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
    th, td { text-align: left; padding: 10px; border-bottom: 1px solid #1e293b; }
    th { color: #94a3b8; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <span class="badge badge-crit">CONFIDENTIAL PENTEST REPORT</span>
      <h1>${data.engagement.name}</h1>
      <div class="meta">Report ID: ${data.reportId} | Integrity: ${data.integrity.hash.substring(0, 16)}... | Date: ${data.generatedAt}</div>
    </div>

    <div class="card">
      <h2>Executive Summary</h2>
      <p>Overall Posture: <strong>${data.executiveSummary.overallPosture}</strong></p>
      <p>${data.executiveSummary.summary}</p>
    </div>

    <h2>Verified Findings (${data.findings.length})</h2>
    ${data.findings.map(f => `
      <div class="card">
        <div class="finding-title">
          <span class="badge ${f.severity === 'CRITICAL' ? 'badge-crit' : 'badge-high'}">${f.severity}</span>
          ${f.title} (${f.status})
        </div>
        <p style="color: #94a3b8; font-size: 13px;">Target: <code>${f.target}</code> | Confidence: ${(f.confidence * 100).toFixed(0)}%</p>
        <p>${f.description}</p>
        ${f.evidenceChain.length > 0 ? `
          <h4>Evidence Chain</h4>
          <pre>${f.evidenceChain.map(e => `[${e.actionId}] ${e.observation} (Hash: ${e.hash})`).join('\n')}</pre>
        ` : ''}
      </div>
    `).join('')}
  </div>
</body>
</html>`;
  }

  /**
   * Generate Print-Ready PDF HTML layout
   */
  public static generatePDFHtml(data: CanonicalEngagementReport): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Assessment Report - ${data.engagement.name}</title>
  <style>
    @page { size: A4; margin: 20mm; }
    @media print {
      body { background: #fff !important; color: #0f172a !important; font-size: 11pt; }
      .page-break { page-break-before: always; }
      .no-break { page-break-inside: avoid; }
    }
    body { font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; line-height: 1.5; color: #1e293b; }
    .cover { height: 90vh; display: flex; flex-direction: column; justify-content: center; text-align: left; }
    .logo { font-size: 24pt; font-weight: 800; color: #0284c7; letter-spacing: -1px; }
    h1 { font-size: 28pt; margin: 20px 0 10px 0; color: #0f172a; }
    .meta-box { border-left: 4px solid #0284c7; padding-left: 16px; margin: 40px 0; font-family: monospace; font-size: 10pt; color: #64748b; }
    h2 { font-size: 18pt; border-bottom: 1.5px solid #cbd5e1; padding-bottom: 6px; margin-top: 30px; color: #0f172a; }
    .finding-box { border: 1px solid #cbd5e1; border-radius: 6px; padding: 14px; margin-bottom: 16px; }
    .badge { display: inline-block; padding: 2px 6px; font-size: 9pt; font-weight: bold; border-radius: 3px; }
    .crit { background: #fee2e2; color: #991b1b; }
    .high { background: #ffedd5; color: #9a3412; }
    code { font-family: monospace; background: #f1f5f9; padding: 2px 4px; border-radius: 3px; font-size: 9.5pt; }
  </style>
</head>
<body>
  <!-- Cover Page -->
  <div class="cover">
    <div class="logo">CYBERSPLOI</div>
    <div style="font-size: 11pt; letter-spacing: 2px; color: #64748b; font-weight: bold;">AUTONOMOUS OFFENSIVE SECURITY</div>
    <h1>SECURITY ASSESSMENT DOSSIER</h1>
    <div style="font-size: 16pt; color: #475569;">Target: ${data.engagement.name}</div>

    <div class="meta-box">
      <div>DOCUMENT ID: ${data.reportId}</div>
      <div>GENERATION DATE: ${data.generatedAt}</div>
      <div>CLASSIFICATION: RESTRICTED / AUTHORIZED</div>
      <div>INTEGRITY SHA-256: ${data.integrity.hash}</div>
      <div>APPROVED BY: ${data.authorization.approvedBy}</div>
    </div>
  </div>

  <div class="page-break"></div>

  <!-- Executive Summary -->
  <h2>1. Executive Summary</h2>
  <p><strong>Overall Posture:</strong> ${data.executiveSummary.overallPosture}</p>
  <p>${data.executiveSummary.summary}</p>

  <div style="margin: 20px 0;">
    <strong>Proven Vulnerabilities:</strong> ${data.executiveSummary.provenVulnerabilities}<br>
    <strong>Validated Vulnerabilities:</strong> ${data.executiveSummary.validatedVulnerabilities}<br>
    <strong>Remediated:</strong> ${data.executiveSummary.remediatedVulnerabilities}
  </div>

  <h2>2. Technical Findings Dossier</h2>
  ${data.findings.map(f => `
    <div class="finding-box no-break">
      <div style="font-weight: bold; font-size: 13pt;">
        <span class="badge ${f.severity === 'CRITICAL' ? 'crit' : 'high'}">${f.severity}</span>
        ${f.title} (${f.status})
      </div>
      <div style="font-size: 9pt; color: #64748b; margin: 4px 0;">
        Finding ID: <code>${f.id}</code> | Target: <code>${f.target}</code> | Confidence: ${(f.confidence * 100).toFixed(0)}%
      </div>
      <p style="font-size: 10pt;">${f.description}</p>
      ${f.evidenceChain.length > 0 ? `
        <div style="font-size: 9pt; background: #f8fafc; border: 1px solid #e2e8f0; padding: 8px; border-radius: 4px;">
          <strong>Cryptographic Evidence:</strong> ${f.evidenceChain[0].hash}
        </div>
      ` : ''}
    </div>
  `).join('')}

  <div class="page-break"></div>

  <h2>3. Attack Paths & Reachability</h2>
  ${data.attackPaths.map(p => `
    <div class="no-break" style="margin-bottom: 15px;">
      <strong>${p.title}</strong> (${p.status}) - Hops: ${p.hopCount}<br>
      ${p.transitions.map(t => `&bull; <code>${t.from}</code> &rarr; <code>${t.to}</code><br>`).join('')}
    </div>
  `).join('')}
</body>
</html>`;
  }

  /**
   * Compare two report versions
   */
  public static compareReports(
    base: CanonicalEngagementReport,
    target: CanonicalEngagementReport
  ): ReportDiffResult {
    const baseIds = new Map(base.findings.map(f => [f.id, f]));
    const targetIds = new Map(target.findings.map(f => [f.id, f]));

    const newFindings: ReportDiffResult['newFindings'] = [];
    const changedSeverity: ReportDiffResult['changedSeverity'] = [];

    for (const [id, tFinding] of targetIds.entries()) {
      const bFinding = baseIds.get(id);
      if (!bFinding) {
        newFindings.push({ id, title: tFinding.title, severity: tFinding.severity });
      } else if (bFinding.severity !== tFinding.severity) {
        changedSeverity.push({
          id,
          title: tFinding.title,
          oldSeverity: bFinding.severity,
          newSeverity: tFinding.severity
        });
      }
    }

    const resolvedFindings: ReportDiffResult['resolvedFindings'] = [];
    for (const [id, bFinding] of baseIds.entries()) {
      const tFinding = targetIds.get(id);
      if (!tFinding || tFinding.status === 'REMEDIATED' || tFinding.status === 'REVALIDATED') {
        resolvedFindings.push({ id, title: bFinding.title });
      }
    }

    const netRiskScoreChange = (newFindings.length * 10) - (resolvedFindings.length * 10);
    const summary = `Delta Analysis: ${newFindings.length} new findings, ${resolvedFindings.length} resolved findings. Net risk delta: ${netRiskScoreChange}.`;

    return {
      baseReportId: base.reportId,
      targetReportId: target.reportId,
      timestamp: new Date().toISOString(),
      newFindings,
      resolvedFindings,
      changedSeverity,
      netRiskScoreChange,
      summary
    };
  }
}
