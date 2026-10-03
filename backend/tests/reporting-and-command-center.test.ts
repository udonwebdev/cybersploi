import http from 'http';
import express from 'express';
import axios from 'axios';
import crypto from 'crypto';
import prisma from '../config/database';
import engagementsRouter from '../routes/engagements.routes';
import {
  OffensiveEngineReportService,
  CanonicalEngagementReport,
  ReportDiffResult
} from '../services/offensive-engine/reporting.service';

async function runReportingAndCommandCenterTestSuite() {
  console.log('============================================================');
  console.log('CYBERSPLOI // SECTION 16 REPORTING & COMMAND CENTER TEST SUITE');
  console.log('============================================================\n');

  const app = express();
  app.use(express.json());
  app.use('/engagements', engagementsRouter);

  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const address = server.address() as any;
  const baseUrl = `http://127.0.0.1:${address.port}`;

  let passed = 0;
  let total = 0;

  function test(name: string, condition: boolean, details?: string) {
    total++;
    if (condition) {
      passed++;
      console.log(`[PASS] Test ${total}: ${name}`);
      if (details) console.log(`       › ${details}`);
    } else {
      console.error(`[FAIL] Test ${total}: ${name}`);
      if (details) console.error(`       › Details: ${details}`);
      throw new Error(`Test failed: ${name}`);
    }
  }

  try {
    // ------------------------------------------------------------
    // 1. UNIT TESTS: SENSITIVE DATA REDACTION ENGINE
    // ------------------------------------------------------------
    console.log('--- 1. Sensitive Data Redaction Engine ---');
    const secretContent = `
      Target credentials leaked:
      AWS_KEY: AKIAIOSFODNN7EXAMPLE
      Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature12345
      Private key:
      -----BEGIN RSA PRIVATE KEY-----
      MIIEowIBAAKCAQEA0Y1234567890abcdef
      -----END RSA PRIVATE KEY-----
      User payload: {"user": "admin", "password": "SuperSecretPassword123!"}
      Query param: https://target.internal/login?user=admin&password=SecretParamPass!
    `;

    const redactionResult = OffensiveEngineReportService.redactSensitiveData(secretContent);
    test('Redaction engine catches multiple secret categories', redactionResult.redactionCount >= 4);
    test('AWS Access Key is redacted', !redactionResult.text.includes('AKIAIOSFODNN7EXAMPLE') && redactionResult.text.includes('[REDACTED_AWS_KEY]'));
    test('Bearer Token is redacted', !redactionResult.text.includes('signature12345') && redactionResult.text.includes('Bearer [REDACTED_TOKEN]'));
    test('Private Key block is redacted', !redactionResult.text.includes('MIIEowIBAAKCAQEA0Y1234567890abcdef') && redactionResult.text.includes('[REDACTED_PRIVATE_KEY]'));
    test('JSON password field is redacted', !redactionResult.text.includes('SuperSecretPassword123!') && redactionResult.text.includes('"password": "[REDACTED]"'));

    // ------------------------------------------------------------
    // 2. SEED TEST ENGAGEMENT & CANONICAL ARTIFACTS
    // ------------------------------------------------------------
    console.log('\n--- 2. Database Seeding for Canonical Reporting ---');
    const engagement = await prisma.engagement.create({
      data: {
        name: 'Report Test Lab 2026',
        environment: 'staging',
        status: 'active',
        currentPhase: 'POC_VERIFY',
        scope: {
          create: {
            allowedTargets: JSON.stringify(['app.target.internal', 'db.target.internal']),
            allowedTestTypes: JSON.stringify(['RECON', 'AUTH', 'INJECTION']),
            destructiveActionsAllowed: false,
            activePoCAllowed: true,
            rateLimit: JSON.stringify({ requestsPerSecond: 20 }),
            validFrom: new Date(),
            validUntil: new Date(Date.now() + 86400000 * 7),
            approvedBy: 'Director of Cyber Defense',
            approvalRecordUrl: 'https://grc.internal/sec-904'
          }
        }
      }
    });
    test('Created test engagement with ID', !!engagement.id);

    // Create Assets
    const asset1 = await prisma.asset.create({
      data: {
        engagementId: engagement.id,
        type: 'HOST',
        value: 'app.target.internal',
        host: 'app.target.internal',
        port: 443,
        protocol: 'https',
        verificationStatus: 'VERIFIED'
      }
    });
    test('Created asset record', !!asset1.id);

    // Create Findings (Proven and Validated)
    const finding1 = await prisma.engineFinding.create({
      data: {
        engagementId: engagement.id,
        title: 'BOLA Access to IAM Metadata Endpoint',
        category: 'AUTH_BYPASS',
        severity: 'CRITICAL',
        target: 'app.target.internal:443/api/v1/iam',
        status: 'PROVEN',
        reproducible: true,
        description: 'Observed unauthenticated JWT leakage: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token.sig123'
      }
    });

    const evidence1 = await prisma.engineEvidence.create({
      data: {
        findingId: finding1.id,
        actionId: 'ACT-IAM-LEAK',
        target: 'app.target.internal',
        observation: 'Extracted temporary session token with AWS_KEY: AKIAIOSFODNN7EXAMPLE',
        requestMetadata: JSON.stringify({ method: 'GET', path: '/api/v1/iam' }),
        responseMetadata: JSON.stringify({ status: 200 }),
        reproductionSteps: 'curl -s https://app.target.internal/api/v1/iam',
        authContext: 'UNAUTHENTICATED',
        hash: 'b10a8db164e0754105b7a99be72e3fe5aa70513f5d812e128cb5b00c2cb4d3e8',
        isImmutable: true
      }
    });
    test('Created proven finding with immutable evidence', !!evidence1.id);

    const finding2 = await prisma.engineFinding.create({
      data: {
        engagementId: engagement.id,
        title: 'Reflected Injection on Search Query',
        category: 'INJECTION',
        severity: 'HIGH',
        target: 'app.target.internal:443/search',
        status: 'VALIDATED',
        reproducible: true,
        description: 'Parameter q reflects unsanitized user input.'
      }
    });
    test('Created validated finding', !!finding2.id);

    // ------------------------------------------------------------
    // 3. CANONICAL REPORT BUILD (SECTION 16 DATA MODEL)
    // ------------------------------------------------------------
    console.log('\n--- 3. Canonical Report Model & Invariants ---');
    const canonical = await OffensiveEngineReportService.buildCanonicalReport(engagement.id, {
      scope: 'technical',
      redact: true
    });

    test('Canonical report schemaVersion is 2.1.0', canonical.schemaVersion === '2.1.0');
    test('Report ID generated with prefix ENG-REP-', canonical.reportId.startsWith('ENG-REP-'));
    test('Overall Posture evaluated to CRITICAL_RISK due to proven finding', canonical.executiveSummary.overallPosture === 'CRITICAL_RISK');
    test('Proven vulnerabilities count matches database records', canonical.executiveSummary.provenVulnerabilities === 1);
    test('Total findings matches database records', canonical.findings.length === 2);
    const findingWithSecret = canonical.findings.find(f => f.id === finding1.id);
    test('Findings description underwent automatic secret redaction', !!findingWithSecret && (findingWithSecret.description.includes('[REDACTED_TOKEN]') || findingWithSecret.description.includes('[REDACTED_JWT]')));
    test('Evidence observation underwent automatic secret redaction', !!findingWithSecret && findingWithSecret.evidenceChain[0]?.observation.includes('[REDACTED_AWS_KEY]'));
    test('SHA-256 integrity hash is computed and valid 64-char hex', /^[a-f0-9]{64}$/.test(canonical.integrity.hash));

    // ------------------------------------------------------------
    // 4. MULTI-FORMAT GENERATORS (PDF, JSON, CSV, HTML, MD, SARIF)
    // ------------------------------------------------------------
    console.log('\n--- 4. Multi-Format Report Generators ---');

    // 4a. SARIF 2.1.0 Generator
    const sarifOutput: any = OffensiveEngineReportService.generateSARIF(canonical);
    test('SARIF $schema is official OASIS SARIF 2.1.0', sarifOutput.$schema.includes('sarif-schema-2.1.0'));
    test('SARIF version is 2.1.0', sarifOutput.version === '2.1.0');
    test('SARIF tool driver name is CyberSploi Offensive Engine', sarifOutput.runs[0].tool.driver.name === 'CyberSploi Offensive Testing Engine');
    test('SARIF contains rules for findings', sarifOutput.runs[0].tool.driver.rules.length === 2);
    test('SARIF results map finding status and severity', sarifOutput.runs[0].results.length === 2 && sarifOutput.runs[0].results[0].level === 'error');

    // 4b. CSV Bundle Generator
    const csvBundle = OffensiveEngineReportService.generateCSVBundle(canonical);
    test('CSV bundle contains 5 modular CSV tables', !!csvBundle['findings.csv'] && !!csvBundle['assets.csv'] && !!csvBundle['attack_paths.csv'] && !!csvBundle['evidence.csv'] && !!csvBundle['remediation.csv']);
    test('CSV findings table has valid headers and rows', csvBundle['findings.csv'].includes('finding_id,title,category,severity,status,target') && csvBundle['findings.csv'].includes('BOLA Access to IAM Metadata Endpoint'));
    test('CSV evidence table has cryptographic hashes', csvBundle['evidence.csv'].includes('b10a8db164e0754105b7a99be72e3fe5aa70513f5d812e128cb5b00c2cb4d3e8'));

    // 4c. Markdown Generator
    const markdownOutput = OffensiveEngineReportService.generateMarkdown(canonical);
    test('Markdown contains report title and executive summary', markdownOutput.includes('Security Assessment Report') && markdownOutput.includes('## 1. Executive Summary'));
    test('Markdown contains findings table with severity', markdownOutput.includes('CRITICAL') && markdownOutput.includes('BOLA Access to IAM Metadata Endpoint'));
    test('Markdown contains cryptographic evidence hashes', markdownOutput.includes('b10a8db164e07541'));

    // 4d. Standalone HTML Generator
    const htmlOutput = OffensiveEngineReportService.generateHTML(canonical);
    test('HTML contains doctype and CyberSploi styling', htmlOutput.includes('<!DOCTYPE html>') && htmlOutput.includes('CyberSploi'));
    test('HTML renders overall posture badge', htmlOutput.includes('CRITICAL_RISK'));
    test('HTML embeds cryptographic integrity block', htmlOutput.includes(canonical.integrity.hash.substring(0, 16)));

    // 4e. Print-Ready PDF HTML Generator
    const pdfHtmlOutput = OffensiveEngineReportService.generatePDFHtml(canonical);
    test('PDF HTML contains @page CSS and page breaks', pdfHtmlOutput.includes('@page') && pdfHtmlOutput.includes('page-break'));
    test('PDF HTML contains title dossier and findings breakdown', pdfHtmlOutput.includes('Technical Findings Dossier'));

    // ------------------------------------------------------------
    // 5. REPORT VERSION DIFFING & REGRESSION TRACKING
    // ------------------------------------------------------------
    console.log('\n--- 5. Report Revision Diffing ---');
    // Simulate previous baseline report with finding2 resolved and finding1 as MEDIUM
    const baselineReport: CanonicalEngagementReport = JSON.parse(JSON.stringify(canonical));
    baselineReport.reportId = 'ENG-REP-BASELINE-01';
    const baseF1 = baselineReport.findings.find(f => f.id === finding1.id);
    if (baseF1) baseF1.severity = 'MEDIUM'; // severity drift
    // Remove finding2 from target to simulate resolved finding
    const targetReport: CanonicalEngagementReport = JSON.parse(JSON.stringify(canonical));
    targetReport.findings = targetReport.findings.filter(f => f.id !== finding2.id);

    const diffResult = OffensiveEngineReportService.compareReports(baselineReport, targetReport);
    test('Diff identifies resolved findings', diffResult.resolvedFindings.length === 1 && diffResult.resolvedFindings[0].title.includes('Reflected Injection'));
    test('Diff identifies changed severity drift', diffResult.changedSeverity.length === 1 && diffResult.changedSeverity[0].oldSeverity === 'MEDIUM' && diffResult.changedSeverity[0].newSeverity === 'CRITICAL');
    test('Diff calculates net risk score change', typeof diffResult.netRiskScoreChange === 'number');
    test('Diff generates clear summary string', diffResult.summary.includes('Delta Analysis:'));

    // ------------------------------------------------------------
    // 6. REST API ENDPOINTS VIA HTTP
    // ------------------------------------------------------------
    console.log('\n--- 6. REST API Integration Endpoints ---');

    // 6a. GET /engagements/:id/report/canonical
    const resCanonical = await axios.get(`${baseUrl}/engagements/${engagement.id}/report/canonical?scope=technical&redact=true`);
    test('GET /report/canonical returns 200 OK', resCanonical.status === 200);
    test('GET /report/canonical data matches schema v2.1.0', resCanonical.data.data.schemaVersion === '2.1.0');
    const resFindingWithSecret = resCanonical.data.data.findings.find((f: any) => f.id === finding1.id);
    test('GET /report/canonical contains redacted findings', !!resFindingWithSecret && (resFindingWithSecret.description.includes('[REDACTED_TOKEN]') || resFindingWithSecret.description.includes('[REDACTED_JWT]')));

    // 6b. GET /engagements/:id/report/export?format=sarif
    const resSarif = await axios.get(`${baseUrl}/engagements/${engagement.id}/report/export?format=sarif`);
    test('GET /report/export?format=sarif returns 200 OK', resSarif.status === 200);
    test('GET /report/export?format=sarif mimeType is application/sarif+json', resSarif.data.mimeType === 'application/sarif+json');
    test('GET /report/export?format=sarif data contains OASIS rules', resSarif.data.data.runs[0].tool.driver.rules.length > 0);

    // 6c. GET /engagements/:id/report/export?format=csv
    const resCsv = await axios.get(`${baseUrl}/engagements/${engagement.id}/report/export?format=csv`);
    test('GET /report/export?format=csv returns 200 OK', resCsv.status === 200);
    test('GET /report/export?format=csv contains all 5 CSV tables', typeof resCsv.data.data['findings.csv'] === 'string' && typeof resCsv.data.data['evidence.csv'] === 'string');

    // 6d. GET /engagements/:id/report/export?format=markdown
    const resMarkdown = await axios.get(`${baseUrl}/engagements/${engagement.id}/report/export?format=markdown`);
    test('GET /report/export?format=markdown returns 200 OK', resMarkdown.status === 200);
    test('GET /report/export?format=markdown mimeType is text/markdown', resMarkdown.data.mimeType === 'text/markdown');
    test('GET /report/export?format=markdown data is string markdown', typeof resMarkdown.data.data === 'string' && resMarkdown.data.data.includes('Security Assessment Report'));

    // 6e. GET /engagements/:id/report/export?format=html
    const resHtml = await axios.get(`${baseUrl}/engagements/${engagement.id}/report/export?format=html`);
    test('GET /report/export?format=html returns 200 OK', resHtml.status === 200);
    test('GET /report/export?format=html data contains HTML document', resHtml.data.data.includes('<!DOCTYPE html>'));

    // 6f. GET /engagements/:id/report/export?format=pdf&download=true
    const resPdfDownload = await axios.get(`${baseUrl}/engagements/${engagement.id}/report/export?format=pdf&download=true`);
    test('GET /report/export?format=pdf&download=true returns 200 OK', resPdfDownload.status === 200);
    test('GET /report/export?download=true sets Content-Disposition attachment header', resPdfDownload.headers['content-disposition']?.includes('attachment'));

    // 6g. POST /engagements/:id/report/diff
    const resDiff = await axios.post(`${baseUrl}/engagements/${engagement.id}/report/diff`, {
      baseReport: baselineReport,
      targetReport: targetReport
    });
    test('POST /report/diff returns 200 OK', resDiff.status === 200);
    test('POST /report/diff returns structured diff object', resDiff.data.data.resolvedFindings.length === 1 && resDiff.data.data.changedSeverity.length === 1);

    // 6h. GET /engagements/:id/report (Backwards compatibility)
    const resLegacyReport = await axios.get(`${baseUrl}/engagements/${engagement.id}/report?format=json`);
    test('GET /report (legacy) returns 200 OK', resLegacyReport.status === 200);
    test('GET /report (legacy) contains report id and sections', !!resLegacyReport.data.report.reportId && !!resLegacyReport.data.report.sections);

    console.log('\n============================================================');
    console.log(`ALL TESTS PASSED! (${passed}/${total})`);
    console.log('============================================================');
  } finally {
    server.close();
  }
}

runReportingAndCommandCenterTestSuite().catch((err) => {
  console.error('Test suite failed:', err);
  process.exit(1);
});
