/**
 * Reconnaissance Orchestration Service
 * Central coordinator for all reconnaissance modules
 * Manages Subdomain Enumeration, Service Detection, Cloud Security, Attack Paths
 * 
 * Responsibilities:
 * - Execute reconnaissance in correct order (dependencies)
 * - Aggregate findings from all modules
 * - Build comprehensive attack surface
 * - Store findings in database
 * - Track progress
 * - Handle errors with fallbacks
 */

const axios = require('axios');
const { promisify } = require('util');

class ReconOrchestrationService {
  constructor(config = {}) {
    this.name = 'Reconnaissance Orchestration';
    this.version = '1.0.0';
    this.config = config;
    this.supportedReconTypes = [
      'subdomain-enumeration',
      'service-detection',
      'cloud-security',
      'attack-path-discovery',
    ];
    this.db = config.db;
    this.queue = config.queue;
    this.cache = config.cache;
  }

  /**
   * Verify all reconnaissance modules are available
   */
  async verifyReconModules() {
    const SubdomainEnumerationService = require('./subdomain-enumeration.service');
    const ServiceDetectionService = require('./service-detection.service');
    const CloudSecurityService = require('./cloud-security.service');
    const AttackPathDiscoveryService = require('./attack-path-discovery.service');

    const modules = {
      subdomains: new SubdomainEnumerationService(this.config),
      services: new ServiceDetectionService(this.config),
      cloudSecurity: new CloudSecurityService(this.config),
      attackPaths: new AttackPathDiscoveryService(this.config),
    };

    const status = {};
    for (const [name, module] of Object.entries(modules)) {
      try {
        const check = await module.checkInstallation?.();
        status[name] = check || { installed: true };
      } catch (e) {
        status[name] = { installed: false, error: e.message };
      }
    }

    return status;
  }

  /**
   * Get available reconnaissance types
   */
  getAvailableReconTypes() {
    return this.supportedReconTypes;
  }

  /**
   * Execute full reconnaissance pipeline
   */
  async executeRecognaissance(asset, config = {}) {
    const scanType = config.scanType || 'standard'; // quick, standard, deep
    const reconTypes = config.reconTypes || ['subdomains', 'services', 'cloudSecurity', 'attackPaths'];

    const reconId = `recon-${asset.id}-${Date.now()}`;
    const startTime = Date.now();

    try {
      // Initialize tracking
      const progress = {
        reconId: reconId,
        assetId: asset.id,
        status: 'running',
        progress: 0,
        totalSteps: reconTypes.length + 1,
        currentStep: 0,
        modules: {},
        findings: [],
        errors: [],
      };

      // Step 1: Subdomain Enumeration (if enabled)
      if (reconTypes.includes('subdomains')) {
        try {
          progress.modules.subdomainEnumeration = { status: 'running' };
          const SubdomainEnumerationService = require('./subdomain-enumeration.service');
          const subdomainService = new SubdomainEnumerationService(this.config);

          const subdomainResults = await subdomainService.execute(asset, { scanType });
          progress.modules.subdomainEnumeration = {
            status: 'completed',
            enumerated: subdomainResults.enumerated || 0,
            findings: subdomainResults.findings?.length || 0,
          };

          progress.findings.push(...(subdomainResults.findings || []));
          progress.subdomains = subdomainResults.subdomains || [];

          // Store in database
          if (this.db && subdomainResults.findings) {
            await this.storeFindingsInDatabase(reconId, subdomainResults.findings);
          }
        } catch (e) {
          progress.errors.push({
            module: 'subdomain-enumeration',
            error: e.message,
          });
          progress.modules.subdomainEnumeration = { status: 'error', error: e.message };
        }
      }

      // Step 2: Service Detection (if enabled)
      if (reconTypes.includes('services') && progress.subdomains?.length > 0) {
        try {
          progress.modules.serviceDetection = { status: 'running' };
          const ServiceDetectionService = require('./service-detection.service');
          const serviceService = new ServiceDetectionService(this.config);

          const serviceResults = await serviceService.execute(asset, progress.subdomains, { scanType });
          progress.modules.serviceDetection = {
            status: 'completed',
            detected: serviceResults.detected || 0,
            findings: serviceResults.findings?.length || 0,
          };

          progress.findings.push(...(serviceResults.findings || []));
          progress.services = serviceResults.services || [];

          // Store in database
          if (this.db && serviceResults.findings) {
            await this.storeFindingsInDatabase(reconId, serviceResults.findings);
          }
        } catch (e) {
          progress.errors.push({
            module: 'service-detection',
            error: e.message,
          });
          progress.modules.serviceDetection = { status: 'error', error: e.message };
        }
      }

      // Step 3: Cloud Security Testing (if enabled)
      if (reconTypes.includes('cloudSecurity')) {
        try {
          progress.modules.cloudSecurity = { status: 'running' };
          const CloudSecurityService = require('./cloud-security.service');
          const cloudService = new CloudSecurityService(this.config);

          const cloudResults = await cloudService.execute(asset, { scanType });
          progress.modules.cloudSecurity = {
            status: 'completed',
            issues: cloudResults.issuesFound || 0,
            findings: cloudResults.findings?.length || 0,
          };

          progress.findings.push(...(cloudResults.findings || []));

          // Store in database
          if (this.db && cloudResults.findings) {
            await this.storeFindingsInDatabase(reconId, cloudResults.findings);
          }
        } catch (e) {
          progress.errors.push({
            module: 'cloud-security',
            error: e.message,
          });
          progress.modules.cloudSecurity = { status: 'error', error: e.message };
        }
      }

      // Step 4: Attack Path Discovery (if enabled)
      if (reconTypes.includes('attackPaths') && progress.findings?.length > 0) {
        try {
          progress.modules.attackPathDiscovery = { status: 'running' };
          const AttackPathDiscoveryService = require('./attack-path-discovery.service');
          const pathService = new AttackPathDiscoveryService(this.config);

          const pathResults = await pathService.execute(progress.findings, { scanType });
          progress.modules.attackPathDiscovery = {
            status: 'completed',
            chains: pathResults.chainCount || 0,
            criticalChains: pathResults.criticalChainCount || 0,
            findings: pathResults.findings?.length || 0,
          };

          progress.findings.push(...(pathResults.findings || []));

          // Store in database
          if (this.db && pathResults.findings) {
            await this.storeFindingsInDatabase(reconId, pathResults.findings);
          }
        } catch (e) {
          progress.errors.push({
            module: 'attack-path-discovery',
            error: e.message,
          });
          progress.modules.attackPathDiscovery = { status: 'error', error: e.message };
        }
      }

      // Finalize
      const endTime = Date.now();
      progress.status = 'completed';
      progress.progress = 100;
      progress.totalFindings = progress.findings.length;
      progress.severity = this.calculateOverallSeverity(progress.findings);
      progress.duration = endTime - startTime;

      // Store reconnaissance record
      if (this.db) {
        await this.storeReconRecord(reconId, progress);
      }

      return progress;
    } catch (error) {
      return {
        reconId: reconId,
        status: 'error',
        error: error.message,
        findings: [],
        modules: {},
      };
    }
  }

  /**
   * Execute single reconnaissance module
   */
  async executeReconModule(moduleName, asset, config = {}) {
    try {
      switch (moduleName) {
        case 'subdomains':
          const SubdomainEnumerationService = require('./subdomain-enumeration.service');
          const subdomainService = new SubdomainEnumerationService(this.config);
          return await subdomainService.execute(asset, config);

        case 'services':
          const ServiceDetectionService = require('./service-detection.service');
          const serviceService = new ServiceDetectionService(this.config);
          return await serviceService.execute(asset, [], config);

        case 'cloudSecurity':
          const CloudSecurityService = require('./cloud-security.service');
          const cloudService = new CloudSecurityService(this.config);
          return await cloudService.execute(asset, config);

        case 'attackPaths':
          const AttackPathDiscoveryService = require('./attack-path-discovery.service');
          const pathService = new AttackPathDiscoveryService(this.config);
          return await pathService.execute([], config);

        default:
          throw new Error(`Unknown reconnaissance module: ${moduleName}`);
      }
    } catch (error) {
      return {
        status: 'error',
        error: error.message,
        module: moduleName,
      };
    }
  }

  /**
   * Get reconnaissance progress
   */
  async getReconProgress(reconId) {
    if (this.cache) {
      const cached = await this.cache.get(`recon:progress:${reconId}`);
      if (cached) {
        return JSON.parse(cached);
      }
    }

    return { status: 'not-found', reconId };
  }

  /**
   * Cancel ongoing reconnaissance
   */
  async cancelRecognaissance(reconId) {
    if (this.queue) {
      // Cancel any queued recon jobs
      const jobs = await this.queue.getJobs(['active', 'wait']);
      for (const job of jobs) {
        if (job.data?.reconId === reconId) {
          await job.remove();
        }
      }
    }

    return { reconId, cancelled: true };
  }

  /**
   * Store findings in database
   */
  async storeFindingsInDatabase(reconId, findings) {
    if (!this.db || !findings || findings.length === 0) {
      return;
    }

    try {
      for (const finding of findings) {
        await this.db.vulnerability.create({
          data: {
            title: finding.title,
            severity: finding.severity,
            cvss: finding.cvss,
            cve: finding.cve,
            cwe: finding.cwe,
            description: finding.description,
            evidence: finding.evidence,
            remediation: finding.remediation,
            source: finding.source,
            tags: finding.tags?.join(',') || '',
            metadata: JSON.stringify({
              reconId,
              timestamp: new Date(),
            }),
          },
        });
      }
    } catch (e) {
      console.error('Error storing findings in database:', e);
    }
  }

  /**
   * Store reconnaissance record
   */
  async storeReconRecord(reconId, progress) {
    if (!this.db) {
      return;
    }

    try {
      // Store as scan record with findings
      await this.db.scan.create({
        data: {
          status: progress.status,
          type: 'reconnaissance',
          startedAt: new Date(Date.now() - progress.duration),
          completedAt: new Date(),
          results: JSON.stringify({
            reconId,
            totalFindings: progress.totalFindings,
            modules: progress.modules,
            errors: progress.errors,
          }),
        },
      });
    } catch (e) {
      console.error('Error storing reconnaissance record:', e);
    }
  }

  /**
   * Calculate overall severity from findings
   */
  calculateOverallSeverity(findings) {
    if (!findings || findings.length === 0) {
      return 'INFO';
    }

    const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    const foundSeverities = findings.map(f => f.severity);

    for (const severity of severityOrder) {
      if (foundSeverities.includes(severity)) {
        return severity;
      }
    }

    return 'INFO';
  }

  /**
   * Generate reconnaissance summary
   */
  generateReconSummary(progress) {
    const summary = {
      totalFindings: progress.totalFindings || 0,
      severity: progress.severity,
      duration: progress.duration,
      modules: progress.modules,
      findingsByModule: {},
    };

    // Count findings by module
    progress.findings?.forEach(finding => {
      const source = finding.source || 'unknown';
      if (!summary.findingsByModule[source]) {
        summary.findingsByModule[source] = 0;
      }
      summary.findingsByModule[source]++;
    });

    return summary;
  }

  /**
   * Export reconnaissance results
   */
  exportResults(progress, format = 'json') {
    switch (format) {
      case 'json':
        return JSON.stringify(progress, null, 2);

      case 'csv':
        let csv = 'Title,Severity,CVSS,CWE,Source\n';
        progress.findings?.forEach(f => {
          csv += `"${f.title}","${f.severity}",${f.cvss},${f.cwe},"${f.source}"\n`;
        });
        return csv;

      case 'html':
        return this.generateHTMLReport(progress);

      default:
        return JSON.stringify(progress);
    }
  }

  /**
   * Generate HTML report
   */
  generateHTMLReport(progress) {
    const summary = this.generateReconSummary(progress);

    return `
<!DOCTYPE html>
<html>
<head>
  <title>Reconnaissance Report</title>
  <style>
    body { font-family: Arial; margin: 20px; }
    .critical { color: #d32f2f; }
    .high { color: #f57c00; }
    .medium { color: #fbc02d; }
    .low { color: #388e3c; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background-color: #f5f5f5; }
  </style>
</head>
<body>
  <h1>Reconnaissance Report</h1>
  <p>Total Findings: <strong>${summary.totalFindings}</strong></p>
  <p>Overall Severity: <strong class="${summary.severity.toLowerCase()}">${summary.severity}</strong></p>
  <p>Duration: <strong>${(summary.duration / 1000).toFixed(1)}s</strong></p>

  <h2>Module Summary</h2>
  <table>
    <tr>
      <th>Module</th>
      <th>Status</th>
      <th>Findings</th>
    </tr>
    ${Object.entries(summary.findingsByModule).map(([module, count]) => `
    <tr>
      <td>${module}</td>
      <td>Completed</td>
      <td>${count}</td>
    </tr>
    `).join('')}
  </table>

  <h2>Findings</h2>
  <table>
    <tr>
      <th>Title</th>
      <th>Severity</th>
      <th>CVSS</th>
      <th>Source</th>
    </tr>
    ${progress.findings?.map(f => `
    <tr>
      <td>${f.title}</td>
      <td class="${f.severity.toLowerCase()}">${f.severity}</td>
      <td>${f.cvss}</td>
      <td>${f.source}</td>
    </tr>
    `).join('') || '<tr><td colspan="4">No findings</td></tr>'}
  </table>
</body>
</html>
    `;
  }
}

module.exports = ReconOrchestrationService;
