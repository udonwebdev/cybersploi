/**
 * Scanner Orchestration Service
 * Coordinates all scanners (Nuclei, ZAP, Nmap) and job queue
 */

const NucleiScanner = require('./nuclei.service');
const ZapScanner = require('./zap.service');
const NmapScanner = require('./nmap.service');
const { prisma } = require('../config/database');
const jobQueue = require('./job-queue.service');

class ScannerService {
  constructor() {
    this.scanners = {
      nuclei: new NucleiScanner(),
      zap: new ZapScanner(),
      nmap: new NmapScanner()
    };

    this.jobQueue = jobQueue;
  }

  /**
   * Verify all scanners are installed
   */
  async verifyScanners() {
    const status = {};

    for (const [name, scanner] of Object.entries(this.scanners)) {
      try {
        status[name] = await scanner.checkInstallation();
      } catch (error) {
        status[name] = false;
        console.error(`Scanner ${name} check failed:`, error.message);
      }
    }

    return status;
  }

  /**
   * Get available scanners
   */
  async getAvailableScanners() {
    const available = [];
    const status = await this.verifyScanners();

    for (const [name, isInstalled] of Object.entries(status)) {
      if (isInstalled) {
        available.push({
          name: name,
          type: this.getScannerType(name),
          description: this.getScannerDescription(name)
        });
      }
    }

    return available;
  }

  /**
   * Get scanner type
   */
  getScannerType(scannerName) {
    switch (scannerName) {
      case 'nuclei':
        return 'web'; // Web/template-based scanning
      case 'zap':
        return 'web'; // Web application scanning
      case 'nmap':
        return 'network'; // Network scanning
      default:
        return 'unknown';
    }
  }

  /**
   * Get scanner description
   */
  getScannerDescription(scannerName) {
    switch (scannerName) {
      case 'nuclei':
        return 'ProjectDiscovery Nuclei - Template-based vulnerability scanning';
      case 'zap':
        return 'OWASP ZAP - Web application security scanning';
      case 'nmap':
        return 'Nmap - Network reconnaissance and service enumeration';
      default:
        return 'Unknown scanner';
    }
  }

  /**
   * Execute scan with specified scanners
   */
  async executeScan(scan, asset, config = {}) {
    try {
      // Validate inputs
      if (!scan || !scan.id) {
        throw new Error('Scan ID is required');
      }
      if (!asset || !asset.value) {
        throw new Error('Asset is required');
      }

      // Update scan status
      await prisma.scan.update({
        where: { id: scan.id },
        data: {
          status: 'running',
          progress: 0
        }
      });

      // Determine which scanners to use
      const scannersToUse = config.scanners || this.getDefaultScanners(asset.type);

      // Create scan jobs
      const jobs = [];
      for (const scannerName of scannersToUse) {
        const scanner = this.scanners[scannerName];
        if (!scanner) {
          console.warn(`Scanner ${scannerName} not found`);
          continue;
        }

        // Create job for this scanner
        const scanTask = async (onProgress) => {
          try {
            onProgress(10);
            const result = await scanner.execute(asset, config);
            onProgress(90);

            // Store findings in database
            await this.storeFindings(scan.id, asset.id, result);
            onProgress(100);

            return result;
          } catch (error) {
            console.error(`Scanner ${scannerName} failed:`, error.message);
            throw error;
          }
        };

        const job = await jobQueue.addScanJob({
          scanId: scan.id,
          assetId: asset.id,
          scannerName: scannerName,
          task: scanTask
        });

        jobs.push(job);
      }

      // Return job information
      return {
        scanId: scan.id,
        jobs: jobs,
        jobIds: jobs.map(j => j.id),
        scanners: scannersToUse,
        status: 'started'
      };
    } catch (error) {
      // Update scan status to failed
      await prisma.scan.update({
        where: { id: scan.id },
        data: {
          status: 'failed'
        }
      });

      throw error;
    }
  }

  /**
   * Get default scanners based on asset type
   */
  getDefaultScanners(assetType) {
    switch (assetType?.toUpperCase()) {
      case 'WEB':
      case 'WEBSITE':
      case 'API':
        return ['nuclei', 'zap']; // Web scanners
      case 'SERVER':
      case 'IP':
      case 'NETWORK':
        return ['nmap']; // Network scanner
      case 'DOMAIN':
        return ['nuclei', 'nmap']; // Both
      default:
        return ['nuclei']; // Default to nuclei
    }
  }

  /**
   * Store findings in database
   */
  async storeFindings(scanId, assetId, result) {
    const findings = result.findings || [];

    for (const finding of findings) {
      await prisma.vulnerability.upsert({
        where: {
          scanId_assetId_title: {
            scanId: scanId,
            assetId: assetId,
            title: finding.title
          }
        },
        update: {
          description: finding.description,
          type: finding.type,
          severity: finding.severity,
          cvss: finding.cvss || 0,
          cve: finding.cve,
          cwe: finding.cwe,
          evidence: finding.evidence,
          remediation: finding.remediation,
          status: 'open'
        },
        create: {
          scanId: scanId,
          assetId: assetId,
          organizationId: (await prisma.asset.findUnique({
            where: { id: assetId }
          }))?.organizationId,
          title: finding.title,
          description: finding.description,
          type: finding.type,
          severity: finding.severity,
          cvss: finding.cvss || 0,
          cve: finding.cve,
          cwe: finding.cwe,
          evidence: finding.evidence,
          remediation: finding.remediation,
          status: 'open'
        }
      });
    }

    // Update scan with summary
    await prisma.scan.update({
      where: { id: scanId },
      data: {
        findingsCritical: findings.filter(f => f.severity === 'CRITICAL').length,
        findingsHigh: findings.filter(f => f.severity === 'HIGH').length,
        findingsMedium: findings.filter(f => f.severity === 'MEDIUM').length,
        findingsLow: findings.filter(f => f.severity === 'LOW').length,
        findingsInfo: findings.filter(f => f.severity === 'INFO').length
      }
    });
  }

  /**
   * Get scan progress
   */
  async getScanProgress(scanId) {
    const scan = await prisma.scan.findUnique({
      where: { id: scanId }
    });

    if (!scan) {
      throw new Error('Scan not found');
    }

    // Get jobs for this scan
    const jobs = this.jobQueue.getScanJobs(scanId);

    let totalProgress = 0;
    if (jobs.length > 0) {
      totalProgress = jobs.reduce((sum, job) => sum + job.progress, 0) / jobs.length;
    }

    return {
      scanId: scan.id,
      status: scan.status,
      progress: totalProgress,
      jobs: jobs.length,
      completedJobs: jobs.filter(j => j.status === 'completed').length,
      failedJobs: jobs.filter(j => j.status === 'failed').length,
      findings: {
        critical: scan.findingsCritical,
        high: scan.findingsHigh,
        medium: scan.findingsMedium,
        low: scan.findingsLow,
        info: scan.findingsInfo,
        total: (scan.findingsCritical || 0) + (scan.findingsHigh || 0) + 
               (scan.findingsMedium || 0) + (scan.findingsLow || 0) + (scan.findingsInfo || 0)
      }
    };
  }

  /**
   * Perform quick scan (Nuclei high/critical only)
   */
  async quickScan(asset, organizationId) {
    const scan = await prisma.scan.create({
      data: {
        organizationId: organizationId,
        assetId: asset.id,
        type: 'quick',
        status: 'pending'
      }
    });

    const nuclei = this.scanners.nuclei;
    const result = await nuclei.quickScan(asset);

    await this.storeFindings(scan.id, asset.id, result);

    return scan;
  }

  /**
   * Perform full scan (all severity levels, all scanners)
   */
  async fullScan(asset, organizationId) {
    const scan = await prisma.scan.create({
      data: {
        organizationId: organizationId,
        assetId: asset.id,
        type: 'full',
        status: 'pending'
      }
    });

    return this.executeScan(scan, asset, {
      scanners: this.getDefaultScanners(asset.type),
      severity: ['critical', 'high', 'medium', 'low', 'info']
    });
  }

  /**
   * Perform custom scan with specific options
   */
  async customScan(asset, organizationId, options = {}) {
    const scan = await prisma.scan.create({
      data: {
        organizationId: organizationId,
        assetId: asset.id,
        type: 'custom',
        status: 'pending',
        configuration: options
      }
    });

    return this.executeScan(scan, asset, options);
  }

  /**
   * Get scan results
   */
  async getScanResults(scanId) {
    const vulnerabilities = await prisma.vulnerability.findMany({
      where: { scanId: scanId }
    });

    return {
      scanId: scanId,
      vulnerabilityCount: vulnerabilities.length,
      vulnerabilities: vulnerabilities
    };
  }

  /**
   * Cancel scan
   */
  async cancelScan(scanId) {
    const jobs = this.jobQueue.getScanJobs(scanId);

    for (const job of jobs) {
      this.jobQueue.cancelJob(job.id);
    }

    await prisma.scan.update({
      where: { id: scanId },
      data: { status: 'cancelled' }
    });

    return { scanId: scanId, status: 'cancelled' };
  }
}

module.exports = new ScannerService();
