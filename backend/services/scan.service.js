const prisma = require('../config/database');
const { SCAN_TYPES, SCAN_STATUS, SEVERITY } = require('../config/constants');
const RealScannerEngine = require('./real-scanner-engine.service');
const RedTeamOrchestratorService = require('./red-team/red-team-orchestrator.service');

class ScanService {
  static formatScan(scan) {
    const targetVal = scan.asset?.value || 'Scoped Target';
    const vulns = scan.vulnerabilities || [];
    const critCount = scan.criticalCount !== undefined && scan.criticalCount > 0
      ? scan.criticalCount
      : vulns.filter(v => v.severity?.toLowerCase() === 'critical').length;
    const highCount = scan.highCount !== undefined && scan.highCount > 0
      ? scan.highCount
      : vulns.filter(v => v.severity?.toLowerCase() === 'high').length;
    const medCount = scan.mediumCount !== undefined && scan.mediumCount > 0
      ? scan.mediumCount
      : vulns.filter(v => v.severity?.toLowerCase() === 'medium').length;
    const lowCount = scan.lowCount !== undefined && scan.lowCount > 0
      ? scan.lowCount
      : vulns.filter(v => v.severity?.toLowerCase() === 'low' || v.severity?.toLowerCase() === 'info').length;

    return {
      id: scan.id,
      name: `Pentest Scan - ${targetVal}`,
      target: targetVal,
      type: (scan.type || 'vulnerability').toUpperCase(),
      status: scan.status,
      progress: scan.progress || 0,
      criticalCount: critCount,
      highCount: highCount,
      mediumCount: medCount,
      lowCount: lowCount,
      findings: scan.findings || vulns.length,
      startedAt: scan.startedAt,
      completedAt: scan.completedAt,
      createdAt: scan.createdAt,
      asset: scan.asset,
      vulnerabilities: vulns,
      redTeamAssessment: scan.redTeamAssessment || null,
      logs: scan.redTeamAssessment?.events?.length > 0
        ? scan.redTeamAssessment.events.map(e => `[${e.phase}] ${e.message}`)
        : [
            `[Engine] Initialized autonomous scan orchestrator for ${targetVal}`,
            `[Engine] Mode: ${(scan.type || 'vulnerability').toUpperCase()} | Status: ${scan.status.toUpperCase()}`,
            `[Engine] Current execution progress: ${scan.progress}%`,
            ...(vulns.map(v => `[Finding] ${v.severity.toUpperCase()}: ${v.title} (${v.cve || 'Advisory'})`))
          ]
    };
  }

  /**
   * Create a new scan
   */
  static async createScan(organizationId, data) {
    const assetIdentifier = data.assetId || data.target || 'https://api.cybersploi.io';
    const scanType = (data.type || data.scanType || SCAN_TYPES.QUICK || 'quick').toLowerCase();
    const configuration = data.configuration || data.profile || null;

    // Verify or find asset
    let asset = await prisma.asset.findFirst({
      where: {
        organizationId,
        OR: [
          { id: assetIdentifier },
          { value: assetIdentifier }
        ]
      }
    });

    if (!asset) {
      // Auto-provision asset if not already registered
      asset = await prisma.asset.create({
        data: {
          organizationId,
          type: 'api',
          value: assetIdentifier,
          description: `Target ${assetIdentifier}`,
          verificationStatus: 'verified'
        }
      });
    }

    const configStr = typeof configuration === 'object' ? JSON.stringify(configuration) : (configuration || null);

    // Create scan in database
    const scan = await prisma.scan.create({
      data: {
        organizationId,
        assetId: asset.id,
        type: scanType,
        status: SCAN_STATUS.RUNNING,
        progress: 5,
        configuration: configStr,
        startedAt: new Date()
      },
      include: {
        asset: true
      }
    });

    // Launch real background execution engine
    this.executeScanWorker(scan.id, asset, scanType, configStr, organizationId);

    return this.formatScan(scan);
  }

  /**
   * Background scan worker that advances progress and writes real findings
   */
  static executeScanWorker(scanId, asset, scanType, configuration = null, organizationId = null) {
    if (scanType.toLowerCase() === 'aggressive') {
      // Dispatch Autonomous Ultra-Deep Red Team Orchestrator
      RedTeamOrchestratorService.executeAssessment(scanId, asset, configuration, organizationId).catch((err) => {
        console.error('[ScanService] Red Team Orchestrator failed:', err);
      });
    } else {
      // Dispatch standard network & vulnerability probe asynchronously
      RealScannerEngine.executeRealScan(scanId, asset, scanType).catch((err) => {
        console.error('[ScanService] Real scanner execution failed:', err);
      });
    }
  }

  /**
   * Get scan by ID
   */
  static async getScan(organizationId, scanId) {
    const scan = await prisma.scan.findFirst({
      where: {
        id: scanId,
        organizationId
      },
      include: {
        asset: {
          select: {
            id: true,
            type: true,
            value: true
          }
        },
        results: true,
        redTeamAssessment: {
          include: {
            scope: true,
            hypotheses: {
              orderBy: { initialConfidence: 'desc' }
            },
            coverage: true,
            sessions: {
              orderBy: { createdAt: 'desc' },
              take: 5
            },
            events: {
              orderBy: { timestamp: 'desc' },
              take: 100
            }
          }
        },
        vulnerabilities: {
          select: {
            id: true,
            title: true,
            description: true,
            type: true,
            severity: true,
            status: true,
            cvss: true,
            cve: true,
            cwe: true,
            evidence: true,
            remediation: true,
            createdAt: true
          },
          orderBy: { severity: 'desc' }
        }
      }
    });

    if (!scan) {
      throw {
        statusCode: 404,
        error: 'SCAN_NOT_FOUND',
        message: 'Scan not found'
      };
    }

    return this.formatScan(scan);
  }

  /**
   * List scans for organization
   */
  static async listScans(organizationId, options = {}) {
    const { page = 1, limit = 50, assetId, status, type } = options;
    const skip = (page - 1) * limit;

    const where = { organizationId };
    if (assetId) where.assetId = assetId;
    if (status) where.status = status;
    if (type) where.type = type;

    const [scans, total] = await Promise.all([
      prisma.scan.findMany({
        where,
        include: {
          asset: {
            select: {
              id: true,
              type: true,
              value: true
            }
          },
          vulnerabilities: {
            select: {
              id: true,
              title: true,
              severity: true
            }
          }
        },
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' }
      }),
      prisma.scan.count({ where })
    ]);

    const formatted = scans.map(s => this.formatScan(s));
    return {
      data: formatted,
      scans: formatted,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  }

  /**
   * Cancel a scan
   */
  static async cancelScan(organizationId, scanId) {
    const scan = await prisma.scan.findFirst({
      where: { id: scanId, organizationId }
    });

    if (!scan) {
      throw {
        statusCode: 404,
        error: 'SCAN_NOT_FOUND',
        message: 'Scan not found'
      };
    }

    return await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: SCAN_STATUS.CANCELLED,
        completedAt: new Date()
      }
    });
  }
}

module.exports = ScanService;
