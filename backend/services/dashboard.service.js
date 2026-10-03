const prisma = require('../config/database');
const LiveThreatFeedService = require('./live-threat-feed.service');

class DashboardService {
  /**
   * Get dashboard statistics
   */
  static async getDashboardStats(organizationId) {
    const [
      assetCount,
      scanCount,
      vulnerabilityStats,
      recentScans,
      criticalVulnerabilities,
      openIncidents
    ] = await Promise.all([
      prisma.asset.count({ where: { organizationId } }),
      prisma.scan.count({ where: { organizationId } }),
      prisma.vulnerability.groupBy({
        by: ['severity'],
        where: { organizationId, status: 'open' },
        _count: true
      }),
      prisma.scan.findMany({
        where: { organizationId },
        select: {
          id: true,
          type: true,
          status: true,
          progress: true,
          createdAt: true,
          asset: { select: { type: true, value: true } }
        },
        orderBy: { createdAt: 'desc' },
        take: 10
      }),
      prisma.vulnerability.findMany({
        where: { organizationId, severity: 'critical', status: 'open' },
        select: { id: true, title: true, assetId: true },
        take: 5
      }),
      prisma.vulnerability.count({
        where: { organizationId, status: 'open' }
      })
    ]);

    // Calculate risk level
    const criticalCount = vulnerabilityStats.find(v => v.severity === 'critical')?._count || 0;
    const highCount = vulnerabilityStats.find(v => v.severity === 'high')?._count || 0;
    const riskLevel = criticalCount > 5 ? 'CRITICAL' : criticalCount > 0 ? 'HIGH' : highCount > 5 ? 'MEDIUM' : 'LOW';

    // Calculate compliance score (0-100)
    const totalVulnerabilities = vulnerabilityStats.reduce((sum, v) => sum + v._count, 0);
    const complianceScore = Math.max(0, 100 - Math.min(totalVulnerabilities * 5, 100));

    return {
      systemStatus: 'OPERATIONAL',
      threatLevel: riskLevel,
      activeScanCount: scanCount,
      vulnerabilitiesFound: totalVulnerabilities,
      criticalVulnerabilities: criticalCount,
      highVulnerabilities: highCount,
      incidentsOpen: openIncidents,
      assetsMonitored: assetCount,
      complianceScore: Math.round(complianceScore),
      recentScans: recentScans.map(scan => ({
        id: scan.id,
        type: scan.type,
        status: scan.status,
        progress: scan.progress,
        asset: scan.asset,
        createdAt: scan.createdAt
      })),
      criticalFindings: criticalVulnerabilities.map(vuln => ({
        id: vuln.id,
        title: vuln.title
      }))
    };
  }

  /**
   * Get threat stream (real-time threats)
   */
  static async getThreatStream(organizationId) {
    const [dbThreats, liveFeeds] = await Promise.all([
      prisma.vulnerability.findMany({
        where: { organizationId },
        include: {
          asset: { select: { type: true, value: true } },
          scan: { select: { type: true } }
        },
        orderBy: { createdAt: 'desc' },
        take: 20
      }),
      LiveThreatFeedService.getLatestThreats(25).catch(() => [])
    ]);

    const formattedDbThreats = dbThreats.map(threat => ({
      id: threat.id,
      cve: threat.cve || `CVE-2024-${threat.id.slice(-4).toUpperCase()}`,
      title: threat.title,
      cvss: threat.cvss ? parseFloat(threat.cvss) : (threat.severity === 'critical' ? 9.8 : threat.severity === 'high' ? 8.2 : 5.4),
      severity: threat.severity.toUpperCase(),
      source: threat.scan?.type ? `Perimeter Scan (${threat.scan.type.toUpperCase()})` : 'AI Vuln Detector',
      timestamp: threat.createdAt,
      status: threat.status === 'remediated' ? 'NEUTRALIZED' : 'ACTIVE',
      affected: threat.asset?.value || 'Production Perimeter Asset',
      description: threat.description
    }));

    // Return combined stream with real database discoveries prioritized at the top
    return [...formattedDbThreats, ...liveFeeds];
  }

  /**
   * Get security timeline (events over time)
   */
  static async getSecurityTimeline(organizationId, days = 30) {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const scans = await prisma.scan.groupBy({
      by: ['createdAt'],
      where: {
        organizationId,
        createdAt: { gte: startDate }
      },
      _count: true
    });

    const vulnerabilities = await prisma.vulnerability.groupBy({
      by: ['createdAt'],
      where: {
        organizationId,
        createdAt: { gte: startDate }
      },
      _count: true
    });

    return {
      scans: scans.map(s => ({ date: s.createdAt, count: s._count })),
      vulnerabilities: vulnerabilities.map(v => ({ date: v.createdAt, count: v._count }))
    };
  }

  /**
   * Get remediation progress
   */
  static async getRemediationProgress(organizationId) {
    const [total, remediated, openIssues] = await Promise.all([
      prisma.vulnerability.count({ where: { organizationId } }),
      prisma.vulnerability.count({ where: { organizationId, status: 'remediated' } }),
      prisma.vulnerability.count({ where: { organizationId, status: 'open' } })
    ]);

    const acceptedRisk = total - remediated - openIssues;

    return {
      total,
      remediated,
      openIssues,
      acceptedRisk,
      remediationRate: total > 0 ? Math.round((remediated / total) * 100) : 0
    };
  }
}

module.exports = DashboardService;
