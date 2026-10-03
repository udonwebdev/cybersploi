/**
 * Report Generation Service
 * Creates comprehensive malware analysis reports
 * Supports PDF, HTML, JSON formats
 * 
 * Features:
 * - Multi-format report generation
 * - Timeline visualization data
 * - Executive summary
 * - Detailed findings
 * - Risk assessment
 */

const crypto = require('crypto');

class ReportGenerationService {
  constructor(config = {}) {
    this.name = 'Report Generation';
    this.version = '1.0.0';
    this.organizationName = config.organizationName || 'CyberSploi Security';
  }

  /**
   * Generate comprehensive analysis report
   */
  async generateReport(analysisData, format = 'json') {
    try {
      const report = {
        id: this.generateReportId(),
        generatedAt: new Date(),
        format: format,
        sections: {
          executive: this.generateExecutiveSummary(analysisData),
          technical: this.generateTechnicalSummary(analysisData),
          timeline: this.generateTimeline(analysisData),
          findings: this.generateFindingsSection(analysisData),
          recommendations: this.generateRecommendations(analysisData),
          metadata: this.generateMetadata(analysisData),
        },
      };

      // Format report
      if (format === 'json') {
        return {
          success: true,
          report: report,
          mimeType: 'application/json',
        };
      } else if (format === 'html') {
        return {
          success: true,
          report: this.formatAsHTML(report),
          mimeType: 'text/html',
        };
      } else if (format === 'pdf') {
        return {
          success: true,
          report: report, // Would be converted to PDF via external library
          mimeType: 'application/pdf',
        };
      }

      return {
        success: true,
        report: report,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Generate executive summary
   */
  generateExecutiveSummary(analysisData) {
    const {
      classification,
      staticAnalysis,
      dynamicAnalysis,
      yaraResults,
    } = analysisData;

    let summarySeverity = 'UNKNOWN';
    if (classification.family !== 'Unknown') {
      summarySeverity = 'CRITICAL';
    } else if (staticAnalysis?.riskScore >= 7 || dynamicAnalysis?.riskScore >= 7) {
      summarySeverity = 'HIGH';
    } else if (staticAnalysis?.riskScore >= 4 || dynamicAnalysis?.riskScore >= 4) {
      summarySeverity = 'MEDIUM';
    } else {
      summarySeverity = 'LOW';
    }

    return {
      title: 'Executive Summary',
      overallRisk: summarySeverity,
      detectionStatus: yaraResults?.totalMatches > 0 ? 'DETECTED' : 'SUSPICIOUS',
      malwareFamily: classification.family,
      malwareType: classification.type,
      confidence: `${(classification.confidence * 100).toFixed(0)}%`,
      summary: `The submitted file has been analyzed and classified as ${summarySeverity} risk. ${
        yaraResults?.totalMatches > 0
          ? `Known malware signatures were detected (${yaraResults.totalMatches} matches).`
          : 'File exhibits suspicious characteristics but no known signatures detected.'
      } ${
        classification.tags?.includes('Multiple Critical Behaviors')
          ? 'Multiple critical behaviors were observed during dynamic analysis.'
          : ''
      }`,
      keyFindings: this.extractKeyFindings(analysisData),
    };
  }

  /**
   * Generate technical summary
   */
  generateTechnicalSummary(analysisData) {
    const {
      staticAnalysis,
      dynamicAnalysis,
      yaraResults,
    } = analysisData;

    return {
      title: 'Technical Analysis Summary',
      staticAnalysis: {
        riskScore: staticAnalysis?.riskScore || 0,
        fileFormat: staticAnalysis?.fileFormat || 'Unknown',
        fileSize: staticAnalysis?.fileSize || 0,
        entropy: staticAnalysis?.entropy || 0,
        isPacked: staticAnalysis?.isPacked || false,
        packingMethod: staticAnalysis?.packingMethod || 'None',
        suspiciousAPIs: staticAnalysis?.suspiciousAPIs?.filter((_, i) => i < 10) || [],
      },
      dynamicAnalysis: {
        riskScore: dynamicAnalysis?.riskScore || 0,
        totalBehaviors: dynamicAnalysis?.behaviors?.length || 0,
        processCount: dynamicAnalysis?.processes?.length || 0,
        fileModifications: dynamicAnalysis?.fileModifications?.length || 0,
        networkConnections: dynamicAnalysis?.networkConnections?.length || 0,
        registryModifications: dynamicAnalysis?.registryModifications?.length || 0,
      },
      signatureAnalysis: {
        totalMatches: yaraResults?.totalMatches || 0,
        detectedFamilies: yaraResults?.malwareFamilies || [],
        confidence: yaraResults?.confidence || 0,
      },
    };
  }

  /**
   * Generate timeline
   */
  generateTimeline(analysisData) {
    const { dynamicAnalysis } = analysisData;

    if (!dynamicAnalysis || !dynamicAnalysis.timeline) {
      return { title: 'Execution Timeline', events: [] };
    }

    // Group events by type
    const eventsByType = {};
    for (const event of dynamicAnalysis.timeline) {
      if (!eventsByType[event.type]) {
        eventsByType[event.type] = [];
      }
      eventsByType[event.type].push(event);
    }

    return {
      title: 'Execution Timeline',
      events: dynamicAnalysis.timeline.slice(0, 50), // First 50 events
      summary: {
        totalEvents: dynamicAnalysis.timeline.length,
        eventTypes: Object.keys(eventsByType),
        criticalEvents: dynamicAnalysis.timeline.filter(e => e.severity === 'CRITICAL').length,
      },
    };
  }

  /**
   * Generate findings section
   */
  generateFindingsSection(analysisData) {
    const { findings } = analysisData;

    if (!findings || findings.length === 0) {
      return {
        title: 'Findings',
        totalFindings: 0,
        findings: [],
      };
    }

    // Group by severity
    const bySeverity = {
      CRITICAL: [],
      HIGH: [],
      MEDIUM: [],
      LOW: [],
      INFO: [],
    };

    for (const finding of findings) {
      if (bySeverity[finding.severity]) {
        bySeverity[finding.severity].push(finding);
      }
    }

    return {
      title: 'Findings',
      totalFindings: findings.length,
      bySeverity: {
        critical: bySeverity.CRITICAL.length,
        high: bySeverity.HIGH.length,
        medium: bySeverity.MEDIUM.length,
        low: bySeverity.LOW.length,
        info: bySeverity.INFO.length,
      },
      findings: findings.slice(0, 20), // First 20 findings
    };
  }

  /**
   * Generate recommendations
   */
  generateRecommendations(analysisData) {
    const recommendations = [];
    const { classification, staticAnalysis, dynamicAnalysis } = analysisData;

    if (classification.family !== 'Unknown') {
      recommendations.push({
        priority: 'CRITICAL',
        action: 'Quarantine',
        description: `File is confirmed malware (${classification.family}). Immediately isolate and remove from all systems.`,
      });
    } else if (staticAnalysis?.riskScore >= 7 || dynamicAnalysis?.riskScore >= 7) {
      recommendations.push({
        priority: 'HIGH',
        action: 'Isolate',
        description: 'File exhibits highly suspicious characteristics. Isolate affected systems and investigate.',
      });
    }

    if (dynamicAnalysis?.behaviors?.filter(b => b.type === 'network').length > 0) {
      recommendations.push({
        priority: 'HIGH',
        action: 'Block Network',
        description: 'Block identified command and control servers at network perimeter.',
      });
    }

    if (staticAnalysis?.isPacked) {
      recommendations.push({
        priority: 'MEDIUM',
        action: 'Advanced Analysis',
        description: `File is packed (${staticAnalysis.packingMethod}). Perform unpacking and deeper analysis.`,
      });
    }

    if (dynamicAnalysis?.behaviors?.filter(b => b.action === 'dll_injected').length > 0) {
      recommendations.push({
        priority: 'HIGH',
        action: 'Process Monitoring',
        description: 'Enable advanced process monitoring. Malware uses code injection techniques.',
      });
    }

    recommendations.push({
      priority: 'MEDIUM',
      action: 'Share Intelligence',
      description: 'Submit findings to threat intelligence feeds and security community.',
    });

    return {
      title: 'Recommendations',
      recommendations: recommendations,
    };
  }

  /**
   * Generate metadata
   */
  generateMetadata(analysisData) {
    const { staticAnalysis } = analysisData;

    return {
      title: 'File Information',
      filename: staticAnalysis?.filename || 'Unknown',
      fileSize: staticAnalysis?.fileSize || 0,
      hashes: {
        md5: staticAnalysis?.hashes?.md5 || 'N/A',
        sha1: staticAnalysis?.hashes?.sha1 || 'N/A',
        sha256: staticAnalysis?.hashes?.sha256 || 'N/A',
        ssdeep: staticAnalysis?.hashes?.ssdeep || 'N/A',
      },
      fileFormat: staticAnalysis?.fileFormat || 'Unknown',
      analysisDate: new Date().toISOString(),
      organization: this.organizationName,
    };
  }

  /**
   * Extract key findings
   */
  extractKeyFindings(analysisData) {
    const findings = [];
    const { staticAnalysis, dynamicAnalysis, yaraResults } = analysisData;

    if (yaraResults?.totalMatches > 0) {
      findings.push(`${yaraResults.totalMatches} malware signatures detected`);
    }

    if (staticAnalysis?.isPacked) {
      findings.push(`File is packed (${staticAnalysis.packingMethod})`);
    }

    if (staticAnalysis?.suspiciousAPIs?.length > 0) {
      findings.push(`${Math.min(5, staticAnalysis.suspiciousAPIs.length)} suspicious APIs detected`);
    }

    if (dynamicAnalysis?.behaviors?.length > 0) {
      findings.push(`${dynamicAnalysis.behaviors.length} suspicious behaviors observed`);
    }

    return findings.slice(0, 5);
  }

  /**
   * Format as HTML
   */
  formatAsHTML(report) {
    return `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Malware Analysis Report</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 20px; border-radius: 5px; }
        h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        h2 { color: #007bff; margin-top: 30px; }
        .severity-critical { color: #dc3545; font-weight: bold; }
        .severity-high { color: #fd7e14; font-weight: bold; }
        .severity-medium { color: #ffc107; font-weight: bold; }
        .severity-low { color: #28a745; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        table, th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background-color: #007bff; color: white; }
        .timestamp { color: #666; font-size: 12px; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🔒 Malware Analysis Report</h1>
        <p class="timestamp">Generated: ${report.generatedAt}</p>
        
        <h2>Executive Summary</h2>
        <p><strong>Overall Risk:</strong> <span class="severity-${report.sections.executive.overallRisk.toLowerCase()}">${report.sections.executive.overallRisk}</span></p>
        <p><strong>Malware Family:</strong> ${report.sections.executive.malwareFamily}</p>
        <p><strong>Confidence:</strong> ${report.sections.executive.confidence}</p>
        <p>${report.sections.executive.summary}</p>
        
        <h2>Technical Analysis</h2>
        <p><strong>Static Analysis Risk:</strong> ${report.sections.technical.staticAnalysis.riskScore}/10</p>
        <p><strong>Dynamic Analysis Risk:</strong> ${report.sections.technical.dynamicAnalysis.riskScore}/10</p>
        <p><strong>Signature Matches:</strong> ${report.sections.technical.signatureAnalysis.totalMatches}</p>
        
        <h2>Recommendations</h2>
        <ul>
          ${report.sections.recommendations.recommendations.map(r => 
            `<li><strong>${r.priority}:</strong> ${r.action} - ${r.description}</li>`
          ).join('')}
        </ul>
      </div>
    </body>
    </html>
    `;
  }

  /**
   * Generate report ID
   */
  generateReportId() {
    return `REPORT_${Date.now()}_${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  }
}

module.exports = ReportGenerationService;
