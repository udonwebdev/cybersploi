/**
 * Scanner Base Service
 * Abstract base class for all scanner implementations
 */

class ScannerBase {
  constructor(name, config = {}) {
    this.name = name;
    this.config = {
      timeout: 300, // 5 minutes default
      retries: 3,
      ...config
    };
    this.isInstalled = false;
  }

  /**
   * Check if scanner is installed and available
   */
  async checkInstallation() {
    throw new Error('checkInstallation() must be implemented by subclass');
  }

  /**
   * Validate asset before scanning
   */
  validateAsset(asset) {
    if (!asset) {
      throw new Error('Asset is required');
    }
    if (!asset.value) {
      throw new Error('Asset value is required');
    }
    if (!asset.type) {
      throw new Error('Asset type is required');
    }
    return true;
  }

  /**
   * Validate scan configuration
   */
  validateConfig(config) {
    if (!config) {
      return {};
    }
    return config;
  }

  /**
   * Execute the scan - must be implemented by subclass
   */
  async execute(asset, config = {}) {
    throw new Error('execute() must be implemented by subclass');
  }

  /**
   * Parse raw scanner output into standardized format
   */
  async parseResults(rawOutput) {
    throw new Error('parseResults() must be implemented by subclass');
  }

  /**
   * Format findings into standardized vulnerability objects
   */
  formatFindings(rawFindings) {
    if (!Array.isArray(rawFindings)) {
      return [];
    }

    return rawFindings.map(finding => ({
      title: finding.title || finding.name || 'Unknown Vulnerability',
      description: finding.description || finding.detail || '',
      type: finding.type || 'Unknown',
      severity: this.normalizeSeverity(finding.severity || finding.level),
      cvss: finding.cvss || finding.cvssScore || 0,
      cve: finding.cve || null,
      cwe: finding.cwe || null,
      evidence: finding.evidence || finding.output || '',
      remediation: finding.remediation || finding.solution || '',
      scanner: this.name,
      reference: finding.reference || finding.link || null,
      raw: finding
    }));
  }

  /**
   * Normalize severity to standard levels: CRITICAL, HIGH, MEDIUM, LOW, INFO
   */
  normalizeSeverity(severity) {
    if (!severity) return 'MEDIUM';

    const normalized = String(severity).toUpperCase();
    
    if (['CRITICAL', 'SEVERE', 'CRITICAL_HIGH'].includes(normalized)) {
      return 'CRITICAL';
    }
    if (['HIGH', 'MAJOR'].includes(normalized)) {
      return 'HIGH';
    }
    if (['MEDIUM', 'MODERATE'].includes(normalized)) {
      return 'MEDIUM';
    }
    if (['LOW', 'MINOR'].includes(normalized)) {
      return 'LOW';
    }
    if (['INFO', 'INFORMATION', 'INFORMATIONAL'].includes(normalized)) {
      return 'INFO';
    }

    return 'MEDIUM'; // Default fallback
  }

  /**
   * Generate unique scan ID
   */
  generateScanId() {
    return `${this.name}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Handle retry logic
   */
  async executeWithRetry(fn, retries = this.config.retries) {
    let lastError;

    for (let i = 0; i < retries; i++) {
      try {
        return await fn();
      } catch (error) {
        lastError = error;
        console.warn(`Attempt ${i + 1}/${retries} failed for ${this.name}: ${error.message}`);
        
        if (i < retries - 1) {
          // Wait before retry (exponential backoff)
          await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1)));
        }
      }
    }

    throw lastError;
  }

  /**
   * Calculate overall vulnerability statistics
   */
  calculateStats(findings) {
    return {
      total: findings.length,
      critical: findings.filter(f => f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.severity === 'HIGH').length,
      medium: findings.filter(f => f.severity === 'MEDIUM').length,
      low: findings.filter(f => f.severity === 'LOW').length,
      info: findings.filter(f => f.severity === 'INFO').length
    };
  }
}

module.exports = ScannerBase;
