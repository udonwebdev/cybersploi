/**
 * Reconnaissance Base Service
 * Abstract base class for all reconnaissance modules
 * Provides standardized methods for discovery operations
 * 
 * Extends ScannerBase to leverage existing infrastructure
 * Used by: Subdomain Enumeration, Port Scanning, Service Detection, Tech Stack Detection
 */

const ScannerBase = require('./scanner-base.service');

class ReconBase extends ScannerBase {
  constructor(config = {}) {
    super(config);
    this.reconType = null;
    this.discoveredAssets = [];
    this.attackSurface = {};
    this.dependencies = [];
    this.sortOrder = 0;
  }

  /**
   * Validate recon target (domain, CIDR, etc.)
   * @param {Object} asset - Asset to scan
   * @returns {Boolean}
   */
  validateTarget(asset) {
    if (!asset || !asset.url) {
      throw new Error('Invalid asset: requires url property');
    }

    // Extract domain from URL
    try {
      const url = new URL(asset.url);
      const domain = url.hostname;
      
      if (!domain || domain.length < 4) {
        throw new Error('Invalid domain format');
      }

      return true;
    } catch (e) {
      throw new Error(`Invalid URL: ${e.message}`);
    }
  }

  /**
   * Extract domain from asset URL
   * @param {Object} asset
   * @returns {String}
   */
  extractDomain(asset) {
    try {
      const url = new URL(asset.url);
      return url.hostname;
    } catch (e) {
      return asset.url;
    }
  }

  /**
   * Format discovered asset
   * @param {Object} data - Raw discovered data
   * @returns {Object}
   */
  formatDiscoveredAsset(data) {
    return {
      type: data.type || 'unknown',
      value: data.value,
      source: data.source || this.reconType,
      confidence: data.confidence || 0.8,
      metadata: data.metadata || {},
      timestamp: new Date(),
      criticalityScore: this.calculateCriticalityScore(data),
    };
  }

  /**
   * Calculate criticality score for discovered asset
   * @param {Object} data
   * @returns {Number} 0.0 - 1.0
   */
  calculateCriticalityScore(data) {
    let score = 0.5; // Base score

    // Increase score for common service ports
    if (data.port) {
      const criticalPorts = [22, 80, 443, 3306, 5432, 5984, 6379, 8080, 8443, 9200];
      if (criticalPorts.includes(data.port)) {
        score += 0.2;
      }
    }

    // Increase score for known vulnerable technologies
    if (data.technology) {
      const vulnerableTechs = ['php', 'wordpress', 'joomla', 'drupal', 'jenkins', 'tomcat'];
      if (vulnerableTechs.some(t => data.technology.toLowerCase().includes(t))) {
        score += 0.15;
      }
    }

    // Increase score for missing security headers
    if (data.missingSecurityHeaders) {
      score += data.missingSecurityHeaders.length * 0.05;
    }

    return Math.min(score, 1.0);
  }

  /**
   * Store discovered asset in attack surface map
   * @param {Object} asset
   */
  addToAttackSurface(asset) {
    const type = asset.type;
    if (!this.attackSurface[type]) {
      this.attackSurface[type] = [];
    }
    this.attackSurface[type].push(asset);
    this.discoveredAssets.push(asset);
  }

  /**
   * Get all discovered assets by type
   * @param {String} type - Optional filter by type
   * @returns {Array}
   */
  getDiscoveredAssets(type = null) {
    if (type) {
      return this.attackSurface[type] || [];
    }
    return this.discoveredAssets;
  }

  /**
   * Generate attack surface summary
   * @returns {Object}
   */
  generateAttackSurfaceSummary() {
    const summary = {
      totalAssets: this.discoveredAssets.length,
      assetsByType: {},
      highCriticalityCount: 0,
      averageCriticalityScore: 0,
      topThreats: [],
    };

    let totalCriticality = 0;

    // Count by type and criticality
    Object.entries(this.attackSurface).forEach(([type, assets]) => {
      summary.assetsByType[type] = assets.length;
      assets.forEach(asset => {
        totalCriticality += asset.criticalityScore;
        if (asset.criticalityScore > 0.7) {
          summary.highCriticalityCount++;
        }
      });
    });

    summary.averageCriticalityScore = 
      this.discoveredAssets.length > 0 
        ? totalCriticality / this.discoveredAssets.length 
        : 0;

    // Top threats (sorted by criticality)
    summary.topThreats = this.discoveredAssets
      .sort((a, b) => b.criticalityScore - a.criticalityScore)
      .slice(0, 10);

    return summary;
  }

  /**
   * Build dependency tree for attack chaining
   * @returns {Object}
   */
  buildDependencyTree() {
    const tree = {
      root: this.extractDomain(this.assetConfig),
      subdomains: this.attackSurface.subdomain || [],
      openPorts: this.attackSurface.openPort || [],
      services: this.attackSurface.service || [],
      technologies: this.attackSurface.technology || [],
      vulnerabilities: this.attackSurface.vulnerability || [],
    };

    return tree;
  }

  /**
   * Format findings for database storage
   * @param {Object} rawData
   * @returns {Object}
   */
  formatFinding(rawData) {
    return {
      title: rawData.title || `Recon Finding: ${this.reconType}`,
      severity: rawData.severity || 'INFO',
      cvss: rawData.cvss || 0,
      cve: rawData.cve || null,
      cwe: rawData.cwe || null,
      description: rawData.description || '',
      evidence: JSON.stringify(rawData.evidence || {}),
      remediation: rawData.remediation || 'No remediation available',
      source: this.reconType,
      tags: rawData.tags || [this.reconType, 'reconnaissance'],
    };
  }

  /**
   * Base execute method (override in subclass)
   * @param {Object} asset
   * @param {Object} config
   */
  async execute(asset, config = {}) {
    throw new Error('execute() must be implemented in subclass');
  }

  /**
   * Check if reconnaissance results are cached
   * @param {String} domain
   * @param {Number} maxAgeHours
   * @returns {Boolean}
   */
  isCachValid(domain, maxAgeHours = 24) {
    const cacheKey = `recon:${domain}`;
    const cached = this.cache?.get?.(cacheKey);
    
    if (!cached) return false;

    const ageHours = (Date.now() - cached.timestamp) / (1000 * 60 * 60);
    return ageHours < maxAgeHours;
  }

  /**
   * Cache reconnaissance results
   * @param {String} domain
   * @param {Object} results
   */
  cacheResults(domain, results) {
    const cacheKey = `recon:${domain}`;
    if (this.cache?.set) {
      this.cache.set(cacheKey, {
        results,
        timestamp: Date.now(),
      });
    }
  }

  /**
   * Generate recon summary for findings
   * @returns {Object}
   */
  generateReconSummary() {
    return {
      reconType: this.reconType,
      timestamp: new Date(),
      totalDiscoveries: this.discoveredAssets.length,
      attackSurface: this.generateAttackSurfaceSummary(),
      dependencies: this.buildDependencyTree(),
      discoveredAssets: this.discoveredAssets,
    };
  }
}

module.exports = ReconBase;
