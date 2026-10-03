/**
 * Attack Path Discovery Service
 * Analyzes findings and builds attack chains
 * Identifies realistic exploitation paths and priorities for remediation
 * 
 * Features:
 * - Attack chain visualization (graph structure)
 * - Exploitation complexity scoring
 * - Impact assessment
 * - Privilege escalation detection
 * - Chaining of vulnerabilities into realistic attack scenarios
 */

const ReconBase = require('./recon-base.service');

class AttackPathDiscoveryService extends ReconBase {
  constructor(config = {}) {
    super(config);
    this.reconType = 'attack-path-discovery';
    this.vulnerabilities = [];
    this.attackPaths = [];
    this.exploitableChains = [];
    this.dependencyGraph = {};
  }

  /**
   * Check installation - no external tools needed
   */
  async checkInstallation() {
    return { installed: true, tool: 'attack-path-discovery', message: 'Native service, no installation required' };
  }

  /**
   * Build attack paths from vulnerabilities
   */
  async discoverAttackPaths(vulnerabilities) {
    if (!Array.isArray(vulnerabilities)) {
      throw new Error('vulnerabilities must be an array');
    }

    this.vulnerabilities = vulnerabilities;

    // Step 1: Build dependency graph
    this.buildDependencyGraph();

    // Step 2: Find exploitable chains
    this.findExploitableChains();

    // Step 3: Calculate complexity and impact
    this.calculatePathMetrics();

    // Step 4: Prioritize attack paths
    this.prioritizeAttackPaths();

    return {
      attackPaths: this.attackPaths,
      exploitableChains: this.exploitableChains,
      totalChains: this.exploitableChains.length,
      criticalChains: this.getCriticalChains(),
    };
  }

  /**
   * Build dependency graph of vulnerabilities
   */
  buildDependencyGraph() {
    this.dependencyGraph = {};

    // Create nodes for each vulnerability
    this.vulnerabilities.forEach((vuln, index) => {
      this.dependencyGraph[index] = {
        vulnerability: vuln,
        dependsOn: [],
        enablesAccess: [],
      };
    });

    // Identify dependencies and relationships
    this.vulnerabilities.forEach((vuln, i) => {
      this.vulnerabilities.forEach((otherVuln, j) => {
        if (i !== j) {
          if (this.canChainExploits(vuln, otherVuln)) {
            this.dependencyGraph[i].dependsOn.push(j);
            this.dependencyGraph[j].enablesAccess.push(i);
          }
        }
      });
    });
  }

  /**
   * Check if two vulnerabilities can be chained
   */
  canChainExploits(vuln1, vuln2) {
    // Authentication bypass → Remote code execution
    if (this.isAuthBypass(vuln1) && this.isRCE(vuln2)) {
      return true;
    }

    // Information disclosure → Authentication bypass
    if (this.isInformationDisclosure(vuln1) && this.isAuthBypass(vuln2)) {
      return true;
    }

    // SQL injection → Authentication bypass
    if (this.isSQLInjection(vuln1) && this.isAuthBypass(vuln2)) {
      return true;
    }

    // RCE → Privilege escalation
    if (this.isRCE(vuln1) && this.isPrivilegeEsc(vuln2)) {
      return true;
    }

    // Configuration issue → Data breach
    if (this.isConfigIssue(vuln1) && this.isDataAccess(vuln2)) {
      return true;
    }

    // Same component version → Multiple exploits
    if (vuln1.source === vuln2.source && vuln1.evidence) {
      return true;
    }

    return false;
  }

  /**
   * Vulnerability type predicates
   */
  isAuthBypass(vuln) {
    const authKeywords = ['auth', 'bypass', 'authentication', 'session', 'jwt', 'token', 'login', 'password'];
    return authKeywords.some(kw => {
      const text = (vuln.title + vuln.description).toLowerCase();
      return text.includes(kw);
    });
  }

  isRCE(vuln) {
    const rceKeywords = ['remote code execution', 'rce', 'code execution', 'command injection', 'shell access'];
    return rceKeywords.some(kw => {
      const text = (vuln.title + vuln.description).toLowerCase();
      return text.includes(kw);
    });
  }

  isSQLInjection(vuln) {
    const sqlKeywords = ['sql injection', 'sqli', 'database', 'sql', 'injection'];
    return sqlKeywords.some(kw => {
      const text = (vuln.title + vuln.description).toLowerCase();
      return text.includes(kw);
    });
  }

  isPrivilegeEsc(vuln) {
    const privKeywords = ['privilege', 'escalation', 'root', 'admin', 'sudo', 'elevation'];
    return privKeywords.some(kw => {
      const text = (vuln.title + vuln.description).toLowerCase();
      return text.includes(kw);
    });
  }

  isConfigIssue(vuln) {
    const configKeywords = ['misconfiguration', 'config', 'exposure', 's3', 'bucket', 'storage', 'security group'];
    return configKeywords.some(kw => {
      const text = (vuln.title + vuln.description).toLowerCase();
      return text.includes(kw);
    });
  }

  isInformationDisclosure(vuln) {
    const infoKeywords = ['information disclosure', 'leak', 'exposure', 'enumeration', 'version', 'error message', 'stack trace'];
    return infoKeywords.some(kw => {
      const text = (vuln.title + vuln.description).toLowerCase();
      return text.includes(kw);
    });
  }

  isDataAccess(vuln) {
    const dataKeywords = ['data', 'access', 'read', 'retrieve', 'extract', 'exfiltrate', 'sensitive'];
    return dataKeywords.some(kw => {
      const text = (vuln.title + vuln.description).toLowerCase();
      return text.includes(kw);
    });
  }

  /**
   * Find exploitable chains
   */
  findExploitableChains() {
    this.exploitableChains = [];

    // Find all paths starting from each node
    this.vulnerabilities.forEach((_, startIdx) => {
      const paths = this.findPaths(startIdx, []);
      this.exploitableChains.push(...paths.filter(p => p.length > 1));
    });

    // Deduplicate paths
    this.exploitableChains = this.deduplikateChains(this.exploitableChains);

    // Convert to readable format
    this.exploitableChains = this.exploitableChains.map(chain => 
      this.formatChain(chain)
    );
  }

  /**
   * Depth-first search for vulnerability chains
   */
  findPaths(currentIdx, visitedIndices, maxDepth = 4) {
    if (visitedIndices.length >= maxDepth) {
      return [visitedIndices];
    }

    const paths = [];
    const currentNode = this.dependencyGraph[currentIdx];

    if (!currentNode || !currentNode.enablesAccess || currentNode.enablesAccess.length === 0) {
      return visitedIndices.length > 0 ? [visitedIndices] : [];
    }

    for (const nextIdx of currentNode.enablesAccess) {
      if (!visitedIndices.includes(nextIdx)) {
        const newVisited = [...visitedIndices, nextIdx];
        paths.push(...this.findPaths(nextIdx, newVisited, maxDepth));
      }
    }

    return paths.length > 0 ? paths : [visitedIndices];
  }

  /**
   * Remove duplicate chains
   */
  deduplikateChains(chains) {
    const unique = [];
    const seen = new Set();

    chains.forEach(chain => {
      const key = JSON.stringify(chain.sort((a, b) => a - b));
      if (!seen.has(key)) {
        unique.push(chain);
        seen.add(key);
      }
    });

    return unique;
  }

  /**
   * Format chain into readable format
   */
  formatChain(chain) {
    const formatted = {
      chain: chain.map(idx => ({
        title: this.vulnerabilities[idx].title,
        severity: this.vulnerabilities[idx].severity,
        idx: idx,
      })),
      description: this.generateChainDescription(chain),
      impactScore: this.calculateImpactScore(chain),
      complexityScore: this.calculateComplexityScore(chain),
      exploitabilityScore: this.calculateExploitabilityScore(chain),
    };

    return formatted;
  }

  /**
   * Generate description of attack chain
   */
  generateChainDescription(chain) {
    const steps = chain.map((idx, stepNum) => {
      const vuln = this.vulnerabilities[idx];
      return `Step ${stepNum + 1}: ${vuln.title}`;
    });

    return steps.join(' → ');
  }

  /**
   * Calculate impact score for chain (0-1)
   */
  calculateImpactScore(chain) {
    const severities = chain.map(idx => this.vulnerabilities[idx].severity);
    
    // Scale: CRITICAL=1.0, HIGH=0.8, MEDIUM=0.6, LOW=0.4, INFO=0.2
    const severityScale = {
      CRITICAL: 1.0,
      HIGH: 0.8,
      MEDIUM: 0.6,
      LOW: 0.4,
      INFO: 0.2,
    };

    const sum = severities.reduce((acc, sev) => acc + (severityScale[sev] || 0.3), 0);
    return Math.min(sum / chain.length, 1.0);
  }

  /**
   * Calculate complexity score for chain (0-1, lower = easier)
   */
  calculateComplexityScore(chain) {
    // Fewer steps = lower complexity (easier)
    const lengthFactor = 1 - (chain.length / 5);

    // Certain vulnerability types are easier to chain
    const vulnTypeEase = chain.map(idx => {
      const vuln = this.vulnerabilities[idx];
      const easyTypes = ['information disclosure', 'misconfiguration', 'exposure', 'sql injection'];
      return easyTypes.some(type => vuln.title.toLowerCase().includes(type)) ? 1 : 0.5;
    });

    const easeAverage = vulnTypeEase.reduce((a, b) => a + b, 0) / vulnTypeEase.length;

    return 1 - ((lengthFactor + easeAverage) / 2);
  }

  /**
   * Calculate exploitability score (0-1)
   */
  calculateExploitabilityScore(chain) {
    // Combines impact and complexity: high impact but low complexity = high exploitability
    const impact = this.calculateImpactScore(chain);
    const complexity = this.calculateComplexityScore(chain);

    return (impact + complexity) / 2;
  }

  /**
   * Calculate metrics for all paths
   */
  calculatePathMetrics() {
    this.exploitableChains.forEach(chain => {
      chain.metrics = {
        impact: chain.impactScore,
        complexity: chain.complexityScore,
        exploitability: chain.exploitabilityScore,
        riskLevel: this.calculateRiskLevel(chain),
      };
    });
  }

  /**
   * Calculate risk level based on metrics
   */
  calculateRiskLevel(chain) {
    const exploitability = chain.exploitabilityScore;

    if (exploitability > 0.8) return 'CRITICAL';
    if (exploitability > 0.6) return 'HIGH';
    if (exploitability > 0.4) return 'MEDIUM';
    return 'LOW';
  }

  /**
   * Prioritize attack paths
   */
  prioritizeAttackPaths() {
    this.attackPaths = this.exploitableChains
      .sort((a, b) => {
        // Sort by exploitability (highest first)
        if (b.exploitabilityScore !== a.exploitabilityScore) {
          return b.exploitabilityScore - a.exploitabilityScore;
        }
        // Then by impact (highest first)
        return b.impactScore - a.impactScore;
      });
  }

  /**
   * Get critical attack chains
   */
  getCriticalChains() {
    return this.attackPaths.filter(chain => chain.metrics?.riskLevel === 'CRITICAL');
  }

  /**
   * Format findings from attack paths
   */
  formatFindings() {
    const findings = [];

    this.getCriticalChains().forEach((chain, idx) => {
      findings.push({
        title: `Critical Attack Chain #${idx + 1}: ${chain.chain[0].title}`,
        severity: 'CRITICAL',
        cvss: 9.0 + (chain.exploitabilityScore * 0.9),
        cve: null,
        cwe: 1287, // Improper Validation of Specified Quantity in Input
        description: chain.description,
        evidence: JSON.stringify(chain),
        remediation: this.generateChainRemediation(chain),
        source: this.reconType,
        tags: ['attack-chain', 'critical', 'prioritized'],
      });
    });

    return findings;
  }

  /**
   * Generate remediation for attack chain
   */
  generateChainRemediation(chain) {
    const steps = chain.chain.map((vuln, idx) => 
      `${idx + 1}. Fix "${vuln.title}" (Severity: ${vuln.severity})`
    );

    return `Remediate this attack chain in order of severity:\n${steps.join('\n')}\n\nFix the first vulnerability to break the attack chain.`;
  }

  /**
   * Visualize attack path as text graph
   */
  visualizeAttackPath(chain) {
    let visualization = 'Attack Chain Visualization:\n\n';

    chain.chain.forEach((vuln, idx) => {
      visualization += `${vuln.title}\n`;
      visualization += `├─ Severity: ${vuln.severity}\n`;
      
      if (idx < chain.chain.length - 1) {
        visualization += `└─ LEADS TO ↓\n\n`;
      }
    });

    visualization += `\nFinal Impact: ${chain.metrics.riskLevel}\n`;
    visualization += `Exploitability Score: ${(chain.exploitabilityScore * 100).toFixed(1)}%\n`;

    return visualization;
  }

  /**
   * Main execute method
   */
  async execute(vulnerabilities, config = {}) {
    try {
      const result = await this.discoverAttackPaths(vulnerabilities);

      return {
        status: 'completed',
        chainCount: result.totalChains,
        criticalChainCount: result.criticalChains.length,
        attackPaths: result.attackPaths,
        findings: this.formatFindings(),
        visualization: result.criticalChains.map(chain => this.visualizeAttackPath(chain)),
      };
    } catch (error) {
      return {
        status: 'error',
        error: error.message,
        attackPaths: [],
        findings: [],
      };
    }
  }
}

module.exports = AttackPathDiscoveryService;
