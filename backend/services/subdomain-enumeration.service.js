/**
 * Subdomain Enumeration Service
 * Discovers subdomains using Subfinder, Amass, and certificate transparency
 * 
 * Features:
 * - Multi-source enumeration (DNS, Certificate Transparency, web crawling)
 * - Deduplication and validation
 * - Real response checking (quick filtering of dead subdomains)
 * - Metadata collection (IP, tech stack, status codes)
 * - Attack surface analysis
 */

const { exec } = require('child_process');
const axios = require('axios');
const { promisify } = require('util');
const ReconBase = require('./recon-base.service');

const execAsync = promisify(exec);

class SubdomainEnumerationService extends ReconBase {
  constructor(config = {}) {
    super(config);
    this.reconType = 'subdomain-enumeration';
    this.timeout = config.timeout || 300000; // 5 minutes
    this.validateLiveSubdomains = config.validateLive !== false;
    this.useAmass = config.useAmass !== false;
    this.useSubfinder = config.useSubfinder !== false;
    this.useCertifyAPI = config.useCertify !== false;
    this.maxHttpRequests = config.maxHttpRequests || 50;
  }

  /**
   * Check if Subfinder is installed
   */
  async checkInstallation() {
    try {
      await execAsync('subfinder -version');
      return { installed: true, tool: 'subfinder' };
    } catch (e) {
      return { 
        installed: false, 
        message: 'Subfinder not found. Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest' 
      };
    }
  }

  /**
   * Quick subdomain enumeration (Subfinder only, 1-2 minutes)
   */
  async quickEnumerate(asset) {
    this.validateTarget(asset);
    const domain = this.extractDomain(asset);

    const sourceEnumerations = [];

    // Subfinder - fastest
    if (this.useSubfinder) {
      try {
        const subfinderResults = await this.runSubfinder(domain);
        sourceEnumerations.push(...subfinderResults);
      } catch (e) {
        console.error('Subfinder error:', e.message);
      }
    }

    // Deduplicate and validate
    const uniqueSubdomains = [...new Set(sourceEnumerations)];
    
    if (this.validateLiveSubdomains && uniqueSubdomains.length > 0) {
      return await this.validateSubdomains(uniqueSubdomains.slice(0, this.maxHttpRequests));
    }

    return uniqueSubdomains.map(subdomain => ({
      value: subdomain,
      type: 'subdomain',
      source: 'subfinder',
      validated: false,
    }));
  }

  /**
   * Standard enumeration (Subfinder + Amass, 3-5 minutes)
   */
  async standardEnumerate(asset) {
    this.validateTarget(asset);
    const domain = this.extractDomain(asset);

    const sourceEnumerations = [];

    // Subfinder
    if (this.useSubfinder) {
      try {
        const subfinderResults = await this.runSubfinder(domain);
        sourceEnumerations.push(...subfinderResults);
      } catch (e) {
        console.error('Subfinder error:', e.message);
      }
    }

    // Amass
    if (this.useAmass) {
      try {
        const amassResults = await this.runAmass(domain);
        sourceEnumerations.push(...amassResults);
      } catch (e) {
        console.error('Amass error:', e.message);
      }
    }

    // Certificate Transparency
    if (this.useCertifyAPI) {
      try {
        const certResults = await this.runCertificateTransparency(domain);
        sourceEnumerations.push(...certResults);
      } catch (e) {
        console.error('Certificate Transparency error:', e.message);
      }
    }

    // Deduplicate
    const uniqueSubdomains = [...new Set(sourceEnumerations)];

    // Validate and gather metadata
    return await this.validateSubdomains(uniqueSubdomains.slice(0, this.maxHttpRequests * 2));
  }

  /**
   * Deep enumeration (all sources + passive APIs, 5-10 minutes)
   */
  async deepEnumerate(asset) {
    const standardResults = await this.standardEnumerate(asset);
    
    // Add additional data gathering
    const enrichedResults = [];
    
    for (const subdomain of standardResults) {
      try {
        const enriched = await this.enrichSubdomainData(subdomain);
        enrichedResults.push(enriched);
      } catch (e) {
        enrichedResults.push(subdomain);
      }
    }

    return enrichedResults;
  }

  /**
   * Run Subfinder command
   */
  async runSubfinder(domain) {
    try {
      const { stdout } = await execAsync(
        `subfinder -d ${domain} -silent -all`,
        { timeout: 120000 }
      );

      return stdout
        .split('\n')
        .filter(line => line.trim().length > 0)
        .map(line => line.trim());
    } catch (e) {
      console.error('Subfinder execution error:', e);
      return [];
    }
  }

  /**
   * Run Amass command
   */
  async runAmass(domain) {
    try {
      const { stdout } = await execAsync(
        `amass enum -d ${domain} -passive`,
        { timeout: 180000 }
      );

      return stdout
        .split('\n')
        .filter(line => line.trim().length > 0)
        .map(line => {
          // Amass output: subdomain (IP address)
          const match = line.match(/^([^ ]+)/);
          return match ? match[1] : line.trim();
        });
    } catch (e) {
      console.error('Amass execution error:', e);
      return [];
    }
  }

  /**
   * Query Certificate Transparency logs
   */
  async runCertificateTransparency(domain) {
    try {
      // Using crt.sh API (free, no auth required)
      const response = await axios.get(
        `https://crt.sh/?q=${domain}&output=json`,
        { timeout: 10000 }
      );

      const subdomains = [];
      
      if (Array.isArray(response.data)) {
        response.data.forEach(cert => {
          if (cert.name_value) {
            cert.name_value.split('\n').forEach(name => {
              const normalized = name.trim().replace(/\*\./, '');
              if (normalized && !subdomains.includes(normalized)) {
                subdomains.push(normalized);
              }
            });
          }
        });
      }

      return subdomains;
    } catch (e) {
      console.error('Certificate Transparency error:', e.message);
      return [];
    }
  }

  /**
   * Validate subdomains and gather metadata
   */
  async validateSubdomains(subdomains) {
    const validated = [];
    let requestsRemaining = this.maxHttpRequests;

    for (const subdomain of subdomains) {
      if (requestsRemaining <= 0) break;

      try {
        const metadata = await this.probeSubdomain(subdomain);
        if (metadata.alive) {
          validated.push({
            value: subdomain,
            type: 'subdomain',
            source: 'enumeration',
            validated: true,
            metadata: metadata,
            criticalityScore: this.calculateSubdomainCriticality(metadata),
          });
        }
        requestsRemaining--;
      } catch (e) {
        // Domain not responding or error - skip
      }
    }

    return validated;
  }

  /**
   * Probe individual subdomain
   */
  async probeSubdomain(subdomain) {
    const metadata = {
      alive: false,
      statusCode: null,
      redirectsTo: null,
      title: null,
      serverHeader: null,
      contentLength: null,
    };

    const urls = [
      `https://${subdomain}`,
      `http://${subdomain}`,
    ];

    for (const url of urls) {
      try {
        const response = await axios.get(url, {
          timeout: 5000,
          maxRedirects: 2,
          validateStatus: () => true, // Accept all status codes
        });

        metadata.alive = true;
        metadata.statusCode = response.status;
        metadata.serverHeader = response.headers['server'];
        metadata.contentLength = response.headers['content-length'];
        
        // Extract title from HTML
        if (response.data) {
          const titleMatch = response.data.match(/<title>([^<]+)<\/title>/i);
          if (titleMatch) {
            metadata.title = titleMatch[1];
          }
        }

        // Check for redirects
        if (response.request?.url !== url) {
          metadata.redirectsTo = response.request.url;
        }

        return metadata;
      } catch (e) {
        // Try next URL
      }
    }

    return metadata;
  }

  /**
   * Calculate criticality score for subdomain
   */
  calculateSubdomainCriticality(metadata) {
    let score = 0.3; // Base score for discovered subdomain

    if (!metadata.alive) return 0.2;

    // Increase for web-facing servers
    if ([200, 301, 302, 401, 403].includes(metadata.statusCode)) {
      score += 0.2;
    }

    // Increase for admin/sensitive subdomains
    const sensitivePrefixes = ['admin', 'api', 'test', 'dev', 'staging', 'backup', 'internal'];
    // Extracted from subdomain parameter if available

    // Increase for interesting server headers (vulnerable versions)
    if (metadata.serverHeader) {
      const vulnerableServers = ['Apache/2.2', 'nginx/1.1', 'PHP/5'];
      if (vulnerableServers.some(v => metadata.serverHeader.includes(v))) {
        score += 0.15;
      }
    }

    // Increase for authentication pages
    if (metadata.statusCode === 401 || metadata.title?.toLowerCase().includes('login')) {
      score += 0.1;
    }

    return Math.min(score, 1.0);
  }

  /**
   * Enrich subdomain with additional data
   */
  async enrichSubdomainData(subdomain) {
    const enriched = { ...subdomain };

    try {
      // TODO: Add DNS resolution
      // TODO: Add WHOIS lookup
      // TODO: Add certificate analysis
      // TODO: Add SSL/TLS analysis
    } catch (e) {
      // If enrichment fails, return original data
    }

    return enriched;
  }

  /**
   * Format findings from enumeration
   */
  formatFindings(subdomains) {
    const findings = [];

    subdomains.forEach(subdomain => {
      findings.push({
        title: `Discovered Subdomain: ${subdomain.value}`,
        severity: this.calculateSeverity(subdomain),
        cvss: 0,
        cve: null,
        cwe: null,
        description: `Subdomain discovered during reconnaissance. ${
          subdomain.validated ? `Server responded with status ${subdomain.metadata?.statusCode}` : 'Not validated'
        }`,
        evidence: JSON.stringify(subdomain),
        remediation: 'Review this subdomain for security issues and ensure it\'s not accidentally exposed.',
        source: this.reconType,
        tags: ['subdomain', 'reconnaissance', 'public-exposure'],
      });
    });

    return findings;
  }

  /**
   * Calculate severity based on subdomain properties
   */
  calculateSeverity(subdomain) {
    if (!subdomain.validated || !subdomain.metadata?.alive) {
      return 'LOW';
    }

    if (subdomain.metadata.statusCode === 401 || subdomain.metadata.statusCode === 403) {
      return 'MEDIUM'; // Authentication required suggests sensitive endpoint
    }

    const sensitivePrefixes = ['admin', 'api-test', 'staging', 'dev', 'backup', 'internal'];
    if (sensitivePrefixes.some(prefix => subdomain.value.toLowerCase().includes(prefix))) {
      return 'MEDIUM';
    }

    return 'LOW';
  }

  /**
   * Main execute method
   */
  async execute(asset, config = {}) {
    try {
      const scanType = config.scanType || 'standard'; // quick, standard, deep

      let subdomains;
      switch (scanType) {
        case 'quick':
          subdomains = await this.quickEnumerate(asset);
          break;
        case 'deep':
          subdomains = await this.deepEnumerate(asset);
          break;
        case 'standard':
        default:
          subdomains = await this.standardEnumerate(asset);
      }

      // Format findings and add to attack surface
      subdomains.forEach(subdomain => {
        this.addToAttackSurface(this.formatDiscoveredAsset(subdomain));
      });

      return {
        status: 'completed',
        enumerated: subdomains.length,
        subdomains: subdomains,
        attackSurface: this.generateAttackSurfaceSummary(),
        findings: this.formatFindings(subdomains),
      };
    } catch (error) {
      return {
        status: 'error',
        error: error.message,
        enumerated: 0,
        subdomains: [],
        findings: [],
      };
    }
  }
}

module.exports = SubdomainEnumerationService;
