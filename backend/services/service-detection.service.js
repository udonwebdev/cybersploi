/**
 * Service Detection Service
 * Identifies services, technologies, and security headers on discovered assets
 * 
 * Uses:
 * - httpx for HTTP header analysis
 * - Custom technology fingerprinting
 * - Security header detection
 * - SSL/TLS certificate analysis
 * - Version detection
 */

const axios = require('axios');
const { exec } = require('child_process');
const { promisify } = require('util');
const ReconBase = require('./recon-base.service');

const execAsync = promisify(exec);

class ServiceDetectionService extends ReconBase {
  constructor(config = {}) {
    super(config);
    this.reconType = 'service-detection';
    this.timeout = config.timeout || 60000;
    this.useHttpx = config.useHttpx !== false;
    this.detectTechnologies = config.detectTechs !== false;
    this.analyzeSSL = config.analyzeSSL !== false;
    this.maxConcurrent = config.maxConcurrent || 10;
  }

  /**
   * Check if httpx is installed
   */
  async checkInstallation() {
    try {
      await execAsync('httpx -version');
      return { installed: true, tool: 'httpx' };
    } catch (e) {
      return { 
        installed: false, 
        message: 'httpx not found. Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest' 
      };
    }
  }

  /**
   * Quick service detection (basic HTTP probing)
   */
  async quickDetect(subdomains) {
    const services = [];

    for (const subdomain of subdomains.slice(0, 20)) {
      try {
        const service = await this.probeService(subdomain);
        if (service) {
          services.push(service);
        }
      } catch (e) {
        // Skip failed probes
      }
    }

    return services;
  }

  /**
   * Standard service detection (httpx + tech detection)
   */
  async standardDetect(subdomains) {
    const services = [];

    // Use httpx if available
    if (this.useHttpx) {
      try {
        const httpxResults = await this.runHttpx(subdomains);
        services.push(...httpxResults);
      } catch (e) {
        console.error('httpx error:', e.message);
        
        // Fallback to individual probing
        for (const subdomain of subdomains) {
          try {
            const service = await this.probeService(subdomain);
            if (service) {
              services.push(service);
            }
          } catch (e) {
            // Skip
          }
        }
      }
    } else {
      // Individual probing
      for (const subdomain of subdomains) {
        try {
          const service = await this.probeService(subdomain);
          if (service) {
            services.push(service);
          }
        } catch (e) {
          // Skip failed probes
        }
      }
    }

    // Detect technologies
    if (this.detectTechnologies) {
      for (const service of services) {
        try {
          service.technologies = await this.detectTechnologies(service);
        } catch (e) {
          service.technologies = [];
        }
      }
    }

    return services;
  }

  /**
   * Run httpx on subdomains
   */
  async runHttpx(subdomains) {
    try {
      // Create temporary input file with subdomains
      const input = subdomains.slice(0, 100).join('\n');
      
      // Run httpx with detailed output
      const { stdout } = await execAsync(
        `echo "${input}" | httpx -json -title -status-code -web-server -tech-detect`,
        { timeout: 120000, maxBuffer: 1024 * 1024 }
      );

      const services = [];
      const lines = stdout.split('\n').filter(line => line.trim());

      for (const line of lines) {
        try {
          const parsed = JSON.parse(line);
          services.push({
            url: parsed.url || parsed['input'],
            statusCode: parsed['status-code'],
            title: parsed.title,
            server: parsed['webserver'],
            technologies: parsed.technologies || [],
            cname: parsed.cname,
            rtt: parsed.rtt,
          });
        } catch (e) {
          // Skip invalid JSON lines
        }
      }

      return services;
    } catch (e) {
      console.error('httpx execution error:', e);
      return [];
    }
  }

  /**
   * Probe individual service
   */
  async probeService(subdomain) {
    const metadata = {
      url: null,
      statusCode: null,
      title: null,
      server: null,
      contentType: null,
      contentLength: null,
      securityHeaders: {},
      missingSecurityHeaders: [],
      technologies: [],
      redirectChain: [],
    };

    const urls = [
      `https://${subdomain}`,
      `http://${subdomain}`,
    ];

    for (const url of urls) {
      try {
        const response = await axios.get(url, {
          timeout: 5000,
          maxRedirects: 5,
          validateStatus: () => true,
        });

        metadata.url = url;
        metadata.statusCode = response.status;
        metadata.server = response.headers['server'];
        metadata.contentType = response.headers['content-type'];
        metadata.contentLength = response.headers['content-length'];

        // Extract title
        if (response.data) {
          const titleMatch = response.data.match(/<title>([^<]+)<\/title>/i);
          if (titleMatch) {
            metadata.title = titleMatch[1];
          }
        }

        // Analyze security headers
        this.analyzeSecurityHeaders(response.headers, metadata);

        // Detect technologies
        metadata.technologies = this.detectedTechnologies(response);

        // Analyze SSL certificate if HTTPS
        if (url.startsWith('https://')) {
          try {
            metadata.ssl = await this.analyzeCertificate(subdomain);
          } catch (e) {
            // SSL analysis failed
          }
        }

        return metadata;

      } catch (e) {
        // Try next URL
      }
    }

    return null;
  }

  /**
   * Analyze security headers in response
   */
  analyzeSecurityHeaders(headers, metadata) {
    const importantHeaders = [
      'strict-transport-security',
      'x-frame-options',
      'x-content-type-options',
      'content-security-policy',
      'x-xss-protection',
      'referrer-policy',
      'permissions-policy',
      'set-cookie',
    ];

    const missingHeaders = [];

    importantHeaders.forEach(header => {
      const value = headers[header];
      if (value) {
        metadata.securityHeaders[header] = value;
      } else {
        missingHeaders.push(header);
      }
    });

    metadata.missingSecurityHeaders = missingHeaders;

    // Check for anti-CSRF tokens
    const setCookie = headers['set-cookie'];
    if (Array.isArray(setCookie)) {
      const hasCsrfProtection = setCookie.some(cookie => 
        cookie.includes('csrf') || cookie.includes('xsrf')
      );
      if (hasCsrfProtection) {
        metadata.securityHeaders['csrf-protection'] = 'detected';
      }
    }
  }

  /**
   * Detect technologies from response
   */
  detectedTechnologies(response) {
    const techs = [];
    const data = response.data || '';
    const headers = response.headers || {};
    const server = headers['server'] || '';

    // Server header detection
    if (server) {
      if (server.includes('Apache')) techs.push('Apache');
      if (server.includes('nginx')) techs.push('nginx');
      if (server.includes('IIS')) techs.push('Microsoft IIS');
      if (server.includes('Tomcat')) techs.push('Tomcat');
      if (server.includes('Node')) techs.push('Node.js');
    }

    // Content-type detection
    const contentType = headers['content-type'] || '';
    if (contentType.includes('php')) techs.push('PHP');
    if (contentType.includes('json')) techs.push('JSON API');

    // HTML signature detection
    if (typeof data === 'string') {
      if (data.includes('wp-content')) techs.push('WordPress');
      if (data.includes('joomla')) techs.push('Joomla');
      if (data.includes('drupal') || data.includes('Drupal')) techs.push('Drupal');
      if (data.includes('_next')) techs.push('Next.js');
      if (data.includes('__REACT_DEVTOOLS_GLOBAL_HOOK__')) techs.push('React');
      if (data.includes('angular')) techs.push('Angular');
      if (data.includes('vue')) techs.push('Vue.js');
      if (data.includes('Powered by Joomla')) techs.push('Joomla');
      if (data.includes('WordPress')) techs.push('WordPress');
      if (data.includes('Magento')) techs.push('Magento');
      if (data.includes('OpenCart')) techs.push('OpenCart');
      if (data.includes('Prestashop')) techs.push('PrestaShop');
    }

    // Application detection
    const location = headers['location'] || '';
    if (location.includes('wordpress')) techs.push('WordPress');
    if (location.includes('joomla')) techs.push('Joomla');

    return [...new Set(techs)]; // Deduplicate
  }

  /**
   * Analyze SSL/TLS certificate
   */
  async analyzeCertificate(subdomain) {
    try {
      // Use common TLS tools or direct inspection
      const { stdout } = await execAsync(
        `echo Q | openssl s_client -servername ${subdomain} -connect ${subdomain}:443 -showcerts 2>/dev/null | openssl x509 -noout -subject -dates -issuer 2>/dev/null || echo "Failed"`,
        { timeout: 10000 }
      );

      return {
        raw: stdout,
        // Could parse further, but providing raw for now
      };
    } catch (e) {
      return { error: e.message };
    }
  }

  /**
   * Format findings from service detection
   */
  formatFindings(services) {
    const findings = [];

    services.forEach(service => {
      // Security header findings
      if (service.missingSecurityHeaders && service.missingSecurityHeaders.length > 0) {
        findings.push({
          title: `Missing Security Headers: ${service.missingSecurityHeaders.join(', ')}`,
          severity: 'MEDIUM',
          cvss: 5.3,
          cve: null,
          cwe: 693, // Incomplete List of Disallowed Inputs
          description: `The following security headers are not present: ${service.missingSecurityHeaders.join(', ')}. These headers help prevent common web vulnerabilities.`,
          evidence: JSON.stringify(service),
          remediation: `Add the following headers to your HTTP responses:\n${
            service.missingSecurityHeaders.map(h => `- ${h}`).join('\n')
          }`,
          source: this.reconType,
          tags: ['security-headers', 'web-security'],
        });
      }

      // Outdated technology findings
      if (service.server) {
        const vulnerableSoftware = [
          { pattern: /Apache\/2\.2/, name: 'Apache 2.2', severity: 'HIGH' },
          { pattern: /Apache\/2\.0/, name: 'Apache 2.0', severity: 'CRITICAL' },
          { pattern: /IIS\/[5-6]/, name: 'IIS 5-6', severity: 'CRITICAL' },
          { pattern: /PHP\/5\.[0-3]/, name: 'PHP 5.0-5.3', severity: 'HIGH' },
        ];

        vulnerableSoftware.forEach(vuln => {
          if (vuln.pattern.test(service.server)) {
            findings.push({
              title: `Outdated Software Detected: ${vuln.name}`,
              severity: vuln.severity,
              cvss: vuln.severity === 'CRITICAL' ? 9.8 : 7.5,
              cve: 'Multiple',
              cwe: 1104, // Use of Unmaintained Third Party Components
              description: `The service is running ${vuln.name}, which is outdated and no longer supported.`,
              evidence: JSON.stringify({ server: service.server }),
              remediation: `Update ${vuln.name} to the latest version.`,
              source: this.reconType,
              tags: ['outdated-software', 'version-disclosure'],
            });
          }
        });
      }
    });

    return findings;
  }

  /**
   * Main execute method
   */
  async execute(asset, subdomains, config = {}) {
    try {
      const scanType = config.scanType || 'standard'; // quick, standard

      let services;
      switch (scanType) {
        case 'quick':
          services = await this.quickDetect(subdomains);
          break;
        case 'standard':
        default:
          services = await this.standardDetect(subdomains);
      }

      // Format findings
      const findings = this.formatFindings(services);

      // Add to attack surface
      services.forEach(service => {
        this.addToAttackSurface(this.formatDiscoveredAsset({
          type: 'service',
          value: service.url,
          source: this.reconType,
          metadata,
        }));
      });

      return {
        status: 'completed',
        detected: services.length,
        services: services,
        findings: findings,
        attackSurface: this.generateAttackSurfaceSummary(),
      };
    } catch (error) {
      return {
        status: 'error',
        error: error.message,
        detected: 0,
        services: [],
        findings: [],
      };
    }
  }
}

module.exports = ServiceDetectionService;
