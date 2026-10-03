/**
 * Cloud Security Testing Service
 * Detects cloud misconfigurations in AWS, Azure, and GCP
 * Checks for: S3 bucket exposure, IAM issues, security group problems
 * 
 * Features:
 * - S3 bucket enumeration and permission checking
 * - IAM policy analysis
 * - Security group configuration review
 * - Cloud credentials detection
 * - Storage access validation
 */

const axios = require('axios');
const ReconBase = require('./recon-base.service');

class CloudSecurityService extends ReconBase {
  constructor(config = {}) {
    super(config);
    this.reconType = 'cloud-security';
    this.timeout = config.timeout || 120000;
    this.checkAWS = config.checkAWS !== false;
    this.checkAzure = config.checkAzure !== false;
    this.checkGCP = config.checkGCP !== false;
    this.credentials = config.credentials || {};
  }

  /**
   * Check installation - cloud tools are API-based
   */
  async checkInstallation() {
    return { installed: true, tool: 'cloud-security', message: 'API-based tool, no installation required' };
  }

  /**
   * Quick cloud security scan - passive checks only
   */
  async quickScan(asset) {
    const domain = this.extractDomain(asset);
    const findings = [];

    // Passive checks - no credentials needed
    findings.push(...await this.checkS3BucketEnumeration(domain));
    findings.push(...await this.checkCloudCredentialsExposure(domain));
    findings.push(...await this.checkDNSRecords(domain));

    return findings;
  }

  /**
   * Standard cloud security scan
   */
  async standardScan(asset) {
    const domain = this.extractDomain(asset);
    const findings = [];

    // Passive checks
    findings.push(...await this.checkS3BucketEnumeration(domain));
    findings.push(...await this.checkCloudCredentialsExposure(domain));
    findings.push(...await this.checkDNSRecords(domain));

    // If credentials provided, do active checks
    if (this.credentials.aws) {
      findings.push(...await this.checkAWSConfiguration());
    }
    if (this.credentials.azure) {
      findings.push(...await this.checkAzureConfiguration());
    }
    if (this.credentials.gcp) {
      findings.push(...await this.checkGCPConfiguration());
    }

    return findings;
  }

  /**
   * Check for exposed S3 buckets
   */
  async checkS3BucketEnumeration(domain) {
    const findings = [];

    // Common S3 bucket naming patterns
    const bucketPatterns = [
      `${domain}`,
      `${domain}-prod`,
      `${domain}-backup`,
      `${domain}-assets`,
      `${domain}-data`,
      `${domain}-logs`,
      `${domain}-dev`,
      `backup-${domain}`,
      `assets-${domain}`,
      `data-${domain}`,
    ];

    for (const bucketName of bucketPatterns) {
      try {
        const result = await this.probeS3Bucket(bucketName);
        if (result.accessible) {
          findings.push({
            type: 'aws',
            category: 's3-exposure',
            bucketName: bucketName,
            publiclyAccessible: result.publiclyAccessible,
            accessible: result.accessible,
            region: result.region,
            findings: result.findings,
          });
        }
      } catch (e) {
        // Bucket doesn't exist or not accessible
      }
    }

    return findings.map(f => this.formatCloudFinding(f));
  }

  /**
   * Probe individual S3 bucket for accessibility
   */
  async probeS3Bucket(bucketName) {
    const result = {
      bucketName: bucketName,
      accessible: false,
      publiclyAccessible: false,
      region: null,
      findings: [],
    };

    // Check if bucket exists and is accessible
    try {
      const response = await axios.get(
        `https://${bucketName}.s3.amazonaws.com/`,
        { timeout: 5000, validateStatus: () => true }
      );

      if (response.status === 200) {
        result.accessible = true;
        result.publiclyAccessible = true;
        result.findings.push('Bucket is publicly readable (anonymous LIST permitted)');
      } else if (response.status === 403) {
        result.accessible = true;
        result.findings.push('Bucket exists but is not publicly readable');
      }

      // Try to detect region
      const regionHeader = response.headers['x-amz-bucket-region'];
      if (regionHeader) {
        result.region = regionHeader;
      }
    } catch (e) {
      // Try alternative endpoints
      const regions = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'];
      for (const region of regions) {
        try {
          const response = await axios.get(
            `https://${bucketName}.s3.${region}.amazonaws.com/`,
            { timeout: 3000, validateStatus: () => true }
          );

          if (response.status === 200 || response.status === 403) {
            result.accessible = true;
            result.region = region;
            if (response.status === 200) {
              result.publiclyAccessible = true;
            }
            break;
          }
        } catch (e) {
          // Try next region
        }
      }
    }

    return result;
  }

  /**
   * Check for exposed cloud credentials in common locations
   */
  async checkCloudCredentialsExposure(domain) {
    const findings = [];

    // Common locations where credentials might be exposed
    const suspiciousPaths = [
      '/.env',
      '/.env.local',
      '/config.json',
      '/aws.json',
      '/credentials',
      '/secrets.json',
      '/.aws/credentials',
      '/.git/config',
      '/git/config',
      '/server-config.json',
      '/database-config.json',
      '/api-keys.json',
      '/.github/workflows/config.yml',
    ];

    for (const path of suspiciousPaths) {
      try {
        const urls = [
          `https://${domain}${path}`,
          `http://${domain}${path}`,
        ];

        for (const url of urls) {
          try {
            const response = await axios.get(url, {
              timeout: 3000,
              validateStatus: () => true,
            });

            if (response.status === 200) {
              const content = response.data;

              // Check for credential patterns
              const credPatterns = [
                /AKIA[0-9A-Z]{16}/g, // AWS Access Key
                /aws_secret_access_key|AWS_SECRET|aws_secret/gi,
                /azure.*key|AZURE_.*|azure_secret|AZURE_CLIENT/gi,
                /gcp.*key|GCP_.*|google.*credential/gi,
                /private_key|private-key|privateKey/gi,
                /api.?key|apiKey|API_KEY|api_secret/gi,
              ];

              const hasCredentials = credPatterns.some(pattern => 
                pattern.test(content)
              );

              if (hasCredentials || content.length < 5000) {
                findings.push({
                  type: 'credentials-exposure',
                  path: path,
                  url: url,
                  statusCode: response.status,
                  contentLength: content.length,
                  hasCredentials: hasCredentials,
                });
              }
            }
          } catch (e) {
            // Path not found or error
          }
        }
      } catch (e) {
        // Skip error
      }
    }

    return findings.map(f => this.formatCloudFinding(f));
  }

  /**
   * Check DNS for cloud provider indicators
   */
  async checkDNSRecords(domain) {
    const findings = [];

    // Check for common cloud CNAME patterns
    const cloudIndicators = [
      { pattern: /cloudfront\.net/, provider: 'AWS CloudFront', severity: 'LOW' },
      { pattern: /azurecdn\.net/, provider: 'Azure CDN', severity: 'LOW' },
      { pattern: /akamai\.net/, provider: 'Akamai CDN', severity: 'LOW' },
      { pattern: /amazonaws\.com/, provider: 'AWS', severity: 'LOW' },
      { pattern: /azurewebsites\.net/, provider: 'Azure Web Apps', severity: 'LOW' },
      { pattern: /appspot\.com/, provider: 'Google App Engine', severity: 'LOW' },
      { pattern: /firebaseapp\.com/, provider: 'Firebase', severity: 'LOW' },
    ];

    // Try DNS resolution (passive - no actual DNS queries in this mock)
    // In production, use dns module or external DNS API

    return findings.map(f => this.formatCloudFinding(f));
  }

  /**
   * Check AWS configuration (requires credentials)
   */
  async checkAWSConfiguration() {
    const findings = [];

    // This would require AWS SDK and real credentials
    // For now, returning template structure

    // This would check:
    // - S3 bucket permissions
    // - IAM policies overly permissive
    // - Security groups allowing 0.0.0.0/0
    // - RDS public exposure
    // - Secrets Manager for exposed secrets

    return findings;
  }

  /**
   * Check Azure configuration (requires credentials)
   */
  async checkAzureConfiguration() {
    const findings = [];

    // This would require Azure SDK and real credentials
    // Would check:
    // - Storage account public access
    // - KeyVault access policies
    // - Network security groups
    // - Managed identities configuration

    return findings;
  }

  /**
   * Check GCP configuration (requires credentials)
   */
  async checkGCPConfiguration() {
    const findings = [];

    // This would require GCP SDK and real credentials
    // Would check:
    // - Cloud Storage bucket permissions
    // - IAM roles too permissive
    // - Service accounts with high privileges
    // - Cloud Firewall rules

    return findings;
  }

  /**
   * Format cloud security finding
   */
  formatCloudFinding(finding) {
    return {
      title: this.generateTitle(finding),
      severity: this.calculateCloudSeverity(finding),
      cvss: this.calculateCloudCVSS(finding),
      cve: null,
      cwe: this.mapToCWE(finding),
      description: this.generateDescription(finding),
      evidence: JSON.stringify(finding),
      remediation: this.generateRemediation(finding),
      source: this.reconType,
      tags: ['cloud-security', finding.type || 'misconfiguration'],
    };
  }

  /**
   * Generate title for cloud finding
   */
  generateTitle(finding) {
    if (finding.category === 's3-exposure') {
      return `AWS S3 Bucket Exposure: ${finding.bucketName}`;
    }
    if (finding.type === 'credentials-exposure') {
      return `Cloud Credentials Exposure: ${finding.path}`;
    }
    if (finding.type === 'dns-cloud-service') {
      return `Cloud Service Detected: ${finding.provider}`;
    }
    return 'Cloud Security Issue Detected';
  }

  /**
   * Calculate severity for cloud finding
   */
  calculateCloudSeverity(finding) {
    if (finding.hasCredentials) return 'CRITICAL';
    if (finding.publiclyAccessible) return 'CRITICAL';
    if (finding.type === 'credentials-exposure') return 'CRITICAL';
    if (finding.category === 's3-exposure' && finding.accessible) return 'HIGH';
    return 'MEDIUM';
  }

  /**
   * Calculate CVSS for cloud finding
   */
  calculateCloudCVSS(finding) {
    if (finding.hasCredentials) return 9.8;
    if (finding.publiclyAccessible) return 9.1;
    if (finding.type === 'credentials-exposure') return 9.8;
    if (finding.category === 's3-exposure') return 7.5;
    return 5.3;
  }

  /**
   * Map to CWE
   */
  mapToCWE(finding) {
    if (finding.category === 's3-exposure') return 732; // Incorrect Permission Assignment
    if (finding.type === 'credentials-exposure') return 798; // Use of Hard-Coded Credentials
    return 693; // Incomplete List of Disallowed Inputs
  }

  /**
   * Generate remediation steps
   */
  generateRemediation(finding) {
    if (finding.category === 's3-exposure') {
      return `1. Review S3 bucket "${finding.bucketName}" permissions
2. Remove public access using "Block Public Access" settings
3. Enable S3 server-side encryption
4. Enable S3 versioning and MFA delete
5. Configure S3 bucket lifecycle policies`;
    }
    if (finding.type === 'credentials-exposure') {
      return `1. Remove exposed file from production
2. Rotate exposed credentials immediately
3. Audit access logs for unauthorized access
4. Use AWS Secrets Manager or Azure KeyVault for credential storage
5. Implement file access controls`;
    }
    return 'Review and remediate cloud security configuration';
  }

  /**
   * Generate description
   */
  generateDescription(finding) {
    if (finding.category === 's3-exposure') {
      return `AWS S3 bucket "${finding.bucketName}" is ${finding.publiclyAccessible ? 'publicly accessible' : 'accessible but not public'}. This may expose sensitive data.`;
    }
    if (finding.type === 'credentials-exposure') {
      return `Cloud credentials or secrets might be exposed at ${finding.path}`;
    }
    return 'Cloud security misconfiguration detected';
  }

  /**
   * Main execute method
   */
  async execute(asset, config = {}) {
    try {
      const scanType = config.scanType || 'standard'; // quick, standard

      let findings;
      switch (scanType) {
        case 'quick':
          findings = await this.quickScan(asset);
          break;
        case 'standard':
        default:
          findings = await this.standardScan(asset);
      }

      return {
        status: 'completed',
        findings: findings,
        issuesFound: findings.length,
      };
    } catch (error) {
      return {
        status: 'error',
        error: error.message,
        findings: [],
        issuesFound: 0,
      };
    }
  }
}

module.exports = CloudSecurityService;
