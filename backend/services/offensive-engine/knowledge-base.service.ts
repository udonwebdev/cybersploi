export interface VulnerabilityPattern {
  id: string;
  cwe: string;
  owaspCategory: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  testStrategy: string;
  verificationRequirements: string;
  falsePositiveIndicators: string[];
  remediationAdvice: string;
}

export class SecurityKnowledgeBase {
  private static patterns: Map<string, VulnerabilityPattern> = new Map();

  static {
    this.registerPattern({
      id: 'IDOR_BROKEN_OBJECT_LEVEL_AUTH',
      cwe: 'CWE-639',
      owaspCategory: 'API1:2023 Broken Object Level Authorization',
      name: 'Insecure Direct Object Reference (IDOR)',
      severity: 'HIGH',
      testStrategy: 'Replay request modifying resource IDs using different authenticated session tokens.',
      verificationRequirements: 'Demonstrate access to sensitive data belonging to another tenant/user without authorization.',
      falsePositiveIndicators: ['Publicly readable shared resource', 'Synthetic mock ID returns dummy data'],
      remediationAdvice: 'Implement object-level access control checks verifying user ownership of resource ID.'
    });

    this.registerPattern({
      id: 'BROKEN_FUNCTION_LEVEL_AUTH',
      cwe: 'CWE-285',
      owaspCategory: 'API5:2023 Broken Function Level Authorization',
      name: 'Vertical Privilege Escalation',
      severity: 'CRITICAL',
      testStrategy: 'Execute administrative actions using standard user or guest role credentials.',
      verificationRequirements: 'Successful execution (HTTP 200/201) of administrative endpoint by non-admin identity.',
      falsePositiveIndicators: ['Endpoint returns 200 with error/login prompt body', 'Soft 404 redirects'],
      remediationAdvice: 'Enforce strict role-based access control (RBAC) at the route gateway and controller levels.'
    });

    this.registerPattern({
      id: 'MISSING_SECURITY_HEADERS',
      cwe: 'CWE-693',
      owaspCategory: 'A05:2021 Security Misconfiguration',
      name: 'Missing Security Defense Headers (CSP / HSTS / X-Frame)',
      severity: 'LOW',
      testStrategy: 'Inspect HTTP response headers on HTML/API entry points.',
      verificationRequirements: 'Verify absence of Content-Security-Policy, Strict-Transport-Security, or X-Frame-Options.',
      falsePositiveIndicators: ['Reverse proxy terminates headers only on specific environments'],
      remediationAdvice: 'Configure server to send Content-Security-Policy and Strict-Transport-Security headers.'
    });

    this.registerPattern({
      id: 'INFORMATION_EXPOSURE_SERVER_BANNER',
      cwe: 'CWE-200',
      owaspCategory: 'A05:2021 Security Misconfiguration',
      name: 'Server Technology Banner Disclosure',
      severity: 'LOW',
      testStrategy: 'Analyze Server and X-Powered-By response headers during banner inspection.',
      verificationRequirements: 'Direct disclosure of specific OS and server version numbers in responses.',
      falsePositiveIndicators: ['Generic reverse proxy names without version strings'],
      remediationAdvice: 'Disable server signature tokens in web server configurations.'
    });
  }

  public static registerPattern(pattern: VulnerabilityPattern) {
    this.patterns.set(pattern.id, pattern);
  }

  public static getPattern(id: string): VulnerabilityPattern | undefined {
    return this.patterns.get(id);
  }

  public static listPatterns(): VulnerabilityPattern[] {
    return Array.from(this.patterns.values());
  }

  public static findByCwe(cwe: string): VulnerabilityPattern | undefined {
    for (const p of this.patterns.values()) {
      if (p.cwe === cwe) return p;
    }
    return undefined;
  }
}
