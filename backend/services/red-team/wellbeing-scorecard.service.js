/**
 * Website Wellbeing & Security Posture Scorecard Service
 * Evaluates the overall health, resilience, and security posture of an assessed target
 * across 6 core enterprise security pillars:
 * 1. Perimeter & Infrastructure Resilience
 * 2. Web Application & Ingress Hardening
 * 3. Identity, Session & Access Control
 * 4. Cryptographic Posture & Transport Security
 * 5. Data Protection & Secret Hygiene
 * 6. API, Interface & Error Resilience
 */

class WellbeingScorecardService {
  /**
   * Calculate comprehensive wellbeing scorecard from assessment data
   */
  static calculateScorecard({
    host,
    dnsData = {},
    portData = {},
    tlsData = {},
    appData = {},
    verifiedFindings = [],
    techStack = {},
    coverage = {}
  }) {
    // 1. Evaluate Pillar 1: Perimeter & Infrastructure Resilience (Weight: 15)
    let p1Score = 100;
    const p1Deductions = [];
    const openPorts = portData.openPorts || [];
    const adminPorts = openPorts.filter(p => [21, 22, 23, 3306, 5432, 1433, 6379, 27017, 2375, 3389, 9200].includes(p.port));
    if (adminPorts.length > 0) {
      p1Score -= Math.min(50, adminPorts.length * 25);
      p1Deductions.push(`Exposed administrative/database ports (${adminPorts.map(p => p.port).join(', ')}) on perimeter`);
    }
    if (openPorts.length > 8) {
      p1Score -= 15;
      p1Deductions.push(`High perimeter attack surface: ${openPorts.length} open ports discovered`);
    }
    p1Score = Math.max(0, p1Score);

    // 2. Evaluate Pillar 2: Web Application & Ingress Hardening (Weight: 20)
    let p2Score = 100;
    const p2Deductions = [];
    const secHeaders = appData.securityHeaders || {};
    if (!secHeaders.csp) {
      p2Score -= 25;
      p2Deductions.push('Missing Content-Security-Policy (CSP) exposes users to XSS execution');
    }
    if (!secHeaders.xFrameOptions) {
      p2Score -= 20;
      p2Deductions.push('Missing Clickjacking defense (X-Frame-Options or frame-ancestors)');
    }
    if (!secHeaders.xContentTypeOptions) {
      p2Score -= 15;
      p2Deductions.push('Missing X-Content-Type-Options exposes users to MIME-confusion attacks');
    }
    if (!secHeaders.referrerPolicy) {
      p2Score -= 10;
      p2Deductions.push('Missing Referrer-Policy allows leaking sensitive URLs in Referer header');
    }
    if (!secHeaders.permissionsPolicy) {
      p2Score -= 10;
      p2Deductions.push('Missing Permissions-Policy leaves browser hardware/sensor APIs unconstrained');
    }
    p2Score = Math.max(0, p2Score);

    // 3. Evaluate Pillar 3: Identity, Session & Access Control (Weight: 20)
    let p3Score = 100;
    const p3Deductions = [];
    const cookieIssues = verifiedFindings.filter(f => f.title.includes('HttpOnly') || f.title.includes('Secure') || f.title.includes('SameSite'));
    const authBypass = verifiedFindings.filter(f => f.title.includes('Authorization') || f.title.includes('Auth Boundary'));
    if (authBypass.length > 0) {
      p3Score -= 50;
      p3Deductions.push('Broken function-level authorization or unrestricted administrative entrypoints');
    }
    if (cookieIssues.length > 0) {
      p3Score -= Math.min(40, cookieIssues.length * 20);
      p3Deductions.push(`Session cookies lack modern security flags (${cookieIssues.length} issues identified)`);
    }
    p3Score = Math.max(0, p3Score);

    // 4. Evaluate Pillar 4: Cryptographic Posture & Transport Security (Weight: 15)
    let p4Score = 100;
    const p4Deductions = [];
    if (!secHeaders.hsts) {
      p4Score -= 30;
      p4Deductions.push('HTTP Strict Transport Security (HSTS) not enforced, vulnerable to SSL-stripping');
    }
    if (tlsData.supported) {
      if (tlsData.isExpired) {
        p4Score -= 50;
        p4Deductions.push('TLS/SSL certificate is expired');
      } else if (tlsData.isExpiringSoon) {
        p4Score -= 20;
        p4Deductions.push(`TLS certificate expiring soon (${tlsData.daysRemaining} days remaining)`);
      }
      if (tlsData.protocol === 'TLSv1' || tlsData.protocol === 'TLSv1.1') {
        p4Score -= 35;
        p4Deductions.push(`Legacy insecure TLS protocol (${tlsData.protocol}) negotiated`);
      }
    }
    p4Score = Math.max(0, p4Score);

    // 5. Evaluate Pillar 5: Data Protection & Secret Hygiene (Weight: 15)
    let p5Score = 100;
    const p5Deductions = [];
    const sensitiveLeaks = verifiedFindings.filter(f => f.severity === 'CRITICAL' || f.title.includes('Sensitive') || f.title.includes('Secret') || f.title.includes('.env'));
    if (sensitiveLeaks.length > 0) {
      p5Score -= Math.min(80, sensitiveLeaks.length * 40);
      p5Deductions.push(`Public disclosure of sensitive environment files or secrets (${sensitiveLeaks.length} confirmed)`);
    }
    const stackTraceLeaks = verifiedFindings.filter(f => f.title.includes('Stack Trace') || f.title.includes('Error Leakage'));
    if (stackTraceLeaks.length > 0) {
      p5Score -= 20;
      p5Deductions.push('Verbose stack trace or database error messages leaked in responses');
    }
    p5Score = Math.max(0, p5Score);

    // 6. Evaluate Pillar 6: API, Interface & Error Resilience (Weight: 15)
    let p6Score = 100;
    const p6Deductions = [];
    const corsIssues = verifiedFindings.filter(f => f.title.includes('CORS'));
    if (corsIssues.length > 0) {
      p6Score -= 35;
      p6Deductions.push('Permissive cross-origin resource sharing policy with reflective origins or wildcard credentials');
    }
    const methodIssues = verifiedFindings.filter(f => f.title.includes('HTTP Method') || f.title.includes('TRACE'));
    if (methodIssues.length > 0) {
      p6Score -= 25;
      p6Deductions.push('Insecure HTTP methods (TRACE/PUT/DELETE) enabled on perimeter gateway');
    }
    const apiSchemaExposed = (appData.discoveredEndpoints || []).some(ep => ep.type === 'exposed_api_schema');
    if (apiSchemaExposed) {
      p6Score -= 15;
      p6Deductions.push('API documentation/schema publicly exposed without access control');
    }
    p6Score = Math.max(0, p6Score);

    // Weighted Overall Wellbeing Calculation
    const overallScore = Math.round(
      (p1Score * 0.15) +
      (p2Score * 0.20) +
      (p3Score * 0.20) +
      (p4Score * 0.15) +
      (p5Score * 0.15) +
      (p6Score * 0.15)
    );

    // Grade Assignment
    let letterGrade = 'F';
    let threatIndex = 'CRITICAL';
    let summaryHeadline = '';

    if (overallScore >= 95) {
      letterGrade = 'A+';
      threatIndex = 'MINIMAL';
      summaryHeadline = 'Enterprise-grade defensive hardening with exemplary posture across all pillars.';
    } else if (overallScore >= 85) {
      letterGrade = 'A';
      threatIndex = 'LOW';
      summaryHeadline = 'Strong security posture with minor defense-in-depth hardening opportunities.';
    } else if (overallScore >= 75) {
      letterGrade = 'B';
      threatIndex = 'MODERATE';
      summaryHeadline = 'Acceptable baseline security; moderate exposure to client-side injection and configuration gaps.';
    } else if (overallScore >= 60) {
      letterGrade = 'C';
      threatIndex = 'ELEVATED';
      summaryHeadline = 'Substantial security deficiencies requiring prioritized engineering intervention.';
    } else if (overallScore >= 45) {
      letterGrade = 'D';
      threatIndex = 'HIGH';
      summaryHeadline = 'Severe vulnerability footprint; critical risk of perimeter intrusion or credential compromise.';
    } else {
      letterGrade = 'F';
      threatIndex = 'CRITICAL';
      summaryHeadline = 'Critical security failure. Target perimeter possesses actively exploitable vectors.';
    }

    // Strengths & Highlights
    const strengths = [];
    if (adminPorts.length === 0) strengths.push('Perimeter is free of exposed administrative and database services.');
    if (secHeaders.hsts) strengths.push('Strict Transport Security is active, protecting encrypted channels.');
    if (secHeaders.csp) strengths.push('Content Security Policy is deployed to mitigate script injection.');
    if (sensitiveLeaks.length === 0) strengths.push('Zero configuration files or credential secrets exposed.');
    if (corsIssues.length === 0) strengths.push('CORS access controls properly isolate cross-domain requests.');
    if (cookieIssues.length === 0) strengths.push('Authentication cookies enforce complete HttpOnly and Secure flags.');

    // Critical Exposures
    const criticalExposures = verifiedFindings
      .filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')
      .map(f => ({
        title: f.title,
        severity: f.severity,
        cwe: f.cwe,
        exploitability: f.exploitability || 'DIRECTLY_EXPLOITABLE',
        remediationSummary: f.remediation
      }));

    // Compliance Posture
    const compliance = {
      owaspTop10_2021: {
        a01_broken_access_control: authBypass.length === 0 && corsIssues.length === 0 ? 'PASS' : 'FAIL',
        a02_cryptographic_failures: secHeaders.hsts && (!tlsData.isExpired) ? 'PASS' : 'FAIL',
        a03_injection: secHeaders.csp ? 'PASS' : 'WARNING',
        a04_insecure_design: p1Score > 70 ? 'PASS' : 'WARNING',
        a05_security_misconfiguration: (secHeaders.xFrameOptions && secHeaders.xContentTypeOptions) ? 'PASS' : 'FAIL',
        a07_identification_auth_failures: cookieIssues.length === 0 ? 'PASS' : 'FAIL'
      },
      cisControlsV8: {
        accessControlManagement: authBypass.length === 0 ? 'COMPLIANT' : 'NON_COMPLIANT',
        dataProtection: sensitiveLeaks.length === 0 ? 'COMPLIANT' : 'NON_COMPLIANT',
        secureConfiguration: overallScore >= 75 ? 'COMPLIANT' : 'ACTION_REQUIRED',
        servicePortsRestriction: adminPorts.length === 0 ? 'COMPLIANT' : 'NON_COMPLIANT'
      }
    };

    return {
      overallScore,
      letterGrade,
      threatIndex,
      summaryHeadline,
      pillars: [
        {
          id: 'perimeter',
          name: 'Perimeter & Infrastructure Resilience',
          weightPercent: 15,
          score: p1Score,
          status: p1Score >= 80 ? 'HEALTHY' : (p1Score >= 50 ? 'WARNING' : 'CRITICAL'),
          deductions: p1Deductions
        },
        {
          id: 'web_hardening',
          name: 'Web Application & Ingress Hardening',
          weightPercent: 20,
          score: p2Score,
          status: p2Score >= 80 ? 'HEALTHY' : (p2Score >= 50 ? 'WARNING' : 'CRITICAL'),
          deductions: p2Deductions
        },
        {
          id: 'identity_access',
          name: 'Identity, Session & Access Control',
          weightPercent: 20,
          score: p3Score,
          status: p3Score >= 80 ? 'HEALTHY' : (p3Score >= 50 ? 'WARNING' : 'CRITICAL'),
          deductions: p3Deductions
        },
        {
          id: 'cryptography',
          name: 'Cryptographic Posture & Transport Security',
          weightPercent: 15,
          score: p4Score,
          status: p4Score >= 80 ? 'HEALTHY' : (p4Score >= 50 ? 'WARNING' : 'CRITICAL'),
          deductions: p4Deductions
        },
        {
          id: 'data_protection',
          name: 'Data Protection & Secret Hygiene',
          weightPercent: 15,
          score: p5Score,
          status: p5Score >= 80 ? 'HEALTHY' : (p5Score >= 50 ? 'WARNING' : 'CRITICAL'),
          deductions: p5Deductions
        },
        {
          id: 'api_interface',
          name: 'API, Interface & Error Resilience',
          weightPercent: 15,
          score: p6Score,
          status: p6Score >= 80 ? 'HEALTHY' : (p6Score >= 50 ? 'WARNING' : 'CRITICAL'),
          deductions: p6Deductions
        }
      ],
      strengths,
      criticalExposures,
      compliance,
      techStackSummary: techStack,
      generatedAt: new Date().toISOString()
    };
  }
}

module.exports = WellbeingScorecardService;
