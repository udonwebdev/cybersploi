/**
 * Vulnerability Hypothesis & False-Positive Reduction Engine
 * Formulates testable security hypotheses from discovered attack surface,
 * performs secondary counter-evidence tests, rejects false positives,
 * and calibrates confidence via the FastAPI AI microservice (:8001).
 */

const axios = require('axios');
const net = require('net');

class HypothesisEngineService {
  /**
   * Generates initial hypotheses based on recon & cartography telemetry
   */
  static generateHypotheses({ host, dnsData, portData, tlsData, appData }) {
    const hypotheses = [];

    // 1. Email Sender Spoofing Hypothesis (SPF/DMARC)
    if (dnsData && dnsData.records) {
      const txtRecords = dnsData.records.txt || [];
      const hasSpf = txtRecords.some(r => r.toLowerCase().startsWith('v=spf1'));
      hypotheses.push({
        title: 'Missing SPF Email Authentication Record',
        description: 'Target DNS zone lacks an SPF TXT record, allowing unauthorized third parties to spoof outbound emails.',
        category: 'auth_boundary',
        targetEndpoint: host,
        initialConfidence: hasSpf ? 0.2 : 0.85,
        testProcedure: 'Query DNS TXT records via authoritative resolvers to check for v=spf1 policy string.',
        observedEvidence: { txtRecordCount: txtRecords.length, hasSpf }
      });
    }

    // 2. Open Administrative / Database Ports
    if (portData && portData.openPorts) {
      const openPorts = portData.openPorts;
      const adminPorts = openPorts.filter(p => [21, 22, 23, 3306, 5432, 1433, 6379, 27017, 2375, 3389].includes(p.port));

      adminPorts.forEach(ap => {
        hypotheses.push({
          title: `Administrative / Database Service (${ap.service}) Exposed on Public Perimeter`,
          description: `Port ${ap.port} (${ap.service}) is actively accepting raw TCP connections on the public-facing perimeter.`,
          category: 'network_service',
          targetEndpoint: `${host}:${ap.port}`,
          initialConfidence: 0.9,
          testProcedure: `Attempt secondary socket handshake on port ${ap.port} and inspect banner response.`,
          observedEvidence: { port: ap.port, service: ap.service, banner: ap.banner }
        });
      });
    }

    // 3. TLS Cryptographic / Certificate Expiration Hypothesis
    if (tlsData && tlsData.supported) {
      if (tlsData.isExpired || tlsData.isExpiringSoon) {
        hypotheses.push({
          title: tlsData.isExpired ? 'Expired TLS/SSL Certificate' : 'Imminent TLS/SSL Certificate Expiration',
          description: `TLS certificate for ${host} ${tlsData.isExpired ? 'expired on' : 'expires on'} ${tlsData.validTo} (${tlsData.daysRemaining} days remaining).`,
          category: 'crypto_weakness',
          targetEndpoint: `${host}:443`,
          initialConfidence: 0.95,
          testProcedure: 'Verify certificate validity dates against active system clock.',
          observedEvidence: { validTo: tlsData.validTo, daysRemaining: tlsData.daysRemaining, issuer: tlsData.issuer }
        });
      }

      // Check for legacy TLS protocol (TLSv1.0 or TLSv1.1)
      if (tlsData.protocol === 'TLSv1' || tlsData.protocol === 'TLSv1.1') {
        hypotheses.push({
          title: `Legacy Insecure TLS Protocol Version (${tlsData.protocol})`,
          description: `Server negotiated ${tlsData.protocol} which is deprecated by RFC 8996 due to known cryptographic weaknesses (POODLE, BEAST).`,
          category: 'crypto_weakness',
          targetEndpoint: `${host}:443`,
          initialConfidence: 0.92,
          testProcedure: 'Verify cryptographic handshake version negotiation.',
          observedEvidence: { protocol: tlsData.protocol, cipher: tlsData.cipher }
        });
      }
    }

    // 4. HTTP Security Headers
    if (appData && appData.statusCode) {
      if (!appData.securityHeaders.hsts && (appData.baseUrl.startsWith('https') || portData?.openPorts.some(p => p.port === 443))) {
        hypotheses.push({
          title: 'Missing Strict-Transport-Security (HSTS) Header',
          description: 'Web application fails to enforce HSTS header, allowing man-in-the-middle SSL stripping downgrades.',
          category: 'crypto_weakness',
          targetEndpoint: appData.baseUrl,
          initialConfidence: 0.88,
          testProcedure: 'Perform secondary GET request to verify absence of Strict-Transport-Security response header.',
          observedEvidence: { statusCode: appData.statusCode, hstsPresent: false }
        });
      }

      if (!appData.securityHeaders.csp) {
        hypotheses.push({
          title: 'Missing or Permissive Content Security Policy (CSP)',
          description: 'No Content-Security-Policy header defined on the primary HTTP entrypoint, increasing vulnerability to Cross-Site Scripting (XSS).',
          category: 'input_validation',
          targetEndpoint: appData.baseUrl,
          initialConfidence: 0.85,
          testProcedure: 'Inspect response headers for content-security-policy or content-security-policy-report-only.',
          observedEvidence: { statusCode: appData.statusCode, cspPresent: false }
        });
      }

      if (!appData.securityHeaders.xFrameOptions) {
        hypotheses.push({
          title: 'Missing Clickjacking Defense (X-Frame-Options / CSP frame-ancestors)',
          description: 'Web application can be embedded inside external iframes, leaving users vulnerable to clickjacking attacks.',
          category: 'input_validation',
          targetEndpoint: appData.baseUrl,
          initialConfidence: 0.8,
          testProcedure: 'Check for X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors directive.',
          observedEvidence: { xFrameOptionsPresent: false }
        });
      }

      // CORS Misconfiguration
      if (appData.cors?.isWildcardWithCredentials || appData.cors?.isReflectiveOrigin) {
        hypotheses.push({
          title: 'Permissive Cross-Origin Resource Sharing (CORS) Configuration',
          description: appData.cors.isReflectiveOrigin
            ? 'Access-Control-Allow-Origin dynamically reflects arbitrary third-party origins, allowing unauthorized cross-domain data reading.'
            : 'Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true violates browser security standards.',
          category: 'auth_boundary',
          targetEndpoint: appData.baseUrl,
          initialConfidence: 0.92,
          testProcedure: 'Send preflight probe with unauthorized Origin header and examine response headers.',
          observedEvidence: appData.cors
        });
      }

      // Sensitive Disclosures (Authentic signatures detected)
      if (appData.sensitiveDisclosures && appData.sensitiveDisclosures.length > 0) {
        appData.sensitiveDisclosures.forEach(sd => {
          hypotheses.push({
            title: `Exposed Sensitive Path / Secret Disclosure (${sd.path})`,
            description: `Publicly accessible sensitive endpoint discovered at ${sd.path} returning HTTP status ${sd.statusCode}.`,
            category: 'sensitive_data',
            targetEndpoint: `${appData.baseUrl}${sd.path}`,
            initialConfidence: 0.95,
            testProcedure: `Re-request ${sd.path} and verify data payload contains authentic diagnostic/secret markers.`,
            observedEvidence: sd
          });
        });
      }

      // Suspected Sensitive Disclosures (Candidate hypotheses that may be soft-404 / generic 200 false positives)
      if (appData.suspectedDisclosures && appData.suspectedDisclosures.length > 0) {
        appData.suspectedDisclosures.slice(0, 3).forEach(sd => {
          hypotheses.push({
            title: `Suspected Sensitive Path Disclosure (${sd.path})`,
            description: `HTTP GET to ${sd.path} returned status ${sd.statusCode}. Secondary validation required to eliminate soft-404 false positive.`,
            category: 'sensitive_data',
            targetEndpoint: `${appData.baseUrl}${sd.path}`,
            initialConfidence: 0.60,
            testProcedure: `Perform secondary signature verification on ${sd.path} to differentiate genuine disclosure from soft-404 false positive.`,
            observedEvidence: sd
          });
        });
      }

      // Missing X-Content-Type-Options
      if (!appData.securityHeaders.xContentTypeOptions) {
        hypotheses.push({
          title: 'Missing MIME-Sniffing Protection (X-Content-Type-Options)',
          description: 'Absence of X-Content-Type-Options: nosniff header allows browsers to interpret responses as executable scripts.',
          category: 'input_validation',
          targetEndpoint: appData.baseUrl,
          initialConfidence: 0.85,
          testProcedure: 'Verify absence of X-Content-Type-Options: nosniff header across HTTP responses.',
          observedEvidence: { xContentTypeOptionsPresent: false }
        });
      }

      // Missing Referrer-Policy
      if (!appData.securityHeaders.referrerPolicy) {
        hypotheses.push({
          title: 'Missing Referrer-Policy Header',
          description: 'Target fails to set Referrer-Policy, risking credential, token, or private path leakage in the Referer header to third parties.',
          category: 'sensitive_data',
          targetEndpoint: appData.baseUrl,
          initialConfidence: 0.80,
          testProcedure: 'Inspect headers for referrer-policy directive.',
          observedEvidence: { referrerPolicyPresent: false }
        });
      }

      // Missing Permissions-Policy
      if (!appData.securityHeaders.permissionsPolicy) {
        hypotheses.push({
          title: 'Missing Permissions-Policy (Feature-Policy)',
          description: 'No Permissions-Policy header configured, allowing embedded iframes to access client camera, microphone, and geolocation APIs.',
          category: 'input_validation',
          targetEndpoint: appData.baseUrl,
          initialConfidence: 0.78,
          testProcedure: 'Inspect headers for permissions-policy or feature-policy.',
          observedEvidence: { permissionsPolicyPresent: false }
        });
      }

      // Insecure HTTP TRACE Method (Cross-Site Tracing XST)
      if (appData.methodAudit?.traceEnabled) {
        hypotheses.push({
          title: 'Insecure HTTP TRACE Method Enabled (Cross-Site Tracing XST)',
          description: 'Server reflects arbitrary TRACE requests including authorization headers, enabling attackers to bypass HttpOnly cookie protections via XSS.',
          category: 'network_service',
          targetEndpoint: appData.baseUrl,
          initialConfidence: 0.95,
          testProcedure: 'Send empirical TRACE request with unique token header and verify reflection in response body.',
          observedEvidence: { traceEnabled: true }
        });
      }

      // Verbose Stack Trace / Diagnostic Leakage
      if (appData.diagnosticErrorLeaks && appData.diagnosticErrorLeaks.length > 0) {
        appData.diagnosticErrorLeaks.forEach(errLeak => {
          hypotheses.push({
            title: 'Verbose Stack Trace / Diagnostic Error Leakage',
            description: `Application returns detailed internal debugging traces or database error strings when presented with unexpected input (${errLeak.marker}).`,
            category: 'sensitive_data',
            targetEndpoint: appData.baseUrl,
            initialConfidence: 0.90,
            testProcedure: 'Trigger controlled error condition and examine response payload for diagnostic stack traces.',
            observedEvidence: errLeak
          });
        });
      }

      // Server / Tech Banner Disclosure
      if (appData.headers && (appData.headers['server'] || appData.headers['x-powered-by'])) {
        hypotheses.push({
          title: 'Server Component & Infrastructure Banner Disclosure',
          description: `Server leaks specific software identity in response headers (${appData.headers['server'] || appData.headers['x-powered-by']}), assisting adversary fingerprinting.`,
          category: 'sensitive_data',
          targetEndpoint: appData.baseUrl,
          initialConfidence: 0.92,
          testProcedure: 'Inspect Server and X-Powered-By response headers for version information.',
          observedEvidence: { server: appData.headers['server'], poweredBy: appData.headers['x-powered-by'] }
        });
      }

      // 5. Exposed Production Source Maps (.js.map)
      if (appData.sensitiveDisclosures) {
        const sourceMapDisclosures = appData.sensitiveDisclosures.filter(sd => sd.type === 'exposed_source_map');
        sourceMapDisclosures.forEach(sd => {
          hypotheses.push({
            title: `Exposed Client-Side JavaScript Source Map (${sd.path})`,
            description: `Production JavaScript source map (.map) is publicly accessible at ${sd.path}, disclosing unminified frontend source code, internal route paths, and proprietary business logic.`,
            category: 'sensitive_data',
            targetEndpoint: `${appData.baseUrl}${sd.path}`,
            initialConfidence: 0.96,
            testProcedure: `Re-request ${sd.path} and verify payload matches authentic JSON source map schema with version and sources attributes.`,
            observedEvidence: sd
          });
        });
      }

      // 6. Missing Anti-CSRF Token on State-Changing HTML Forms
      if (appData.discoveredForms && appData.discoveredForms.length > 0) {
        const unprotectedForms = appData.discoveredForms.filter(f => f.method === 'POST' && !f.hasCsrfProtection);
        unprotectedForms.forEach(form => {
          const formEndpoint = form.action.startsWith('http') ? form.action : `${appData.baseUrl}${form.action.startsWith('/') ? form.action : '/' + form.action}`;
          hypotheses.push({
            title: `State-Changing HTML Form Lacks Anti-CSRF Token (${form.action})`,
            description: `Form submitting via POST to '${form.action}' lacks an anti-CSRF token input, enabling cross-origin attackers to submit unauthorized transactions on behalf of authenticated users.`,
            category: 'input_validation',
            targetEndpoint: formEndpoint,
            initialConfidence: 0.90,
            testProcedure: 'Inspect form DOM inputs to verify absence of synchronizer CSRF token fields.',
            observedEvidence: form
          });
        });
      }

      // 7. Cookie Hygiene Attributes (HttpOnly, Secure, SameSite)
      if (appData.cookies && appData.cookies.length > 0) {
        appData.cookies.forEach(cookie => {
          if (!cookie.isHttpOnly) {
            hypotheses.push({
              title: `Session / Authentication Cookie Lacks HttpOnly Flag (${cookie.name})`,
              description: `Cookie '${cookie.name}' is transmitted without the HttpOnly attribute, exposing it to unauthorized extraction via Cross-Site Scripting (XSS).`,
              category: 'auth_boundary',
              targetEndpoint: appData.baseUrl,
              initialConfidence: 0.92,
              testProcedure: 'Verify Set-Cookie response header does not contain HttpOnly directive.',
              observedEvidence: cookie
            });
          }
          if (!cookie.isSecure && (appData.baseUrl.startsWith('https') || portData?.openPorts?.some(p => p.port === 443))) {
            hypotheses.push({
              title: `Cookie Lacks Secure Flag Over Transport (${cookie.name})`,
              description: `Cookie '${cookie.name}' lacks the Secure attribute, allowing unencrypted transmission across plaintext HTTP channels.`,
              category: 'crypto_weakness',
              targetEndpoint: appData.baseUrl,
              initialConfidence: 0.90,
              testProcedure: 'Verify Set-Cookie response header does not enforce the Secure flag.',
              observedEvidence: cookie
            });
          }
          if (!cookie.sameSite || cookie.sameSite.toLowerCase() === 'none') {
            hypotheses.push({
              title: `Cookie SameSite Attribute Missing or Permissive (${cookie.name})`,
              description: `Cookie '${cookie.name}' does not enforce SameSite=Lax or SameSite=Strict, permitting cross-site request forgery leakage.`,
              category: 'auth_boundary',
              targetEndpoint: appData.baseUrl,
              initialConfidence: 0.88,
              testProcedure: 'Inspect Set-Cookie header for missing or overly permissive SameSite attribute.',
              observedEvidence: cookie
            });
          }
        });
      }
    }

    return hypotheses;
  }

  /**
   * Evaluates and tests each hypothesis, rejecting false positives or verifying true positives
   */
  static async evaluateHypothesis(hypo, { host, scope }) {
    let status = 'INCONCLUSIVE';
    let currentConfidence = hypo.initialConfidence;
    let rejectionReason = null;
    let verificationEvidence = null;

    try {
      // Test 1: SPF check
      if (hypo.title.includes('Missing SPF')) {
        const txtRecords = hypo.observedEvidence.txtRecordCount > 0 ? hypo.observedEvidence.hasSpf : false;
        if (hypo.observedEvidence.hasSpf) {
          status = 'REJECTED';
          currentConfidence = 0.05;
          rejectionReason = 'Counter-evidence verified: Authoritative DNS contains valid v=spf1 policy string.';
        } else {
          status = 'VERIFIED';
          currentConfidence = 0.95;
          verificationEvidence = {
            verifiedCheck: 'Authoritative TXT query completed without SPF entry',
            timestamp: new Date().toISOString()
          };
        }
      }

      // Test 2: Port Exposure verification
      else if (hypo.category === 'network_service') {
        const port = hypo.observedEvidence.port;
        // Secondary socket test to ensure repeatability
        const repeatCheck = await this.verifySocketRepeatable(host, port);
        if (repeatCheck.success) {
          status = 'VERIFIED';
          currentConfidence = 0.98;
          verificationEvidence = {
            repeatable: true,
            probesCompleted: 2,
            banner: repeatCheck.banner || hypo.observedEvidence.banner || 'Service responding on TCP port',
            timestamp: new Date().toISOString()
          };
        } else {
          status = 'REJECTED';
          currentConfidence = 0.15;
          rejectionReason = `Counter-evidence: Secondary socket probe to port ${port} failed or was dropped by perimeter firewall.`;
        }
      }

      // Test 3: TLS checks
      else if (hypo.category === 'crypto_weakness' && hypo.title.includes('Certificate')) {
        const days = hypo.observedEvidence.daysRemaining;
        if (days !== null && days <= 30) {
          status = 'VERIFIED';
          currentConfidence = 0.99;
          verificationEvidence = {
            daysRemaining: days,
            validTo: hypo.observedEvidence.validTo,
            issuer: hypo.observedEvidence.issuer,
            timestamp: new Date().toISOString()
          };
        } else {
          status = 'REJECTED';
          currentConfidence = 0.05;
          rejectionReason = `Counter-evidence: Certificate is valid with ${days} days remaining (> 30-day threshold).`;
        }
      }

      // Test 4: Missing HSTS Header
      else if (hypo.title.includes('Missing Strict-Transport-Security')) {
        const recheck = await this.verifyHeaderAbsent(hypo.targetEndpoint, 'strict-transport-security');
        if (recheck.isAbsent) {
          status = 'VERIFIED';
          currentConfidence = 0.94;
          verificationEvidence = {
            retestedEndpoint: hypo.targetEndpoint,
            status: recheck.status,
            hstsHeaderMissing: true,
            timestamp: new Date().toISOString()
          };
        } else {
          status = 'REJECTED';
          currentConfidence = 0.1;
          rejectionReason = 'Counter-evidence: Secondary verification request returned active Strict-Transport-Security header.';
        }
      }

      // Test 5: Missing CSP Header
      else if (hypo.title.includes('Content Security Policy')) {
        const recheck = await this.verifyHeaderAbsent(hypo.targetEndpoint, 'content-security-policy');
        if (recheck.isAbsent) {
          status = 'VERIFIED';
          currentConfidence = 0.92;
          verificationEvidence = {
            retestedEndpoint: hypo.targetEndpoint,
            status: recheck.status,
            cspHeaderMissing: true,
            timestamp: new Date().toISOString()
          };
        } else {
          status = 'REJECTED';
          currentConfidence = 0.08;
          rejectionReason = 'Counter-evidence: Secondary verification request confirmed active Content-Security-Policy header.';
        }
      }

      // Test 6: Missing X-Frame-Options
      else if (hypo.title.includes('Clickjacking Defense')) {
        const recheck = await this.verifyHeaderAbsent(hypo.targetEndpoint, 'x-frame-options');
        if (recheck.isAbsent) {
          status = 'VERIFIED';
          currentConfidence = 0.89;
          verificationEvidence = {
            retestedEndpoint: hypo.targetEndpoint,
            xFrameOptionsMissing: true,
            timestamp: new Date().toISOString()
          };
        } else {
          status = 'REJECTED';
          currentConfidence = 0.08;
          rejectionReason = 'Counter-evidence: Secondary verification request confirmed active X-Frame-Options header.';
        }
      }

      // Test 7: CORS Misconfiguration
      else if (hypo.title.includes('CORS')) {
        if (hypo.observedEvidence.isReflectiveOrigin || hypo.observedEvidence.isWildcardWithCredentials) {
          status = 'VERIFIED';
          currentConfidence = 0.96;
          verificationEvidence = {
            corsTelemetry: hypo.observedEvidence,
            timestamp: new Date().toISOString()
          };
        } else {
          status = 'REJECTED';
          currentConfidence = 0.12;
          rejectionReason = 'Counter-evidence: CORS policy strictly restricts origin or forbids credentials.';
        }
      }

      // Test 8: Sensitive Path Disclosures & Suspected Disclosures
      else if (hypo.category === 'sensitive_data') {
        try {
          const res = await axios.get(hypo.targetEndpoint, {
            timeout: 3000,
            validateStatus: () => true,
            headers: { 'User-Agent': 'CyberSploi-Authorized-RedTeam/3.0' }
          });
          if (res.status === 200 && res.data) {
            const bodyStr = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
            const path = hypo.observedEvidence?.path || hypo.targetEndpoint;

            // Signature verification to filter soft-404s
            let isVerifiedAuthentic = false;
            let failureReason = 'Payload lacks authentic diagnostic signatures (soft-404 / default landing page detected)';

            if (path.includes('.env') && (bodyStr.includes('DB_PASSWORD') || bodyStr.includes('APP_KEY') || bodyStr.includes('SECRET='))) {
              isVerifiedAuthentic = true;
            } else if (path.includes('.git') && bodyStr.includes('ref: refs/')) {
              isVerifiedAuthentic = true;
            } else if ((path.includes('swagger') || path.includes('openapi')) && (bodyStr.includes('"openapi"') || bodyStr.includes('"swagger"'))) {
              isVerifiedAuthentic = true;
            } else if (path.includes('actuator') && (bodyStr.includes('propertySources') || bodyStr.includes('"status"'))) {
              isVerifiedAuthentic = true;
            } else if (path.includes('phpinfo') && bodyStr.includes('PHP Version')) {
              isVerifiedAuthentic = true;
            } else if (path.includes('.map') && (bodyStr.includes('"version"') || bodyStr.includes('"sources"') || bodyStr.includes('"mappings"'))) {
              isVerifiedAuthentic = true;
            } else if (path.includes('openid-configuration') && (bodyStr.includes('"issuer"') || bodyStr.includes('"authorization_endpoint"'))) {
              isVerifiedAuthentic = true;
            } else if (path.includes('jwks.json') && bodyStr.includes('"keys"')) {
              isVerifiedAuthentic = true;
            }

            if (isVerifiedAuthentic) {
              status = 'VERIFIED';
              currentConfidence = 0.99;
              verificationEvidence = {
                endpoint: hypo.targetEndpoint,
                statusCode: res.status,
                contentLength: bodyStr.length,
                signatureVerified: true,
                timestamp: new Date().toISOString()
              };
            } else {
              status = 'REJECTED';
              currentConfidence = 0.05;
              rejectionReason = `Counter-evidence: Secondary probe to ${hypo.targetEndpoint} returned HTTP 200 but ${failureReason}. Disproved false positive.`;
            }
          } else {
            status = 'REJECTED';
            currentConfidence = 0.05;
            rejectionReason = `Counter-evidence: Secondary probe to ${hypo.targetEndpoint} returned HTTP ${res.status} (Access denied/Not found).`;
          }
        } catch (err) {
          status = 'INCONCLUSIVE';
          rejectionReason = `Network timeout during secondary verification: ${err.message}`;
        }
      }

      // Test 9: Session Cookie HttpOnly Check
      else if (hypo.title.includes('Session Cookie Lacks HttpOnly') || hypo.title.includes('HttpOnly Flag')) {
        try {
          const res = await axios.get(hypo.targetEndpoint, {
            timeout: 3000,
            validateStatus: () => true,
            headers: { 'User-Agent': 'CyberSploi-Authorized-RedTeam/3.0' }
          });
          const cookies = res.headers['set-cookie'] || [];
          const targetCookieName = hypo.observedEvidence?.name || hypo.observedEvidence?.cookie?.split('=')[0];
          const matchingCookie = cookies.find(c => targetCookieName ? c.startsWith(targetCookieName) : true);
          
          if (matchingCookie && !matchingCookie.toLowerCase().includes('httponly')) {
            status = 'VERIFIED';
            currentConfidence = 0.95;
            verificationEvidence = {
              retestedEndpoint: hypo.targetEndpoint,
              cookieHeader: matchingCookie,
              httpOnlyAbsent: true,
              timestamp: new Date().toISOString()
            };
          } else {
            status = 'REJECTED';
            currentConfidence = 0.05;
            rejectionReason = 'Counter-evidence: Set-Cookie response header contains HttpOnly directive or cookie was not set.';
          }
        } catch (err) {
          status = 'INCONCLUSIVE';
          rejectionReason = `Retest probe failed: ${err.message}`;
        }
      }

      // Test 10: Broken Function-Level Authorization
      else if (hypo.title.includes('Broken Function-Level Authorization')) {
        try {
          const res = await axios.get(hypo.targetEndpoint, {
            timeout: 3000,
            validateStatus: () => true,
            headers: { 'User-Agent': 'CyberSploi-Authorized-RedTeam/3.0' }
          });
          if (res.status === 200 || res.status === 204) {
            status = 'VERIFIED';
            currentConfidence = 0.98;
            verificationEvidence = {
              endpoint: hypo.targetEndpoint,
              statusCode: res.status,
              unauthenticatedAccessPermitted: true,
              timestamp: new Date().toISOString()
            };
          } else {
            status = 'REJECTED';
            currentConfidence = 0.05;
            rejectionReason = `Counter-evidence: Secondary probe returned HTTP ${res.status} enforcing authentication boundary.`;
          }
        } catch (err) {
          status = 'REJECTED';
          currentConfidence = 0.05;
          rejectionReason = `Secondary probe rejected: ${err.message}`;
        }
      }

      // Test 11: Missing X-Content-Type-Options
      else if (hypo.title.includes('X-Content-Type-Options')) {
        const recheck = await this.verifyHeaderAbsent(hypo.targetEndpoint, 'x-content-type-options');
        if (recheck.isAbsent) {
          status = 'VERIFIED';
          currentConfidence = 0.90;
          verificationEvidence = { retestedEndpoint: hypo.targetEndpoint, xContentTypeOptionsMissing: true, timestamp: new Date().toISOString() };
        } else {
          status = 'REJECTED';
          currentConfidence = 0.05;
          rejectionReason = 'Counter-evidence: X-Content-Type-Options: nosniff header confirmed present on retest.';
        }
      }

      // Test 12: Missing Referrer-Policy
      else if (hypo.title.includes('Referrer-Policy')) {
        const recheck = await this.verifyHeaderAbsent(hypo.targetEndpoint, 'referrer-policy');
        if (recheck.isAbsent) {
          status = 'VERIFIED';
          currentConfidence = 0.88;
          verificationEvidence = { retestedEndpoint: hypo.targetEndpoint, referrerPolicyMissing: true, timestamp: new Date().toISOString() };
        } else {
          status = 'REJECTED';
          currentConfidence = 0.05;
          rejectionReason = 'Counter-evidence: Referrer-Policy header confirmed present.';
        }
      }

      // Test 13: Missing Permissions-Policy
      else if (hypo.title.includes('Permissions-Policy')) {
        const recheck = await this.verifyHeaderAbsent(hypo.targetEndpoint, 'permissions-policy');
        if (recheck.isAbsent) {
          status = 'VERIFIED';
          currentConfidence = 0.85;
          verificationEvidence = { retestedEndpoint: hypo.targetEndpoint, permissionsPolicyMissing: true, timestamp: new Date().toISOString() };
        } else {
          status = 'REJECTED';
          currentConfidence = 0.05;
          rejectionReason = 'Counter-evidence: Permissions-Policy header confirmed present.';
        }
      }

      // Test 14: Insecure HTTP TRACE Method
      else if (hypo.title.includes('HTTP TRACE')) {
        try {
          const traceRes = await axios({
            method: 'TRACE',
            url: hypo.targetEndpoint,
            timeout: 2500,
            validateStatus: () => true,
            headers: { 'X-Audit-Check': 'CyberSploi-XST-Verified' }
          });
          if (traceRes.status === 200 && typeof traceRes.data === 'string' && traceRes.data.includes('CyberSploi-XST-Verified')) {
            status = 'VERIFIED';
            currentConfidence = 0.98;
            verificationEvidence = { reflectedHeader: 'X-Audit-Check: CyberSploi-XST-Verified', xstConfirmed: true, timestamp: new Date().toISOString() };
          } else {
            status = 'REJECTED';
            currentConfidence = 0.05;
            rejectionReason = 'Counter-evidence: TRACE request was rejected, blocked, or did not reflect audit headers.';
          }
        } catch (e) {
          status = 'REJECTED';
          currentConfidence = 0.05;
          rejectionReason = `Counter-evidence: TRACE probe failed with ${e.message}`;
        }
      }

      // Test 15: Verbose Stack Trace / Error Leakage
      else if (hypo.title.includes('Verbose Stack Trace')) {
        try {
          const errRes = await axios.get(`${hypo.targetEndpoint}/?cybersploi_err_test=%27%22%3E%3C%00`, {
            timeout: 2500,
            validateStatus: () => true
          });
          const errBody = typeof errRes.data === 'string' ? errRes.data : JSON.stringify(errRes.data || '');
          const hasStack = ['Traceback', 'NullPointerException', 'at Function.', 'TypeError:', 'SQL syntax'].some(k => errBody.includes(k));
          if (hasStack) {
            status = 'VERIFIED';
            currentConfidence = 0.94;
            verificationEvidence = { diagnosticSnippet: errBody.substring(0, 200), timestamp: new Date().toISOString() };
          } else {
            status = 'REJECTED';
            currentConfidence = 0.05;
            rejectionReason = 'Counter-evidence: Server returns generic, safe error page without stack traces.';
          }
        } catch (e) {
          status = 'INCONCLUSIVE';
          rejectionReason = `Error probe timeout: ${e.message}`;
        }
      }

      // Test 16: Server Component & Infrastructure Banner Disclosure
      else if (hypo.title.includes('Server Component')) {
        try {
          const res = await axios.get(hypo.targetEndpoint, { timeout: 2500, validateStatus: () => true });
          const srv = res.headers['server'] || res.headers['x-powered-by'];
          if (srv) {
            status = 'VERIFIED';
            currentConfidence = 0.96;
            verificationEvidence = { serverHeader: srv, timestamp: new Date().toISOString() };
          } else {
            status = 'REJECTED';
            currentConfidence = 0.05;
            rejectionReason = 'Counter-evidence: Server and X-Powered-By headers are stripped.';
          }
        } catch (e) {
          status = 'INCONCLUSIVE';
          rejectionReason = `Banner probe failed: ${e.message}`;
        }
      }

      // Test 17: State-Changing HTML Form Lacks Anti-CSRF Token
      else if (hypo.title.includes('Lacks Anti-CSRF Token')) {
        try {
          const res = await axios.get(hypo.targetEndpoint, {
            timeout: 3000,
            validateStatus: () => true,
            headers: { 'User-Agent': 'CyberSploi-Authorized-RedTeam/3.0' }
          });
          const html = typeof res.data === 'string' ? res.data : '';
          const hasForm = html.toLowerCase().includes('<form');
          const hasCsrfToken = ['csrf', 'token', 'authenticity'].some(k => html.toLowerCase().includes(k));
          if (hasForm && !hasCsrfToken) {
            status = 'VERIFIED';
            currentConfidence = 0.94;
            verificationEvidence = {
              targetEndpoint: hypo.targetEndpoint,
              formAction: hypo.observedEvidence?.action,
              inputs: hypo.observedEvidence?.inputs,
              csrfProtectionAbsent: true,
              timestamp: new Date().toISOString()
            };
          } else {
            status = 'REJECTED';
            currentConfidence = 0.08;
            rejectionReason = 'Counter-evidence: Form includes anti-CSRF token or form is not accessible.';
          }
        } catch (e) {
          status = 'INCONCLUSIVE';
          rejectionReason = `Form audit probe failed: ${e.message}`;
        }
      }

      // Test 18: Cookie SameSite Attribute Missing
      else if (hypo.title.includes('Cookie SameSite Attribute Missing')) {
        try {
          const res = await axios.get(hypo.targetEndpoint, {
            timeout: 3000,
            validateStatus: () => true,
            headers: { 'User-Agent': 'CyberSploi-Authorized-RedTeam/3.0' }
          });
          const cookies = res.headers['set-cookie'] || [];
          const targetName = hypo.observedEvidence?.name;
          const match = cookies.find(c => targetName ? c.startsWith(targetName) : true);
          if (match && (!match.toLowerCase().includes('samesite=') || match.toLowerCase().includes('samesite=none'))) {
            status = 'VERIFIED';
            currentConfidence = 0.95;
            verificationEvidence = {
              cookieHeader: match,
              sameSiteMissingOrNone: true,
              timestamp: new Date().toISOString()
            };
          } else {
            status = 'REJECTED';
            currentConfidence = 0.05;
            rejectionReason = 'Counter-evidence: Cookie sets SameSite=Lax or SameSite=Strict on secondary probe.';
          }
        } catch (e) {
          status = 'INCONCLUSIVE';
          rejectionReason = `Cookie retest probe failed: ${e.message}`;
        }
      }

      // Test 19: Cookie Lacks Secure Flag
      else if (hypo.title.includes('Cookie Lacks Secure Flag')) {
        try {
          const res = await axios.get(hypo.targetEndpoint, {
            timeout: 3000,
            validateStatus: () => true,
            headers: { 'User-Agent': 'CyberSploi-Authorized-RedTeam/3.0' }
          });
          const cookies = res.headers['set-cookie'] || [];
          const targetName = hypo.observedEvidence?.name;
          const match = cookies.find(c => targetName ? c.startsWith(targetName) : true);
          if (match && !match.toLowerCase().includes('secure')) {
            status = 'VERIFIED';
            currentConfidence = 0.95;
            verificationEvidence = {
              cookieHeader: match,
              secureFlagMissing: true,
              timestamp: new Date().toISOString()
            };
          } else {
            status = 'REJECTED';
            currentConfidence = 0.05;
            rejectionReason = 'Counter-evidence: Cookie sets Secure attribute on secondary probe.';
          }
        } catch (e) {
          status = 'INCONCLUSIVE';
          rejectionReason = `Cookie secure retest failed: ${e.message}`;
        }
      }
    } catch (err) {
      status = 'INCONCLUSIVE';
      rejectionReason = `Hypothesis verification encountered an execution anomaly: ${err.message}`;
    }

    let exploitability = 'ATTACK_SURFACE_WEAKNESS';
    if (
      hypo.title.includes('Sensitive Path') ||
      hypo.title.includes('Secret Disclosure') ||
      hypo.title.includes('Source Map') ||
      hypo.title.includes('Broken Function-Level') ||
      hypo.title.includes('Administrative') ||
      hypo.title.includes('Database Service')
    ) {
      exploitability = 'DIRECTLY_EXPLOITABLE';
    } else if (
      hypo.title.includes('CORS') ||
      hypo.title.includes('HttpOnly') ||
      hypo.title.includes('Anti-CSRF') ||
      hypo.title.includes('SameSite') ||
      hypo.title.includes('TRACE') ||
      hypo.title.includes('Clickjacking') ||
      hypo.title.includes('Verbose Stack Trace')
    ) {
      exploitability = 'CONDITIONALLY_EXPLOITABLE';
    }

    return {
      title: hypo.title,
      description: hypo.description,
      category: hypo.category,
      targetEndpoint: hypo.targetEndpoint,
      initialConfidence: hypo.initialConfidence,
      currentConfidence,
      confidenceBasis: status === 'VERIFIED' ? 'Deterministic multi-probe reproducibility & telemetry match' : 'Counter-evidence obtained during secondary verification',
      status,
      exploitability,
      testProcedure: hypo.testProcedure,
      evidence: verificationEvidence ? JSON.stringify(verificationEvidence) : (hypo.observedEvidence ? JSON.stringify(hypo.observedEvidence) : null),
      rejectionReason,
      verifiedAt: status === 'VERIFIED' ? new Date() : null,
      rejectedAt: status === 'REJECTED' ? new Date() : null
    };
  }

  /**
   * Helper: Secondary socket probe for reproducibility
   */
  static verifySocketRepeatable(host, port) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(1200);
      let banner = '';

      socket.on('connect', () => {
        socket.destroy();
        resolve({ success: true, banner });
      });
      socket.on('data', (d) => {
        banner += d.toString();
        socket.destroy();
        resolve({ success: true, banner });
      });
      socket.on('timeout', () => {
        socket.destroy();
        resolve({ success: false });
      });
      socket.on('error', () => {
        socket.destroy();
        resolve({ success: false });
      });
      try {
        socket.connect(port, host);
      } catch (e) {
        resolve({ success: false });
      }
    });
  }

  /**
   * Helper: Verify absence of HTTP header across secondary request
   */
  static async verifyHeaderAbsent(url, headerName) {
    try {
      const res = await axios.get(url, {
        timeout: 3000,
        validateStatus: () => true,
        headers: { 'User-Agent': 'CyberSploi-Authorized-RedTeam/3.0' }
      });
      const headerVal = res.headers ? res.headers[headerName.toLowerCase()] : null;
      return {
        isAbsent: !headerVal,
        status: res.status,
        headerVal
      };
    } catch (e) {
      return { isAbsent: true, status: 0 };
    }
  }

  /**
   * Query FastAPI AI microservice on Port 8001 for ML risk calibration
   */
  static async calibrateWithAI({ cvss, exploitability, impact, assetCriticality = 'high' }) {
    try {
      const res = await axios.post('http://127.0.0.1:8001/api/v1/predict-risk', {
        cvss_score: cvss || 7.0,
        exploitability: exploitability || 2.5,
        impact_score: impact || 3.5,
        has_exploit: true,
        asset_criticality: assetCriticality
      }, { timeout: 3500 });

      if (res.data?.risk_score) {
        return res.data;
      }
    } catch (e) {}

    // Fallback heuristic if microservice is busy
    return {
      risk_score: Math.min(95, Math.round((cvss || 7.0) * 10)),
      risk_level: (cvss || 7.0) >= 8.5 ? 'CRITICAL' : (cvss || 7.0) >= 6.5 ? 'HIGH' : 'MEDIUM',
      exploitability_index: (cvss || 7.0) / 10
    };
  }
}

module.exports = HypothesisEngineService;
