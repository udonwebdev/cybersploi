/**
 * Authentication & Authorization Boundary Analysis Service
 * Evaluates the identity lifecycle, session creation, cookie attributes (HttpOnly, Secure, SameSite),
 * function-level authorization boundaries, and unauthenticated privileged route access.
 * Maintains non-destructive, authorized testing constraints.
 */

const axios = require('axios');
const SafetyPolicyService = require('./safety-policy.service');

class AuthAnalysisService {
  /**
   * Conduct deep authentication & authorization surface analysis
   */
  static async analyzeIdentitySurfaces(baseUrl, scope, existingAppMap) {
    const findings = [];
    const hypotheses = [];
    const authModel = {
      lifecycleStates: ['UNAUTHENTICATED'],
      discoveredAuthEndpoints: [],
      cookieSecurity: [],
      privilegeBoundariesTested: [],
      summary: 'Identity lifecycle perimeter analyzed.'
    };

    if (!baseUrl) return { authModel, findings, hypotheses };

    // Common authentication and identity endpoints to inspect within scope
    const authCandidateRoutes = [
      { path: '/api/v1/auth/login', type: 'LOGIN', expectedAuth: false },
      { path: '/login', type: 'LOGIN', expectedAuth: false },
      { path: '/api/v1/auth/register', type: 'REGISTRATION', expectedAuth: false },
      { path: '/register', type: 'REGISTRATION', expectedAuth: false },
      { path: '/api/v1/auth/refresh', type: 'TOKEN_REFRESH', expectedAuth: false },
      { path: '/api/v1/users/me', type: 'AUTHENTICATED_PROFILE', expectedAuth: true },
      { path: '/api/v1/admin/users', type: 'PRIVILEGED_ADMIN', expectedAuth: true },
      { path: '/admin', type: 'ADMIN_PANEL', expectedAuth: true }
    ];

    for (const route of authCandidateRoutes) {
      const fullUrl = `${baseUrl}${route.path}`;
      const safetyCheck = SafetyPolicyService.validateAction({
        target: fullUrl,
        path: route.path,
        method: 'GET'
      }, scope);

      if (!safetyCheck.allowed) continue;

      try {
        const response = await axios.get(fullUrl, {
          timeout: 2500,
          validateStatus: () => true,
          headers: {
            'User-Agent': 'CyberSploi-Authorized-RedTeam/3.0 (Identity-Analysis)',
            'Accept': 'application/json, text/html'
          },
          maxRedirects: 2
        });

        const status = response.status;
        const setCookieHeaders = response.headers['set-cookie'] || [];

        authModel.discoveredAuthEndpoints.push({
          path: route.path,
          type: route.type,
          statusCode: status,
          expectedAuthRequired: route.expectedAuth
        });

        // 1. Check Cookie Attributes
        if (setCookieHeaders.length > 0) {
          setCookieHeaders.forEach((cookieStr) => {
            const isHttpOnly = cookieStr.toLowerCase().includes('httponly');
            const isSecure = cookieStr.toLowerCase().includes('secure');
            const hasSameSite = cookieStr.toLowerCase().includes('samesite');

            authModel.cookieSecurity.push({
              cookie: cookieStr.split(';')[0],
              isHttpOnly,
              isSecure,
              hasSameSite
            });

            if (!isHttpOnly) {
              hypotheses.push({
                title: 'Session Cookie Lacks HttpOnly Attribute',
                description: `Cookie '${cookieStr.split('=')[0]}' is set without the HttpOnly flag, allowing client-side scripts to read session credentials if an XSS vulnerability exists.`,
                category: 'auth_boundary',
                targetEndpoint: fullUrl,
                initialConfidence: 0.92,
                testProcedure: 'Inspect Set-Cookie response header from authentication endpoint for absence of HttpOnly directive.',
                observedEvidence: { cookie: cookieStr.split(';')[0], rawHeader: cookieStr }
              });
            }

            if (!isSecure && (baseUrl.startsWith('https') || scope.allowedPorts.includes(443))) {
              hypotheses.push({
                title: 'Session Cookie Missing Secure Flag over HTTPS',
                description: `Cookie '${cookieStr.split('=')[0]}' lacks the Secure flag, making it transmissible over unencrypted plaintext HTTP connections.`,
                category: 'auth_boundary',
                targetEndpoint: fullUrl,
                initialConfidence: 0.9,
                testProcedure: 'Inspect Set-Cookie response header for absence of Secure flag.',
                observedEvidence: { cookie: cookieStr.split(';')[0] }
              });
            }
          });
        }

        // 2. Authorization Boundary Check (Function-Level Access Control)
        // If a privileged admin endpoint returns 200 without credentials, it is a critical access control failure.
        if (route.expectedAuth && (status === 200 || status === 204)) {
          const bodyStr = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
          // Distinguish genuine authorization bypass from static landing page or generic 200 response
          const isPrivilegedData = bodyStr.includes('admin') || bodyStr.includes('users') || bodyStr.includes('role') || bodyStr.includes('organization');
          
          if (isPrivilegedData) {
            hypotheses.push({
              title: `Broken Function-Level Authorization on ${route.path}`,
              description: `Endpoint ${route.path} intended for privileged users returned HTTP ${status} and sensitive state without requiring authentication credentials.`,
              category: 'auth_boundary',
              targetEndpoint: fullUrl,
              initialConfidence: 0.95,
              testProcedure: `Send unauthenticated HTTP GET to ${route.path} and verify if administrative resources are returned.`,
              observedEvidence: { path: route.path, status, preview: bodyStr.substring(0, 150) }
            });
          }
        } else if (route.expectedAuth && (status === 401 || status === 403)) {
          authModel.privilegeBoundariesTested.push({
            path: route.path,
            status: 'PROTECTED',
            httpStatus: status,
            detail: 'Correctly enforced 401/403 unauthenticated boundary'
          });
        }
      } catch (err) {
        // Network timeout or unreachable candidate route
      }
    }

    return { authModel, findings, hypotheses };
  }
}

module.exports = AuthAnalysisService;
