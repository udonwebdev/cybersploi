/**
 * Real Reconnaissance & Application Cartography Engine
 * Performs live DNS queries, TCP socket sweeps, TLS cryptographic handshakes,
 * and HTTP application cartography under strict Scope authorization.
 */

const dns = require('dns').promises;
const net = require('net');
const tls = require('tls');
const axios = require('axios');
const ScopeAuthorizationService = require('./scope-authorization.service');

// Configure authoritative public resolvers for resilience
try {
  dns.setServers(['8.8.8.8', '1.1.1.1']);
} catch (e) {}

class ReconCartographyService {
  /**
   * Probe an individual TCP socket port safely
   */
  static probePort(host, port, timeout = 1200) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let banner = '';
      let isResolved = false;

      const finish = (open) => {
        if (isResolved) return;
        isResolved = true;
        socket.destroy();
        resolve({
          port,
          open,
          service: this.mapPortToServiceName(port),
          banner: banner.trim().substring(0, 200) || null
        });
      };

      socket.setTimeout(timeout);

      socket.on('connect', () => {
        // Send CRLF to trigger server banner grab for standard text protocols (FTP, SSH, SMTP)
        if ([21, 22, 25, 110, 143].includes(port)) {
          socket.write('\r\n');
        } else {
          finish(true);
        }
      });

      socket.on('data', (data) => {
        banner += data.toString('utf8', 0, 200);
        finish(true);
      });

      socket.on('timeout', () => finish(false));
      socket.on('error', () => finish(false));
      socket.on('close', () => {
        if (!isResolved) finish(false);
      });

      try {
        socket.connect(port, host);
      } catch (err) {
        finish(false);
      }
    });
  }

  static mapPortToServiceName(port) {
    const serviceMap = {
      21: 'FTP',
      22: 'SSH',
      23: 'Telnet',
      25: 'SMTP',
      53: 'DNS',
      80: 'HTTP',
      110: 'POP3',
      143: 'IMAP',
      443: 'HTTPS',
      445: 'SMB / NetBIOS',
      993: 'IMAPS',
      995: 'POP3S',
      1433: 'MS-SQL',
      1521: 'Oracle-DB',
      2049: 'NFS',
      2375: 'Docker Unauth Engine',
      3306: 'MySQL',
      3389: 'RDP',
      5000: 'Docker Registry / Flask',
      5432: 'PostgreSQL',
      5900: 'VNC',
      6379: 'Redis In-Memory KeyStore',
      7001: 'WebLogic Console',
      8000: 'HTTP Dev / API',
      8080: 'HTTP Alternate Proxy',
      8443: 'HTTPS Alternate',
      8888: 'Jupyter / Administrative',
      9000: 'SonarQube / Portainer',
      9200: 'Elasticsearch Search Node',
      11211: 'Memcached In-Memory DB',
      27017: 'MongoDB NoSQL Daemon'
    };
    return serviceMap[port] || 'TCP-Service';
  }

  /**
   * Execute full DNS reconnaissance
   */
  static async executeDnsRecon(targetHost, scope) {
    const records = {
      a: [],
      aaaa: [],
      mx: [],
      txt: [],
      ns: [],
      cname: []
    };
    const outOfScopeDiscoveries = [];

    // If host is direct IP, skip DNS lookups
    if (net.isIP(targetHost)) {
      records.a = [targetHost];
      return { records, outOfScopeDiscoveries };
    }

    try {
      records.a = await dns.resolve4(targetHost).catch(() => []);
    } catch (e) {}

    try {
      records.aaaa = await dns.resolve6(targetHost).catch(() => []);
    } catch (e) {}

    try {
      const mx = await dns.resolveMx(targetHost).catch(() => []);
      records.mx = mx.map(m => ({ exchange: m.exchange, priority: m.priority }));
      // Check if MX records are outside scope
      mx.forEach(m => {
        const check = ScopeAuthorizationService.evaluateHostScope(m.exchange, scope);
        if (check.isOutOfScopeDiscovery) {
          outOfScopeDiscoveries.push({
            host: m.exchange,
            type: 'MX_HOST',
            source: targetHost,
            reason: check.reason
          });
        }
      });
    } catch (e) {}

    try {
      const txt = await dns.resolveTxt(targetHost).catch(() => []);
      records.txt = txt.map(chunks => chunks.join(''));
    } catch (e) {}

    try {
      const ns = await dns.resolveNs(targetHost).catch(() => []);
      records.ns = ns;
      ns.forEach(nameserver => {
        const check = ScopeAuthorizationService.evaluateHostScope(nameserver, scope);
        if (check.isOutOfScopeDiscovery) {
          outOfScopeDiscoveries.push({
            host: nameserver,
            type: 'NAME_SERVER',
            source: targetHost,
            reason: check.reason
          });
        }
      });
    } catch (e) {}

    try {
      const cname = await dns.resolveCname(targetHost).catch(() => []);
      records.cname = cname;
      cname.forEach(c => {
        const check = ScopeAuthorizationService.evaluateHostScope(c, scope);
        if (check.isOutOfScopeDiscovery) {
          outOfScopeDiscoveries.push({
            host: c,
            type: 'CNAME_HOST',
            source: targetHost,
            reason: check.reason
          });
        }
      });
    } catch (e) {}

    return { records, outOfScopeDiscoveries };
  }

  /**
   * Execute scope-checked TCP socket port sweep
   */
  static async executePortSweep(host, scope) {
    const portsToScan = scope.allowedPorts;
    const concurrency = Math.min(scope.concurrencyLimit || 5, 8);
    const results = [];

    for (let i = 0; i < portsToScan.length; i += concurrency) {
      const chunk = portsToScan.slice(i, i + concurrency);
      const chunkResults = await Promise.all(
        chunk.map(async (port) => {
          const probeCheck = ScopeAuthorizationService.validateProbe({ host, port, protocol: 'tcp' }, scope);
          if (!probeCheck.allowed) {
            return { port, open: false, skipped: true, reason: probeCheck.reason };
          }
          return this.probePort(host, port);
        })
      );
      results.push(...chunkResults);
    }

    const openPorts = results.filter(r => r.open);
    const closedPorts = results.filter(r => !r.open && !r.skipped);
    const skippedPorts = results.filter(r => r.skipped);

    return {
      openPorts,
      closedCount: closedPorts.length,
      skippedCount: skippedPorts.length,
      totalProbed: results.length
    };
  }

  /**
   * Deep TLS Handshake & Cipher Inspection
   */
  static async executeTlsAnalysis(host, port = 443, scope) {
    const probeCheck = ScopeAuthorizationService.validateProbe({ host, port, protocol: 'https' }, scope);
    if (!probeCheck.allowed) {
      return { supported: false, reason: probeCheck.reason };
    }

    return new Promise((resolve) => {
      const socket = tls.connect({
        host,
        port,
        servername: host,
        rejectUnauthorized: false,
        timeout: 4000
      }, () => {
        try {
          const cert = socket.getPeerCertificate(true);
          const cipher = socket.getCipher();
          const protocol = socket.getProtocol();

          const validFrom = cert?.valid_from ? new Date(cert.valid_from) : null;
          const validTo = cert?.valid_to ? new Date(cert.valid_to) : null;
          const now = new Date();
          const daysRemaining = validTo ? Math.round((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)) : null;

          const sans = cert?.subjectaltname
            ? cert.subjectaltname.split(',').map(s => s.trim().replace(/^DNS:/i, ''))
            : [];

          socket.destroy();

          resolve({
            supported: true,
            protocol,
            cipher: cipher?.name,
            cipherVersion: cipher?.version,
            subject: cert?.subject?.CN || cert?.subject?.O,
            issuer: cert?.issuer?.O || cert?.issuer?.CN,
            validFrom: cert?.valid_from,
            validTo: cert?.valid_to,
            daysRemaining,
            isExpired: daysRemaining !== null && daysRemaining <= 0,
            isExpiringSoon: daysRemaining !== null && daysRemaining > 0 && daysRemaining <= 30,
            sans,
            serialNumber: cert?.serialNumber
          });
        } catch (err) {
          socket.destroy();
          resolve({ supported: false, error: err.message });
        }
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve({ supported: false, error: 'TLS handshake timed out' });
      });

      socket.on('error', (err) => {
        socket.destroy();
        resolve({ supported: false, error: err.message });
      });
    });
  }

  /**
   * Deep Application Cartography: Web Headers, Methods, Routes, Auth Boundaries & Spider
   */
  static async executeApplicationMapping(host, openWebPorts, scope) {
    const webPort = openWebPorts.includes(443) ? 443 : openWebPorts.includes(80) ? 80 : (openWebPorts[0] || 443);
    const protocol = webPort === 443 || webPort === 8443 ? 'https' : 'http';
    const baseUrl = `${protocol}://${host}:${webPort === 80 || webPort === 443 ? '' : webPort}`.replace(/:$/, '');

    const mapping = {
      baseUrl,
      webServer: null,
      statusCode: null,
      headers: {},
      securityHeaders: {
        hsts: false,
        csp: false,
        xFrameOptions: false,
        xContentTypeOptions: false,
        referrerPolicy: false,
        permissionsPolicy: false
      },
      cors: {
        configured: false,
        allowOrigin: null,
        allowCredentials: false,
        isWildcardWithCredentials: false,
        isReflectiveOrigin: false
      },
      techStack: {
        server: null,
        frameworks: [],
        frontend: [],
        cdn: null,
        detectedHeaders: []
      },
      allowedMethods: [],
      methodAudit: {
        traceEnabled: false,
        putEnabled: false,
        deleteEnabled: false,
        unusualMethods: []
      },
      discoveredEndpoints: [],
      crawledPages: [],
      discoveredForms: [],
      discoveredApiRoutes: [],
      authEndpoints: [],
      sensitiveDisclosures: [],
      suspectedDisclosures: [],
      diagnosticErrorLeaks: []
    };

    let initialHtml = '';

    // 1. Primary Ingress GET Request
    try {
      const res = await axios.get(baseUrl, {
        timeout: 4000,
        validateStatus: () => true,
        headers: {
          'User-Agent': 'CyberSploi-Authorized-RedTeam/3.0 (Security Audit & Spider)',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
      });

      mapping.statusCode = res.status;
      mapping.headers = res.headers || {};
      mapping.webServer = res.headers['server'] || res.headers['x-powered-by'] || null;
      initialHtml = typeof res.data === 'string' ? res.data : JSON.stringify(res.data || '');

      // Security Headers Audit
      mapping.securityHeaders.hsts = !!res.headers['strict-transport-security'];
      mapping.securityHeaders.csp = !!res.headers['content-security-policy'];
      mapping.securityHeaders.xFrameOptions = !!res.headers['x-frame-options'];
      mapping.securityHeaders.xContentTypeOptions = !!res.headers['x-content-type-options'];
      mapping.securityHeaders.referrerPolicy = !!res.headers['referrer-policy'];
      mapping.securityHeaders.permissionsPolicy = !!res.headers['permissions-policy'];

      // Cookie Hygiene Extraction
      const rawCookies = res.headers['set-cookie'] || [];
      mapping.cookies = rawCookies.map(c => {
        const parts = c.split(';').map(p => p.trim());
        const [name, val] = parts[0].split('=');
        const isHttpOnly = parts.some(p => p.toLowerCase() === 'httponly');
        const isSecure = parts.some(p => p.toLowerCase() === 'secure');
        const sameSitePart = parts.find(p => p.toLowerCase().startsWith('samesite='));
        const sameSite = sameSitePart ? sameSitePart.split('=')[1] : null;
        return { name: name || 'cookie', isHttpOnly, isSecure, sameSite, raw: c };
      });

      // Technology Stack Fingerprinting
      mapping.techStack = this.detectTechnologyStack(res.headers, initialHtml, res.headers['set-cookie'] || []);
    } catch (e) {
      mapping.error = e.message;
    }

    // 2. HTTP Methods Probe (OPTIONS, TRACE, PUT, DELETE)
    try {
      const optionsRes = await axios({
        method: 'OPTIONS',
        url: baseUrl,
        timeout: 3000,
        validateStatus: () => true
      });
      const allow = optionsRes.headers['allow'] || optionsRes.headers['access-control-allow-methods'];
      if (allow) {
        mapping.allowedMethods = allow.split(',').map(m => m.trim().toUpperCase());
      }
    } catch (e) {}

    // Audit Insecure Verbs (TRACE for XST, PUT/DELETE)
    try {
      const traceRes = await axios({
        method: 'TRACE',
        url: baseUrl,
        timeout: 2500,
        validateStatus: () => true,
        headers: { 'X-Audit-Token': 'CyberSploi-Trace-Check' }
      }).catch(() => null);

      if (traceRes && traceRes.status === 200 && typeof traceRes.data === 'string' && traceRes.data.includes('CyberSploi-Trace-Check')) {
        mapping.methodAudit.traceEnabled = true;
      }
    } catch (e) {}

    // 3. CORS Probe with External Origin
    try {
      const corsRes = await axios.get(baseUrl, {
        timeout: 3000,
        validateStatus: () => true,
        headers: {
          'Origin': 'https://adversary-audit.test',
          'User-Agent': 'CyberSploi-Authorized-RedTeam/3.0'
        }
      });
      const acao = corsRes.headers['access-control-allow-origin'];
      const acac = corsRes.headers['access-control-allow-credentials'];

      if (acao) {
        mapping.cors.configured = true;
        mapping.cors.allowOrigin = acao;
        mapping.cors.allowCredentials = acac === 'true';
        if (acao === '*' && mapping.cors.allowCredentials) {
          mapping.cors.isWildcardWithCredentials = true;
        }
        if (acao === 'https://adversary-audit.test') {
          mapping.cors.isReflectiveOrigin = true;
        }
      }
    } catch (e) {}

    // 4. Recursive Web Crawler & Spider (Discovers internal links, forms, scripts, inline APIs)
    if (initialHtml) {
      await this.crawlAndSpider(baseUrl, initialHtml, scope, mapping);
    }

    // 5. Scope-Checked Route & Sensitive Path Probes (Expanded 50+ enterprise dictionary)
    const sensitivePaths = [
      '/.env',
      '/.env.local',
      '/.env.production',
      '/.git/HEAD',
      '/.git/config',
      '/.svn/entries',
      '/config.json',
      '/web.config',
      '/appsettings.json',
      '/Dockerfile',
      '/docker-compose.yml',
      '/dump.sql',
      '/backup.sql',
      '/db.sqlite3',
      '/robots.txt',
      '/sitemap.xml',
      '/security.txt',
      '/.well-known/security.txt',
      '/swagger.json',
      '/openapi.json',
      '/api-docs',
      '/v2/api-docs',
      '/swagger-ui.html',
      '/swagger-ui/',
      '/graphql',
      '/graphiql',
      '/actuator/health',
      '/actuator/env',
      '/actuator/beans',
      '/metrics',
      '/prometheus',
      '/server-status',
      '/server-info',
      '/phpinfo.php',
      '/phpmyadmin/',
      '/admin',
      '/administrator',
      '/admin/login',
      '/console',
      '/dashboard',
      '/manager/html',
      '/.well-known/openid-configuration',
      '/.well-known/jwks.json',
      '/healthz',
      '/api/health',
      '/api/v1/health',
      '/v1/models',
      '/actuator/info',
      '/package.json',
      '/composer.json'
    ];

    for (const path of sensitivePaths) {
      const pathCheck = ScopeAuthorizationService.evaluatePathScope(path, scope);
      if (!pathCheck.allowed) continue;

      try {
        const probeRes = await axios.get(`${baseUrl}${path}`, {
          timeout: 2200,
          validateStatus: () => true,
          headers: { 'User-Agent': 'CyberSploi-Authorized-RedTeam/3.0' },
          maxRedirects: 2
        });

        if (probeRes.status === 200 && probeRes.data) {
          const bodyStr = typeof probeRes.data === 'string' ? probeRes.data : JSON.stringify(probeRes.data);
          
          let isAuthentic = false;
          let disclosureType = 'information_disclosure';

          if (path.includes('.git') && bodyStr.includes('ref: refs/')) {
            isAuthentic = true;
            disclosureType = 'exposed_git_repository';
          } else if (path.includes('.env') && (bodyStr.includes('DB_PASSWORD') || bodyStr.includes('APP_KEY') || bodyStr.includes('SECRET='))) {
            isAuthentic = true;
            disclosureType = 'exposed_environment_secrets';
          } else if ((path.includes('swagger') || path.includes('openapi')) && (bodyStr.includes('"openapi"') || bodyStr.includes('"swagger"'))) {
            isAuthentic = true;
            disclosureType = 'exposed_api_schema';
          } else if (path.includes('actuator/health') && bodyStr.includes('"status"')) {
            isAuthentic = true;
            disclosureType = 'spring_actuator_exposed';
          } else if (path === '/robots.txt' && bodyStr.includes('User-agent:')) {
            isAuthentic = true;
            disclosureType = 'robots_file';
          } else if (path.includes('phpinfo') && bodyStr.includes('PHP Version')) {
            isAuthentic = true;
            disclosureType = 'exposed_phpinfo';
          } else if (path.includes('.sql') && (bodyStr.includes('INSERT INTO') || bodyStr.includes('CREATE TABLE'))) {
            isAuthentic = true;
            disclosureType = 'database_dump_leak';
          } else if (path.includes('openid-configuration') && (bodyStr.includes('"issuer"') || bodyStr.includes('"authorization_endpoint"'))) {
            isAuthentic = true;
            disclosureType = 'exposed_oauth_metadata';
          } else if (path.includes('jwks.json') && bodyStr.includes('"keys"')) {
            isAuthentic = true;
            disclosureType = 'exposed_jwks_keys';
          } else if ((path === '/package.json' || path === '/composer.json') && (bodyStr.includes('"dependencies"') || bodyStr.includes('"require"'))) {
            isAuthentic = true;
            disclosureType = 'exposed_manifest_dependencies';
          }

          if (isAuthentic) {
            mapping.discoveredEndpoints.push({
              path,
              statusCode: probeRes.status,
              type: disclosureType,
              snippet: bodyStr.substring(0, 150)
            });
            if (['exposed_git_repository', 'exposed_environment_secrets', 'spring_actuator_exposed', 'database_dump_leak', 'exposed_phpinfo', 'exposed_oauth_metadata', 'exposed_jwks_keys', 'exposed_manifest_dependencies'].includes(disclosureType)) {
              mapping.sensitiveDisclosures.push({
                path,
                type: disclosureType,
                statusCode: probeRes.status,
                evidence: bodyStr.substring(0, 200)
              });
            }
          } else {
            // Returned 200 OK on sensitive path without authentic signatures (Candidate hypothesis for false-positive filtering)
            mapping.suspectedDisclosures.push({
              path,
              statusCode: probeRes.status,
              snippet: bodyStr.substring(0, 150)
            });
          }
        }
      } catch (e) {}
    }

    // 6. Authentication Endpoint Probing
    const authCandidatePaths = ['/login', '/auth/login', '/signin', '/admin', '/api/v1/auth/login', '/oauth/token', '/user/login'];
    for (const authPath of authCandidatePaths) {
      const pathCheck = ScopeAuthorizationService.evaluatePathScope(authPath, scope);
      if (!pathCheck.allowed) continue;

      try {
        const authRes = await axios.get(`${baseUrl}${authPath}`, {
          timeout: 2200,
          validateStatus: () => true,
          headers: { 'User-Agent': 'CyberSploi-Authorized-RedTeam/3.0' }
        });
        if (authRes.status < 400 || authRes.status === 401 || authRes.status === 403) {
          mapping.authEndpoints.push({
            path: authPath,
            statusCode: authRes.status,
            requiresAuth: authRes.status === 401 || authRes.status === 403
          });
        }
      } catch (e) {}
    }

    // 7. Verbose Error & Diagnostic Leakage Probing
    try {
      const errProbeRes = await axios.get(`${baseUrl}/?cybersploi_err_test=%27%22%3E%3C%00`, {
        timeout: 2500,
        validateStatus: () => true,
        headers: { 'User-Agent': 'CyberSploi-Authorized-RedTeam/3.0' }
      });
      if (errProbeRes.data) {
        const errBody = typeof errProbeRes.data === 'string' ? errProbeRes.data : JSON.stringify(errProbeRes.data);
        const stackTraceKeywords = ['Traceback (most recent call last)', 'NullPointerException', 'at Function.', 'at Object.', 'TypeError:', 'Fatal error:', 'ORA-', 'pg_query', 'mysql_fetch', 'SQL syntax'];
        const matchedKeyword = stackTraceKeywords.find(k => errBody.includes(k));
        if (matchedKeyword) {
          mapping.diagnosticErrorLeaks.push({
            type: 'verbose_stack_trace_disclosure',
            marker: matchedKeyword,
            statusCode: errProbeRes.status,
            snippet: errBody.substring(0, 200)
          });
        }
      }
    } catch (e) {}

    return mapping;
  }

  /**
   * Helper: Technology Stack Identification
   */
  static detectTechnologyStack(headers = {}, html = '', cookies = []) {
    const tech = {
      server: headers['server'] || null,
      frameworks: [],
      frontend: [],
      cdn: null,
      detectedHeaders: Object.keys(headers)
    };

    const serverLower = (headers['server'] || '').toLowerCase();
    const poweredBy = (headers['x-powered-by'] || '').toLowerCase();
    const cookieStr = cookies.join('; ').toLowerCase();

    // Server Detection
    if (serverLower.includes('nginx')) tech.server = 'Nginx';
    else if (serverLower.includes('apache')) tech.server = 'Apache HTTPD';
    else if (serverLower.includes('caddy')) tech.server = 'Caddy';
    else if (serverLower.includes('cloudflare')) tech.server = 'Cloudflare Edge';
    else if (serverLower.includes('microsoft-iis')) tech.server = 'Microsoft-IIS';
    else if (serverLower.includes('litespeed')) tech.server = 'LiteSpeed';

    // Backend Frameworks & Languages
    if (poweredBy.includes('express') || cookieStr.includes('connect.sid')) tech.frameworks.push('Express / Node.js');
    if (poweredBy.includes('next.js') || html.includes('__NEXT_DATA__') || html.includes('/_next/')) tech.frameworks.push('Next.js');
    if (poweredBy.includes('php') || cookieStr.includes('phpsessid')) tech.frameworks.push('PHP');
    if (poweredBy.includes('asp.net') || cookieStr.includes('asp.net_sessionid') || headers['x-aspnet-version']) tech.frameworks.push('ASP.NET');
    if (cookieStr.includes('csrftoken') || html.includes('csrfmiddlewaretoken')) tech.frameworks.push('Django / Python');
    if (cookieStr.includes('laravel_session')) tech.frameworks.push('Laravel / PHP');
    if (cookieStr.includes('jsessionid')) tech.frameworks.push('Java / Spring Boot');

    // Frontend Libraries
    if (html.includes('react') || html.includes('data-reactroot') || html.includes('_reactRootContainer')) tech.frontend.push('React');
    if (html.includes('vue') || html.includes('data-v-')) tech.frontend.push('Vue.js');
    if (html.includes('ng-version') || html.includes('ng-app')) tech.frontend.push('Angular');
    if (html.includes('jquery')) tech.frontend.push('jQuery');
    if (html.includes('tailwindcss') || html.includes('tailwind')) tech.frontend.push('Tailwind CSS');
    if (html.includes('bootstrap')) tech.frontend.push('Bootstrap');

    // CDN / Proxy
    if (headers['cf-ray'] || headers['cf-cache-status'] || serverLower.includes('cloudflare')) tech.cdn = 'Cloudflare';
    else if (headers['x-amz-cf-id'] || headers['x-amzn-requestid']) tech.cdn = 'Amazon CloudFront';
    else if (headers['x-fastly-request-id']) tech.cdn = 'Fastly';
    else if (headers['x-vercel-id']) tech.cdn = 'Vercel Edge Network';

    return tech;
  }

  /**
   * Helper: Recursive Web Crawler & Asset Spider
   */
  static async crawlAndSpider(baseUrl, html, scope, mapping, maxPages = 10) {
    const visited = new Set();
    const queue = [];

    // Parse initial links
    const linkRegex = /<a\s+(?:[^>]*?\s+)?href=["']([^"'#]+)["']/gi;
    let match;
    while ((match = linkRegex.exec(html)) !== null) {
      const rawHref = match[1].trim();
      if (rawHref && !rawHref.startsWith('javascript:') && !rawHref.startsWith('mailto:') && !rawHref.startsWith('tel:')) {
        queue.push(rawHref);
      }
    }

    // Parse script tags and search for API routes
    const scriptRegex = /<script\s+(?:[^>]*?\s+)?src=["']([^"']+)["']/gi;
    const scriptUrls = [];
    while ((match = scriptRegex.exec(html)) !== null) {
      scriptUrls.push(match[1].trim());
    }

    // Inspect script bundles for inline API endpoints and production source maps
    for (const scriptUrl of scriptUrls.slice(0, 5)) {
      try {
        const fullScriptUrl = scriptUrl.startsWith('http') ? scriptUrl : `${baseUrl}/${scriptUrl.replace(/^\//, '')}`;
        const scriptRes = await axios.get(fullScriptUrl, {
          timeout: 2000,
          validateStatus: () => true,
          headers: { 'User-Agent': 'CyberSploi-Authorized-RedTeam/3.0' }
        });
        if (scriptRes.data && typeof scriptRes.data === 'string') {
          const apiMatches = scriptRes.data.match(/\/api\/[a-zA-Z0-9_\-\/]+/g) || [];
          apiMatches.slice(0, 5).forEach(api => {
            if (!mapping.discoveredApiRoutes.includes(api)) {
              mapping.discoveredApiRoutes.push(api);
              mapping.discoveredEndpoints.push({
                path: api,
                statusCode: 200,
                type: 'discovered_api_route',
                snippet: `Extracted from client-side script bundle: ${scriptUrl}`
              });
            }
          });
        }

        // Check for accompanying source map file
        const cleanScript = fullScriptUrl.split('?')[0];
        const mapUrl = `${cleanScript}.map`;
        const mapRes = await axios.get(mapUrl, {
          timeout: 1500,
          validateStatus: () => true,
          headers: { 'User-Agent': 'CyberSploi-Authorized-RedTeam/3.0' }
        }).catch(() => null);

        if (mapRes && mapRes.status === 200 && mapRes.data && (typeof mapRes.data === 'object' || (typeof mapRes.data === 'string' && mapRes.data.includes('"version":')))) {
          const mapPath = mapUrl.replace(baseUrl, '');
          if (!mapping.discoveredEndpoints.some(e => e.path === mapPath)) {
            mapping.discoveredEndpoints.push({
              path: mapPath,
              statusCode: 200,
              type: 'exposed_source_map',
              snippet: `Production source map disclosed: ${mapPath}`
            });
            mapping.sensitiveDisclosures.push({
              path: mapPath,
              type: 'exposed_source_map',
              statusCode: 200,
              evidence: typeof mapRes.data === 'string' ? mapRes.data.substring(0, 150) : JSON.stringify(mapRes.data).substring(0, 150)
            });
          }
        }
      } catch (e) {}
    }

    // Parse forms helper
    const extractFormsFromHtml = (contentHtml) => {
      const formRegex = /<form([\s\S]*?)>([\s\S]*?)<\/form>/gi;
      let formMatch;
      while ((formMatch = formRegex.exec(contentHtml)) !== null) {
        const formAttributes = formMatch[1] || '';
        const formInner = formMatch[2] || '';

        const actionMatch = formAttributes.match(/action=["']([^"']*)["']/i);
        const methodMatch = formAttributes.match(/method=["']([^"']*)["']/i);

        const formAction = actionMatch ? actionMatch[1] : '/';
        const formMethod = methodMatch ? methodMatch[1].toUpperCase() : 'GET';

        const inputNames = [];
        const inputRegex = /<input[^>]*?\sname=["']([^"']+)["']/gi;
        let inMatch;
        while ((inMatch = inputRegex.exec(formInner)) !== null) {
          inputNames.push(inMatch[1]);
        }
        const hasCsrf = inputNames.some(inp => {
          const lower = inp.toLowerCase();
          return lower.includes('csrf') || lower.includes('token') || lower.includes('authenticity');
        });

        if (!mapping.discoveredForms.some(f => f.action === formAction && f.method === formMethod)) {
          mapping.discoveredForms.push({
            action: formAction,
            method: formMethod,
            inputs: inputNames,
            hasCsrfProtection: hasCsrf
          });
        }
      }
    };

    extractFormsFromHtml(html);

    // Crawl unique internal paths within scope
    while (queue.length > 0 && visited.size < maxPages) {
      const rawPath = queue.shift();
      let normalizedPath = rawPath;
      if (rawPath.startsWith('http')) {
        try {
          const urlObj = new URL(rawPath);
          normalizedPath = urlObj.pathname + urlObj.search;
        } catch (e) {
          continue;
        }
      }
      if (!normalizedPath.startsWith('/')) normalizedPath = `/${normalizedPath}`;
      if (visited.has(normalizedPath)) continue;
      visited.add(normalizedPath);

      const pathCheck = ScopeAuthorizationService.evaluatePathScope(normalizedPath, scope);
      if (!pathCheck.allowed) continue;

      try {
        const crawlRes = await axios.get(`${baseUrl}${normalizedPath}`, {
          timeout: 2000,
          validateStatus: () => true,
          headers: { 'User-Agent': 'CyberSploi-Authorized-RedTeam/3.0 (Crawler)' }
        });
        const crawlData = crawlRes.data;
        mapping.crawledPages.push({
          path: normalizedPath,
          statusCode: crawlRes.status,
          contentType: crawlRes.headers['content-type'] || 'unknown',
          title: (crawlData && typeof crawlData === 'string') ? (crawlData.match(/<title>([^<]+)<\/title>/i)?.[1] || null) : null
        });

        if (typeof crawlData === 'string') {
          extractFormsFromHtml(crawlData);
        }
      } catch (e) {}
    }
  }
}

module.exports = ReconCartographyService;
