/**
 * Scope & Authorization Engine
 * Enforces strict boundary rules before any network probe, socket connection, or HTTP request.
 * Discovered out-of-scope assets are recorded as OUT_OF_SCOPE_DISCOVERY and never probed.
 */

const net = require('net');

class ScopeAuthorizationService {
  /**
   * Normalizes a target string into a clean hostname or IP
   */
  static cleanHost(target) {
    if (!target) return 'localhost';
    let host = target.trim();
    host = host.replace(/^https?:\/\//i, '');
    host = host.split('/')[0];
    host = host.split(':')[0];
    return host.toLowerCase();
  }

  /**
   * Parse scope configuration from DB or input object
   */
  static parseScope(scopeData, target) {
    const defaultHost = this.cleanHost(target);
    
    let allowedDomains = [defaultHost];
    let allowedSubdomains = [defaultHost];
    let allowedIps = [];
    let allowedPorts = [
      20, 21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 636,
      873, 993, 995, 1433, 1521, 2049, 2375, 2376, 3000, 3306, 3389, 4848, 5000, 5432, 5601,
      5900, 5984, 5985, 5986, 6379, 6443, 7000, 7001, 8000, 8008, 8080, 8081, 8443, 8500,
      8888, 9000, 9001, 9042, 9090, 9200, 9300, 9443, 9999, 10000, 10250, 10255, 11211,
      15672, 27017, 50000
    ];
    let allowedProtocols = ['http', 'https', 'tcp', 'dns'];
    let allowedPaths = ['/'];
    let excludedAssets = [];
    let excludedPaths = [];
    let timeBudgetMinutes = 30;
    let concurrencyLimit = 5;
    let destructiveTesting = false;
    let credentialTesting = false;
    let dataAccessPolicy = 'metadata_only';
    let persistencePolicy = 'strictly_prohibited';
    let environment = 'production_authorized';

    if (scopeData) {
      if (typeof scopeData === 'string') {
        try {
          scopeData = JSON.parse(scopeData);
        } catch (e) {
          scopeData = {};
        }
      }

      const parseArr = (val, def) => {
        if (!val) return def;
        if (Array.isArray(val)) return val;
        try {
          const parsed = JSON.parse(val);
          return Array.isArray(parsed) ? parsed : def;
        } catch (e) {
          return def;
        }
      };

      if (scopeData.allowedDomains) allowedDomains = parseArr(scopeData.allowedDomains, allowedDomains);
      if (scopeData.allowedSubdomains) allowedSubdomains = parseArr(scopeData.allowedSubdomains, allowedSubdomains);
      if (scopeData.allowedIps) allowedIps = parseArr(scopeData.allowedIps, allowedIps);
      if (scopeData.allowedPorts) allowedPorts = parseArr(scopeData.allowedPorts, allowedPorts);
      if (scopeData.allowedProtocols) allowedProtocols = parseArr(scopeData.allowedProtocols, allowedProtocols);
      if (scopeData.allowedPaths) allowedPaths = parseArr(scopeData.allowedPaths, allowedPaths);
      if (scopeData.excludedAssets) excludedAssets = parseArr(scopeData.excludedAssets, excludedAssets);
      if (scopeData.excludedPaths) excludedPaths = parseArr(scopeData.excludedPaths, excludedPaths);

      if (scopeData.timeBudgetMinutes) timeBudgetMinutes = Number(scopeData.timeBudgetMinutes) || 30;
      if (scopeData.concurrencyLimit) concurrencyLimit = Number(scopeData.concurrencyLimit) || 5;
      if (scopeData.destructiveTesting !== undefined) destructiveTesting = !!scopeData.destructiveTesting;
      if (scopeData.credentialTesting !== undefined) credentialTesting = !!scopeData.credentialTesting;
      if (scopeData.dataAccessPolicy) dataAccessPolicy = scopeData.dataAccessPolicy;
      if (scopeData.persistencePolicy) persistencePolicy = scopeData.persistencePolicy;
      if (scopeData.environment) environment = scopeData.environment;
    }

    // Ensure primary target is always in allowed domains
    if (!allowedDomains.includes(defaultHost)) {
      allowedDomains.push(defaultHost);
    }

    return {
      target: defaultHost,
      allowedDomains: allowedDomains.map(d => d.toLowerCase().trim()),
      allowedSubdomains: allowedSubdomains.map(s => s.toLowerCase().trim()),
      allowedIps: allowedIps.map(ip => ip.trim()),
      allowedPorts: allowedPorts.map(Number).filter(p => !isNaN(p) && p > 0 && p <= 65535),
      allowedProtocols: allowedProtocols.map(p => p.toLowerCase().trim()),
      allowedPaths,
      excludedAssets: excludedAssets.map(a => a.toLowerCase().trim()),
      excludedPaths,
      timeBudgetMinutes,
      concurrencyLimit,
      destructiveTesting,
      credentialTesting,
      dataAccessPolicy,
      persistencePolicy,
      environment,
      _parsed: true
    };
  }

  /**
   * Ensure scope is always parsed and valid
   */
  static ensureScope(rawScope, target) {
    if (rawScope && rawScope._parsed) return rawScope;
    return this.parseScope(rawScope, target);
  }

  /**
   * Evaluates if a given host/IP and port are in-scope
   */
  static evaluateHostScope(host, rawScope) {
    const scope = this.ensureScope(rawScope, host);
    const clean = this.cleanHost(host);

    // 1. Check excluded assets first
    const excludedList = Array.isArray(scope.excludedAssets) ? scope.excludedAssets : [];
    for (const excluded of excludedList) {
      if (clean === excluded || clean.endsWith('.' + excluded)) {
        return {
          allowed: false,
          reason: `Target ${clean} matches excluded asset rule: ${excluded}`,
          isOutOfScopeDiscovery: false
        };
      }
    }

    // 2. Check if it's direct IP match or localhost
    if (clean === 'localhost' || clean === '127.0.0.1') {
      return { allowed: true, reason: 'Local loopback authorization' };
    }

    if (net.isIP(clean)) {
      if (scope.allowedIps.includes(clean)) {
        return { allowed: true, reason: 'Explicitly allowed IP address' };
      }
      if (scope.target === clean) {
        return { allowed: true, reason: 'Primary target IP' };
      }
      return {
        allowed: false,
        reason: `IP ${clean} is not in the authorized IP scope list`,
        isOutOfScopeDiscovery: true
      };
    }

    // 3. Domain and subdomain evaluation
    if (clean === scope.target) {
      return { allowed: true, reason: 'Primary assessment target' };
    }

    if (scope.allowedDomains.includes(clean)) {
      return { allowed: true, reason: 'Explicitly allowed domain' };
    }

    // Check if it's an authorized subdomain of the primary target
    for (const domain of scope.allowedDomains) {
      if (clean.endsWith('.' + domain)) {
        return { allowed: true, reason: `Authorized subdomain of ${domain}` };
      }
    }

    return {
      allowed: false,
      reason: `Host ${clean} does not belong to authorized domains [${scope.allowedDomains.join(', ')}]`,
      isOutOfScopeDiscovery: true
    };
  }

  /**
   * Check if a port probe is allowed under active policy
   */
  static evaluatePortScope(port, rawScope) {
    const scope = this.ensureScope(rawScope, 'localhost');
    const p = Number(port);
    if (isNaN(p) || p <= 0 || p > 65535) {
      return { allowed: false, reason: `Invalid port number: ${port}` };
    }

    const portsList = Array.isArray(scope.allowedPorts) ? scope.allowedPorts : [];
    if (portsList.length === 0 || portsList.includes(p)) {
      return { allowed: true, reason: `Port ${p} is in authorized ports list` };
    }

    return {
      allowed: false,
      reason: `Port ${p} is not authorized for testing under current scope policy`
    };
  }

  /**
   * Check if an HTTP path is allowed under scope policy
   */
  static evaluatePathScope(path, rawScope) {
    if (!path) return { allowed: true, reason: 'Root path' };
    const scope = this.ensureScope(rawScope, 'localhost');

    const excludedPaths = Array.isArray(scope.excludedPaths) ? scope.excludedPaths : [];
    for (const excluded of excludedPaths) {
      if (path.startsWith(excluded)) {
        return {
          allowed: false,
          reason: `Path ${path} is blocked by excluded path rule: ${excluded}`
        };
      }
    }

    return { allowed: true, reason: 'In-scope path' };
  }

  /**
   * Comprehensive probe evaluation before execution
   */
  static validateProbe({ host, port, path, protocol = 'tcp' }, rawScope) {
    const scope = this.ensureScope(rawScope, host);

    // 1. Host check
    const hostCheck = this.evaluateHostScope(host, scope);
    if (!hostCheck.allowed) return hostCheck;

    // 2. Protocol check
    const protocols = Array.isArray(scope.allowedProtocols) ? scope.allowedProtocols : ['http', 'https', 'tcp', 'dns'];
    if (!protocols.includes(protocol.toLowerCase())) {
      return {
        allowed: false,
        reason: `Protocol ${protocol} is not authorized under active scope policy`
      };
    }

    // 3. Port check (if port provided)
    if (port) {
      const portCheck = this.evaluatePortScope(port, scope);
      if (!portCheck.allowed) return portCheck;
    }

    // 4. Path check (if path provided)
    if (path) {
      const pathCheck = this.evaluatePathScope(path, scope);
      if (!pathCheck.allowed) return pathCheck;
    }

    return { allowed: true, reason: 'Probe passed all scope and authorization rules' };
  }
}

module.exports = ScopeAuthorizationService;
