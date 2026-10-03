import * as net from 'net';

export interface AllowedTargetRule {
  host?: string;
  pattern?: string;
  cidr?: string;
  ports?: number[];
  protocols?: string[];
}

/**
 * Normalizes an input target into a cleaned hostname or IP string.
 * Strips URL schemes, credentials, path, query, and optional port.
 */
export function normalizeTargetHost(target: string): string {
  if (!target) return '';
  let clean = target.trim();
  clean = clean.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//i, ''); // strip scheme
  clean = clean.replace(/^.*@/, ''); // strip basic auth user:pass
  clean = clean.split('/')[0]; // strip path
  clean = clean.split('?')[0]; // strip query
  clean = clean.split('#')[0]; // strip fragment
  
  // Handle [ipv6]:port or host:port
  if (clean.startsWith('[') && clean.includes(']')) {
    const endBracket = clean.indexOf(']');
    clean = clean.substring(1, endBracket);
  } else if (!net.isIPv6(clean) && clean.includes(':')) {
    clean = clean.split(':')[0];
  }
  return clean.toLowerCase();
}

/**
 * Converts an IPv4 string into a 32-bit unsigned integer.
 */
function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.').map(p => Number(p));
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
    return null;
  }
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/**
 * Evaluates whether an IPv4 address falls within a given IPv4 CIDR block (e.g. 192.168.1.0/24).
 */
export function isIpInIpv4Cidr(ip: string, cidr: string): boolean {
  if (!cidr.includes('/')) {
    return normalizeTargetHost(ip) === normalizeTargetHost(cidr);
  }
  const [rangeIp, prefixStr] = cidr.split('/');
  const prefix = Number(prefixStr);
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return false;

  const ipInt = ipv4ToInt(normalizeTargetHost(ip));
  const rangeInt = ipv4ToInt(normalizeTargetHost(rangeIp));
  if (ipInt === null || rangeInt === null) return false;

  if (prefix === 0) return true;
  const mask = ((0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF) >>> 0;
  return (ipInt & mask) === (rangeInt & mask);
}

/**
 * Evaluates whether a domain matches a wildcard or domain pattern.
 * e.g., pattern "*.example.com" or "example.com" matches "sub.example.com" and "example.com"
 */
export function isDomainMatch(targetHost: string, pattern: string): boolean {
  const cleanTarget = normalizeTargetHost(targetHost);
  let cleanPattern = normalizeTargetHost(pattern);

  if (cleanPattern.startsWith('*.')) {
    cleanPattern = cleanPattern.substring(2);
    return cleanTarget === cleanPattern || cleanTarget.endsWith('.' + cleanPattern);
  }

  if (cleanPattern.startsWith('.')) {
    cleanPattern = cleanPattern.substring(1);
    return cleanTarget === cleanPattern || cleanTarget.endsWith('.' + cleanPattern);
  }

  return cleanTarget === cleanPattern || cleanTarget.endsWith('.' + cleanPattern);
}

/**
 * Checks if targetHost, port, and protocol match a single target rule.
 */
export function matchTargetRule(
  targetHost: string,
  targetPort: number | undefined,
  targetProtocol: string | undefined,
  rule: AllowedTargetRule | string
): boolean {
  let ruleHost = '';
  let ruleCidr: string | undefined;
  let rulePattern: string | undefined;
  let allowedPorts: number[] | undefined;
  let allowedProtocols: string[] | undefined;

  if (typeof rule === 'string') {
    if (rule.includes('/') && (net.isIP(rule.split('/')[0]) === 4)) {
      ruleCidr = rule.trim();
    } else {
      ruleHost = rule.trim();
    }
  } else if (rule && typeof rule === 'object') {
    if (rule.cidr) ruleCidr = rule.cidr;
    if (rule.host) ruleHost = rule.host;
    if (rule.pattern) rulePattern = rule.pattern;
    if (rule.ports && Array.isArray(rule.ports)) allowedPorts = rule.ports.map(Number);
    if (rule.protocols && Array.isArray(rule.protocols)) {
      allowedProtocols = rule.protocols.map(p => p.toLowerCase().trim());
    }

    // Auto-detect CIDR in host field
    if (!ruleCidr && ruleHost && ruleHost.includes('/') && net.isIP(ruleHost.split('/')[0]) === 4) {
      ruleCidr = ruleHost;
      ruleHost = '';
    }
  }

  const cleanHost = normalizeTargetHost(targetHost);
  let hostMatched = false;

  // 1. CIDR match
  if (ruleCidr && net.isIP(cleanHost) === 4) {
    if (isIpInIpv4Cidr(cleanHost, ruleCidr)) {
      hostMatched = true;
    }
  }

  // 2. Pattern match
  if (!hostMatched && rulePattern) {
    if (rulePattern.includes('*')) {
      const regexStr = '^' + rulePattern.replace(/[-/\\^$+?.()|[\]{}]/g, '\\$&').replace(/\\\*/g, '.*') + '$';
      try {
        const reg = new RegExp(regexStr, 'i');
        if (reg.test(cleanHost) || reg.test(targetHost)) {
          hostMatched = true;
        }
      } catch {
        // Fallback
      }
    } else if (isDomainMatch(cleanHost, rulePattern)) {
      hostMatched = true;
    }
  }

  // 3. Host / Domain match
  if (!hostMatched && ruleHost) {
    if (net.isIP(cleanHost) && net.isIP(normalizeTargetHost(ruleHost))) {
      if (cleanHost === normalizeTargetHost(ruleHost)) {
        hostMatched = true;
      }
    } else if (isDomainMatch(cleanHost, ruleHost)) {
      hostMatched = true;
    }
  }

  if (!hostMatched) return false;

  // 4. Port constraint check
  if (allowedPorts && allowedPorts.length > 0 && targetPort !== undefined) {
    if (!allowedPorts.includes(Number(targetPort))) {
      return false;
    }
  }

  // 5. Protocol constraint check
  if (allowedProtocols && allowedProtocols.length > 0 && targetProtocol !== undefined) {
    if (!allowedProtocols.includes(targetProtocol.toLowerCase().trim())) {
      return false;
    }
  }

  return true;
}

/**
 * Checks if targetHost (+ optional port/protocol) matches ANY rule in allowedTargets.
 */
export function isTargetAllowed(
  targetHost: string,
  targetPort: number | undefined,
  targetProtocol: string | undefined,
  allowedTargets: (AllowedTargetRule | string)[]
): boolean {
  if (!targetHost || !Array.isArray(allowedTargets) || allowedTargets.length === 0) {
    return false;
  }

  for (const rule of allowedTargets) {
    if (matchTargetRule(targetHost, targetPort, targetProtocol, rule)) {
      return true;
    }
  }

  return false;
}
