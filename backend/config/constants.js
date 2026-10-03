module.exports = {
  // User roles
  ROLES: {
    OWNER: 'owner',
    ADMIN: 'admin',
    MEMBER: 'member',
    VIEWER: 'viewer'
  },

  // Asset types
  ASSET_TYPES: {
    DOMAIN: 'domain',
    IP: 'ip',
    WEBSITE: 'website',
    API: 'api',
    MOBILE_APP: 'mobile_app',
    SERVER: 'server',
    DATABASE: 'database',
    APPLICATION: 'application'
  },

  // Scan types
  SCAN_TYPES: {
    FULL: 'full',
    QUICK: 'quick',
    CUSTOM: 'custom',
    ADVANCED: 'advanced',
    MALWARE: 'malware',
    THREAT_INTEL: 'threat_intel'
  },

  // Scan statuses
  SCAN_STATUS: {
    PENDING: 'pending',
    RUNNING: 'running',
    COMPLETED: 'completed',
    FAILED: 'failed',
    CANCELLED: 'cancelled'
  },

  // Severity levels
  SEVERITY: {
    CRITICAL: 'critical',
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
    INFO: 'info'
  },

  // Vulnerability status
  VULN_STATUS: {
    OPEN: 'open',
    REMEDIATED: 'remediated',
    ACCEPTED_RISK: 'accepted_risk'
  },

  // Asset verification status
  VERIFICATION_STATUS: {
    PENDING: 'pending',
    VERIFIED: 'verified',
    FAILED: 'failed'
  },

  // Pagination defaults
  DEFAULT_PAGE_SIZE: 20,
  MAX_PAGE_SIZE: 100,

  // Token expiry
  JWT_EXPIRY: process.env.JWT_EXPIRY || '7d',
  REFRESH_TOKEN_EXPIRY: '30d',
  EMAIL_VERIFICATION_EXPIRY: 24 * 60 * 60 * 1000, // 24 hours
  PASSWORD_RESET_EXPIRY: 60 * 60 * 1000, // 1 hour
};
