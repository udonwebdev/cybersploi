// Quick page reference for CYBER SPLOI Frontend

// Core Application Pages
export const PAGES = {
  // Main Pages
  HOME: '/',
  DASHBOARD: '/dashboard',
  AUTH: '/auth',
  
  // Security & Vulnerabilities
  VULNERABILITIES: '/vulnerabilities',
  VULNERABILITY_DETAIL: '/vulnerabilities/detail',
  VULNERABILITY_SCANNER: '/vulnerability-scanner',
  THREAT_INTEL: '/threat-intel',
  THREAT_INTEL_DETAIL: '/threat-intel-detail',
  
  // Incident Management
  INCIDENTS: '/incidents',
  INCIDENT_DETAIL: '/incidents/detail',
  INCIDENT_RESPONSE: '/incident-response',
  
  // Asset Management
  ASSETS: '/assets',
  ASSET_DETAIL: '/assets/detail',
  ASSET_MANAGEMENT: '/asset-management',
  
  // Scanning
  SCANS: '/scans',
  SCAN_DETAIL: '/scans/detail',
  SCAN_MANAGEMENT: '/scan-management',
  
  // Monitoring
  MONITORING: '/monitoring',
  INFRASTRUCTURE: '/infrastructure',
  SECURITY_MONITORING: '/security-monitoring',
  
  // Compliance
  COMPLIANCE: '/compliance',
  COMPLIANCE_CENTER: '/compliance-center',
  COMPLIANCE_AUDIT: '/compliance-audit-schedule',
  COMPLIANCE_STANDARDS_DETAIL: '/compliance-standards-detail',
  
  // Policies & Governance
  POLICIES: '/policies',
  SECURITY_POLICY_CONFIG: '/security-policy-configuration',
  PLAYBOOKS: '/playbooks',
  
  // Reporting & Analytics
  REPORTS: '/reports',
  ANALYTICS: '/analytics',
  RISK: '/risk',
  
  // Data
  DATA: '/data',
  
  // Account & Settings
  ACCOUNT_SETTINGS: '/account/settings',
  ACCOUNT_PROFILE: '/account/profile',
  ACCOUNT_API_KEYS: '/account/api-keys',
  SECURITY_SETTINGS: '/settings/security',
  BILLING: '/billing',
  
  // Team & Admin
  TEAM: '/team',
  USER_MANAGEMENT: '/user-management',
  ADMIN: '/admin',
  
  // Advanced Security
  MALWARE_LAB: '/malware-analysis-lab',
  MALWARE_REFINED: '/malware-analysis-lab-refined',
  MALWARE_SANDBOX: '/malware-sandbox-lab',
  RED_TEAM: '/red-team-simulation',
  BLUE_TEAM: '/blue-team-command',
  AI_PENTESTER: '/ai-pentester-engine',
  
  // System
  SYSTEM_STATUS: '/system-status',
  SYSTEM_LOGS: '/system-logs-terminal',
  SYSTEM_CAPABILITIES: '/system-capabilities-overview',
  INFRASTRUCTURE_ORCH: '/infrastructure-orchestration',
  
  // Integration & Settings
  INTEGRATIONS: '/integrations',
  NOTIFICATIONS: '/notifications',
  LOGS: '/logs',
  
  // Support & Docs
  DOCUMENTATION: '/docs',
  HELP: '/help',
  SEARCH: '/search',
  ONBOARDING: '/onboarding',
};

// Layout Configuration
export const LAYOUT = {
  SIDEBAR_WIDTH: '16rem', // w-64
  HEADER_HEIGHT: '4rem',  // h-16
  BREAKPOINTS: {
    mobile: 'md:',
    tablet: 'lg:',
    desktop: 'xl:',
  },
};

// Color System
export const COLORS = {
  primary: '#dbfcff',
  primaryContainer: '#00f0ff',
  background: '#111318',
  error: '#ffb4ab',
  onTertiaryContainer: '#ff7043',
  surfaceContainer: '#1a1b21',
  surfaceContainerHigh: '#282a2f',
};

// Typography
export const FONTS = {
  headline: 'Space Grotesk',
  label: 'Manrope',
};

// Navigation Items
export const NAV_ITEMS = [
  { label: 'Dashboard', url: PAGES.DASHBOARD, icon: 'dashboard' },
  { label: 'Vulnerabilities', url: PAGES.VULNERABILITIES, icon: 'security_scan' },
  { label: 'Incidents', url: PAGES.INCIDENTS, icon: 'warning' },
  { label: 'Assets', url: PAGES.ASSETS, icon: 'dns' },
  { label: 'Compliance', url: PAGES.COMPLIANCE, icon: 'verified_user' },
  { label: 'Reports', url: PAGES.REPORTS, icon: 'assessment' },
  { label: 'Analytics', url: PAGES.ANALYTICS, icon: 'analytics' },
  { label: 'Admin', url: PAGES.ADMIN, icon: 'admin_panel_settings' },
];

// API Routes (for future backend integration)
export const API_ROUTES = {
  BASE_URL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001/api',
  VULNERABILITIES: '/vulnerabilities',
  INCIDENTS: '/incidents',
  ASSETS: '/assets',
  SCANS: '/scans',
  COMPLIANCE: '/compliance',
  REPORTS: '/reports',
  TEAM: '/team',
  ANALYTICS: '/analytics',
};
