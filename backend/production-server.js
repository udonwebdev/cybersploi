const express = require('express');
const cors = require('cors');
require('dotenv').config({ path: '.env' });

// Import middleware
const { authenticate } = require('./middleware/auth');
const errorHandler = require('./middleware/error-handler');

// Import services
const AuthService = require('./services/auth.service');
const UserService = require('./services/user.service');
const AssetService = require('./services/asset.service');
const ScanService = require('./services/scan.service');
const VulnerabilityService = require('./services/vulnerability.service');
const DashboardService = require('./services/dashboard.service');
// Initialize Phase-5 services (orchestration)
require('./services/remediation-orchestrator.service');

// Initialize Express app
const app = express();
const PORT = process.env.API_PORT || 3001;

// ============ MIDDLEWARE ============
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());

// Request logging
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path}`);
  next();
});

// ============ HEALTH CHECK ============
app.get('/health', (req, res) => {
  res.json({
    success: true,
    status: 'operational',
    timestamp: new Date().toISOString()
  });
});

// ============ AUTH ENDPOINTS ============

app.post('/api/v1/auth/register', async (req, res, next) => {
  try {
    const { email, password, firstName, lastName, username } = req.body;

    if (!email || !password || !firstName || !lastName || !username) {
      return res.status(400).json({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Missing required fields'
      });
    }

    const result = await AuthService.register({ email, password, firstName, lastName, username });

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        user: result.user,
        organization: result.organization,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken
      }
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/v1/auth/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Email and password are required'
      });
    }

    const result = await AuthService.login(email, password);

    res.json({
      success: true,
      message: 'Login successful',
      data: result
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/v1/auth/refresh', async (req, res, next) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Refresh token is required'
      });
    }

    const tokens = await AuthService.refreshToken(refreshToken);

    res.json({
      success: true,
      data: tokens
    });
  } catch (error) {
    next(error);
  }
});

// ============ USER ENDPOINTS ============

app.get('/api/v1/users/me', authenticate, async (req, res, next) => {
  try {
    const user = await UserService.getCurrentUser(req.userId);
    res.json({ success: true, data: user });
  } catch (error) {
    next(error);
  }
});

app.patch('/api/v1/users/me', authenticate, async (req, res, next) => {
  try {
    const user = await UserService.updateProfile(req.userId, req.body);
    res.json({ success: true, message: 'Profile updated', data: user });
  } catch (error) {
    next(error);
  }
});

app.post('/api/v1/users/change-password', authenticate, async (req, res, next) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const result = await UserService.changePassword(req.userId, oldPassword, newPassword);
    res.json({ success: true, message: result.message });
  } catch (error) {
    next(error);
  }
});

app.get('/api/v1/organizations/:orgId/users', authenticate, async (req, res, next) => {
  try {
    const { page, limit } = req.query;
    const result = await UserService.getOrganizationUsers(req.organizationId, {
      page: parseInt(page) || 1,
      limit: parseInt(limit) || 20
    });
    res.json({ success: true, data: result });
  } catch (error) {
    next(error);
  }
});

// ============ ASSET ENDPOINTS ============

app.post('/api/v1/assets', authenticate, async (req, res, next) => {
  try {
    const { type, value, description } = req.body;
    if (!type || !value) {
      return res.status(400).json({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'type and value are required'
      });
    }
    const asset = await AssetService.createAsset(req.organizationId, { type, value, description });
    res.status(201).json({ success: true, message: 'Asset created', data: asset });
  } catch (error) {
    next(error);
  }
});

app.get('/api/v1/assets', authenticate, async (req, res, next) => {
  try {
    const result = await AssetService.listAssets(req.organizationId, req.query);
    res.json({ success: true, data: result });
  } catch (error) {
    next(error);
  }
});

app.get('/api/v1/assets/:assetId', authenticate, async (req, res, next) => {
  try {
    const asset = await AssetService.getAsset(req.organizationId, req.params.assetId);
    res.json({ success: true, data: asset });
  } catch (error) {
    next(error);
  }
});

app.patch('/api/v1/assets/:assetId', authenticate, async (req, res, next) => {
  try {
    const asset = await AssetService.updateAsset(req.organizationId, req.params.assetId, req.body);
    res.json({ success: true, message: 'Asset updated', data: asset });
  } catch (error) {
    next(error);
  }
});

app.delete('/api/v1/assets/:assetId', authenticate, async (req, res, next) => {
  try {
    const result = await AssetService.deleteAsset(req.organizationId, req.params.assetId);
    res.json({ success: true, message: result.message });
  } catch (error) {
    next(error);
  }
});

// ============ SCAN ENDPOINTS ============

app.post('/api/v1/scans', authenticate, async (req, res, next) => {
  try {
    const { assetId, type, configuration } = req.body;
    if (!assetId) {
      return res.status(400).json({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'assetId is required'
      });
    }
    const scan = await ScanService.createScan(req.organizationId, { assetId, type, configuration });
    res.status(201).json({ success: true, message: 'Scan created', data: scan });
  } catch (error) {
    next(error);
  }
});

app.get('/api/v1/scans', authenticate, async (req, res, next) => {
  try {
    const result = await ScanService.listScans(req.organizationId, req.query);
    res.json({ success: true, data: result });
  } catch (error) {
    next(error);
  }
});

app.get('/api/v1/scans/:scanId', authenticate, async (req, res, next) => {
  try {
    const scan = await ScanService.getScan(req.organizationId, req.params.scanId);
    res.json({ success: true, data: scan });
  } catch (error) {
    next(error);
  }
});

app.patch('/api/v1/scans/:scanId', authenticate, async (req, res, next) => {
  try {
    const { status, ...data } = req.body;
    const scan = await ScanService.updateScanStatus(req.organizationId, req.params.scanId, status, data);
    res.json({ success: true, message: 'Scan updated', data: scan });
  } catch (error) {
    next(error);
  }
});

app.delete('/api/v1/scans/:scanId', authenticate, async (req, res, next) => {
  try {
    const result = await ScanService.deleteScan(req.organizationId, req.params.scanId);
    res.json({ success: true, message: result.message });
  } catch (error) {
    next(error);
  }
});

// ============ SCANNER EXECUTION ENDPOINTS ============

// Get available scanners
app.get('/api/v1/scanners', authenticate, async (req, res, next) => {
  try {
    const ScannerService = require('./services/scanner.service');
    const scanners = await ScannerService.getAvailableScanners();
    res.json({
      success: true,
      data: scanners,
      message: `${scanners.length} scanner(s) available`
    });
  } catch (error) {
    next(error);
  }
});

// Execute scan with scanners
app.post('/api/v1/scans/:scanId/execute', authenticate, async (req, res, next) => {
  try {
    const { scanId } = req.params;
    const { scanners, scanType } = req.body;

    // Get scan
    const scan = await ScanService.getScan(req.organizationId, scanId);
    if (!scan) {
      return res.status(404).json({
        success: false,
        error: 'NOT_FOUND',
        message: 'Scan not found'
      });
    }

    // Get asset
    const asset = await require('./services/asset.service').getAsset(req.organizationId, scan.assetId);
    if (!asset) {
      return res.status(404).json({
        success: false,
        error: 'NOT_FOUND',
        message: 'Asset not found'
      });
    }

    // Execute scan
    const ScannerService = require('./services/scanner.service');
    const result = await ScannerService.executeScan(scan, asset, {
      scanners: scanners,
      scanType: scanType,
      ...req.body
    });

    res.json({
      success: true,
      message: 'Scan execution started',
      data: result
    });
  } catch (error) {
    next(error);
  }
});

// Get scan progress
app.get('/api/v1/scans/:scanId/progress', authenticate, async (req, res, next) => {
  try {
    const { scanId } = req.params;

    // Verify scan exists and belongs to org
    const scan = await ScanService.getScan(req.organizationId, scanId);
    if (!scan) {
      return res.status(404).json({
        success: false,
        error: 'NOT_FOUND',
        message: 'Scan not found'
      });
    }

    // Get progress
    const ScannerService = require('./services/scanner.service');
    const progress = await ScannerService.getScanProgress(scanId);

    res.json({
      success: true,
      data: progress
    });
  } catch (error) {
    next(error);
  }
});

// Get scan results
app.get('/api/v1/scans/:scanId/results', authenticate, async (req, res, next) => {
  try {
    const { scanId } = req.params;

    // Verify scan exists and belongs to org
    const scan = await ScanService.getScan(req.organizationId, scanId);
    if (!scan) {
      return res.status(404).json({
        success: false,
        error: 'NOT_FOUND',
        message: 'Scan not found'
      });
    }

    // Get results
    const ScannerService = require('./services/scanner.service');
    const results = await ScannerService.getScanResults(scanId);

    res.json({
      success: true,
      data: results
    });
  } catch (error) {
    next(error);
  }
});

// Cancel scan
app.put('/api/v1/scans/:scanId/cancel', authenticate, async (req, res, next) => {
  try {
    const { scanId } = req.params;

    // Verify scan exists and belongs to org
    const scan = await ScanService.getScan(req.organizationId, scanId);
    if (!scan) {
      return res.status(404).json({
        success: false,
        error: 'NOT_FOUND',
        message: 'Scan not found'
      });
    }

    // Cancel scan
    const ScannerService = require('./services/scanner.service');
    const result = await ScannerService.cancelScan(scanId);

    res.json({
      success: true,
      message: 'Scan cancelled',
      data: result
    });
  } catch (error) {
    next(error);
  }
});

// ============ RECONNAISSANCE ENDPOINTS ============

/**
 * Get available reconnaissance modules
 * Returns list of available recon types:
 * - subdomain-enumeration
 * - service-detection
 * - cloud-security
 * - attack-path-discovery
 */
app.get('/api/v1/recon/modules', authenticate, async (req, res, next) => {
  try {
    const ReconOrchestrationService = require('./services/recon-orchestration.service');
    const recon = new ReconOrchestrationService({ db: global.prisma });
    const modules = recon.getAvailableReconTypes();
    const status = await recon.verifyReconModules();

    res.json({
      success: true,
      data: {
        availableModules: modules,
        status: status
      },
      message: `${modules.length} reconnaissance module(s) available`
    });
  } catch (error) {
    next(error);
  }
});

/**
 * Execute reconnaissance on an asset
 * Runs all reconnaissance modules in sequence:
 * 1. Subdomain Enumeration
 * 2. Service Detection
 * 3. Cloud Security Testing
 * 4. Attack Path Discovery
 */
app.post('/api/v1/assets/:assetId/recon', authenticate, async (req, res, next) => {
  try {
    const { assetId } = req.params;
    const { reconTypes, scanType } = req.body;

    // Get asset
    const asset = await AssetService.getAsset(req.organizationId, assetId);
    if (!asset) {
      return res.status(404).json({
        success: false,
        error: 'NOT_FOUND',
        message: 'Asset not found'
      });
    }

    // Execute reconnaissance
    const ReconOrchestrationService = require('./services/recon-orchestration.service');
    const recon = new ReconOrchestrationService({ db: global.prisma });

    const result = await recon.executeRecognaissance(asset, {
      reconTypes: reconTypes || ['subdomains', 'services', 'cloudSecurity', 'attackPaths'],
      scanType: scanType || 'standard'
    });

    res.json({
      success: true,
      message: 'Reconnaissance execution started',
      data: result
    });
  } catch (error) {
    next(error);
  }
});

/**
 * Execute single reconnaissance module
 * Useful for targeted reconnaissance
 * Body: { module: 'subdomains|services|cloudSecurity|attackPaths', scanType: 'quick|standard|deep' }
 */
app.post('/api/v1/assets/:assetId/recon/:module', authenticate, async (req, res, next) => {
  try {
    const { assetId, module } = req.params;
    const { scanType } = req.body;

    // Get asset
    const asset = await AssetService.getAsset(req.organizationId, assetId);
    if (!asset) {
      return res.status(404).json({
        success: false,
        error: 'NOT_FOUND',
        message: 'Asset not found'
      });
    }

    // Execute module
    const ReconOrchestrationService = require('./services/recon-orchestration.service');
    const recon = new ReconOrchestrationService({ db: global.prisma });

    const result = await recon.executeReconModule(module, asset, {
      scanType: scanType || 'standard'
    });

    res.json({
      success: true,
      message: `${module} reconnaissance completed`,
      data: result
    });
  } catch (error) {
    next(error);
  }
});

/**
 * Get reconnaissance progress
 * Returns real-time progress of ongoing reconnaissance
 */
app.get('/api/v1/recon/:reconId/progress', authenticate, async (req, res, next) => {
  try {
    const { reconId } = req.params;

    const ReconOrchestrationService = require('./services/recon-orchestration.service');
    const recon = new ReconOrchestrationService({ db: global.prisma });

    const progress = await recon.getReconProgress(reconId);

    res.json({
      success: true,
      data: progress
    });
  } catch (error) {
    next(error);
  }
});

/**
 * Cancel ongoing reconnaissance
 */
app.put('/api/v1/recon/:reconId/cancel', authenticate, async (req, res, next) => {
  try {
    const { reconId } = req.params;

    const ReconOrchestrationService = require('./services/recon-orchestration.service');
    const recon = new ReconOrchestrationService({ db: global.prisma });

    const result = await recon.cancelRecognaissance(reconId);

    res.json({
      success: true,
      message: 'Reconnaissance cancelled',
      data: result
    });
  } catch (error) {
    next(error);
  }
});

/**
 * Export reconnaissance results
 * Supports: json, csv, html
 */
app.get('/api/v1/recon/:reconId/export/:format', authenticate, async (req, res, next) => {
  try {
    const { reconId, format } = req.params;

    const ReconOrchestrationService = require('./services/recon-orchestration.service');
    const recon = new ReconOrchestrationService({ db: global.prisma });

    const progress = await recon.getReconProgress(reconId);
    const exported = recon.exportResults(progress, format);

    // Set appropriate content type
    switch (format) {
      case 'csv':
        res.type('text/csv');
        break;
      case 'html':
        res.type('text/html');
        break;
      default:
        res.type('application/json');
    }

    res.send(exported);
  } catch (error) {
    next(error);
  }
});

// ============ VULNERABILITY ENDPOINTS ============

app.post('/api/v1/vulnerabilities', authenticate, async (req, res, next) => {
  try {
    const vulnerability = await VulnerabilityService.createVulnerability(req.organizationId, req.body);
    res.status(201).json({ success: true, message: 'Vulnerability created', data: vulnerability });
  } catch (error) {
    next(error);
  }
});

app.get('/api/v1/vulnerabilities', authenticate, async (req, res, next) => {
  try {
    const result = await VulnerabilityService.listVulnerabilities(req.organizationId, req.query);
    res.json({ success: true, data: result });
  } catch (error) {
    next(error);
  }
});

app.get('/api/v1/vulnerabilities/:vulnId', authenticate, async (req, res, next) => {
  try {
    const vuln = await VulnerabilityService.getVulnerability(req.organizationId, req.params.vulnId);
    res.json({ success: true, data: vuln });
  } catch (error) {
    next(error);
  }
});

app.patch('/api/v1/vulnerabilities/:vulnId/status', authenticate, async (req, res, next) => {
  try {
    const { status } = req.body;
    if (!status) {
      return res.status(400).json({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'status is required'
      });
    }
    const vuln = await VulnerabilityService.updateStatus(req.organizationId, req.params.vulnId, status);
    res.json({ success: true, message: 'Vulnerability updated', data: vuln });
  } catch (error) {
    next(error);
  }
});

app.get('/api/v1/vulnerabilities/statistics', authenticate, async (req, res, next) => {
  try {
    const stats = await VulnerabilityService.getStatistics(req.organizationId);
    res.json({ success: true, data: stats });
  } catch (error) {
    next(error);
  }
});

// ============ DASHBOARD ENDPOINTS ============

app.get('/api/v1/dashboard/stats', authenticate, async (req, res, next) => {
  try {
    const stats = await DashboardService.getDashboardStats(req.organizationId);
    res.json({ success: true, data: stats });
  } catch (error) {
    next(error);
  }
});

app.get('/api/v1/dashboard/threats', authenticate, async (req, res, next) => {
  try {
    const threats = await DashboardService.getThreatStream(req.organizationId);
    res.json({ success: true, data: threats });
  } catch (error) {
    next(error);
  }
});

app.get('/api/v1/dashboard/timeline', authenticate, async (req, res, next) => {
  try {
    const { days } = req.query;
    const timeline = await DashboardService.getSecurityTimeline(req.organizationId, parseInt(days) || 30);
    res.json({ success: true, data: timeline });
  } catch (error) {
    next(error);
  }
});

app.get('/api/v1/dashboard/remediation', authenticate, async (req, res, next) => {
  try {
    const progress = await DashboardService.getRemediationProgress(req.organizationId);
    res.json({ success: true, data: progress });
  } catch (error) {
    next(error);
  }
});

// ============ MALWARE ANALYSIS ROUTES (PHASE 4) ============
const { router: malwareRouter } = require('./routes/malware-analysis.routes');
app.use('/api/v1/malware', authenticate, malwareRouter);

// ============ INCIDENT RESPONSE (PHASE 5) ============
const incidentRouter = require('./routes/incidents.routes');
const { router: webhookRouter } = require('./routes/webhooks.routes');
const { incidentRateLimiter, sanitizeIncident, validateOrgContext, auditLog } = require('./middleware/phase5-security');

app.use('/api/v1/incidents', authenticate, auditLog, validateOrgContext, incidentRateLimiter, incidentRouter);
app.use('/api/v1/webhooks', authenticate, auditLog, webhookRouter);

app.get('/api/v1/incidents/health', (req, res) => {
  res.json({
    success: true,
    service: 'Incident Response & Blue Team',
    status: 'operational',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// ============ API DOCUMENTATION ============
app.get('/api/docs', (req, res) => {
  res.json({
    success: true,
    api: 'Cyber Sploi Enterprise Platform',
    version: '1.0.0',
    endpoints: {
      auth: [
        { method: 'POST', path: '/api/v1/auth/register', description: 'Register new user' },
        { method: 'POST', path: '/api/v1/auth/login', description: 'Login user' },
        { method: 'POST', path: '/api/v1/auth/refresh', description: 'Refresh token' }
      ],
      users: [
        { method: 'GET', path: '/api/v1/users/me', description: 'Get current user', auth: true },
        { method: 'PATCH', path: '/api/v1/users/me', description: 'Update profile', auth: true },
        { method: 'POST', path: '/api/v1/users/change-password', description: 'Change password', auth: true }
      ],
      assets: [
        { method: 'POST', path: '/api/v1/assets', description: 'Create asset', auth: true },
        { method: 'GET', path: '/api/v1/assets', description: 'List assets', auth: true },
        { method: 'GET', path: '/api/v1/assets/:id', description: 'Get asset', auth: true },
        { method: 'PATCH', path: '/api/v1/assets/:id', description: 'Update asset', auth: true },
        { method: 'DELETE', path: '/api/v1/assets/:id', description: 'Delete asset', auth: true }
      ],
      scans: [
        { method: 'POST', path: '/api/v1/scans', description: 'Create scan', auth: true },
        { method: 'GET', path: '/api/v1/scans', description: 'List scans', auth: true },
        { method: 'GET', path: '/api/v1/scans/:id', description: 'Get scan', auth: true },
        { method: 'PATCH', path: '/api/v1/scans/:id', description: 'Update scan', auth: true },
        { method: 'DELETE', path: '/api/v1/scans/:id', description: 'Delete scan', auth: true }
      ],
      vulnerabilities: [
        { method: 'POST', path: '/api/v1/vulnerabilities', description: 'Create vulnerability', auth: true },
        { method: 'GET', path: '/api/v1/vulnerabilities', description: 'List vulnerabilities', auth: true },
        { method: 'GET', path: '/api/v1/vulnerabilities/:id', description: 'Get vulnerability', auth: true },
        { method: 'PATCH', path: '/api/v1/vulnerabilities/:id/status', description: 'Update status', auth: true }
      ],
      dashboard: [
        { method: 'GET', path: '/api/v1/dashboard/stats', description: 'Get dashboard stats', auth: true },
        { method: 'GET', path: '/api/v1/dashboard/threats', description: 'Get threat stream', auth: true },
        { method: 'GET', path: '/api/v1/dashboard/timeline', description: 'Get timeline', auth: true },
        { method: 'GET', path: '/api/v1/dashboard/remediation', description: 'Get remediation progress', auth: true }
      ],
      malware: [
        { method: 'POST', path: '/api/v1/malware/upload', description: 'Upload file for malware analysis', auth: true },
        { method: 'GET', path: '/api/v1/malware/:fileId', description: 'Get analysis results', auth: true },
        { method: 'GET', path: '/api/v1/malware/status/:analysisId', description: 'Get analysis status', auth: true },
        { method: 'POST', path: '/api/v1/malware/report/:fileId', description: 'Generate analysis report', auth: true },
        { method: 'GET', path: '/api/v1/malware/list', description: 'List quarantined files', auth: true },
        { method: 'DELETE', path: '/api/v1/malware/:fileId', description: 'Delete from quarantine', auth: true }
      ],
      incidents: [
        { method: 'POST', path: '/api/v1/incidents', description: 'Create incident', auth: true },
        { method: 'GET', path: '/api/v1/incidents', description: 'List incidents', auth: true },
        { method: 'GET', path: '/api/v1/incidents/:id', description: 'Get incident details', auth: true },
        { method: 'POST', path: '/api/v1/incidents/:id/run-playbook', description: 'Execute remediation playbook', auth: true }
      ],
      playbooks: [
        { method: 'POST', path: '/api/v1/incidents/playbooks', description: 'Create playbook', auth: true },
        { method: 'GET', path: '/api/v1/incidents/playbooks', description: 'List playbooks', auth: true },
        { method: 'GET', path: '/api/v1/incidents/playbooks/:id', description: 'Get playbook with steps', auth: true },
        { method: 'POST', path: '/api/v1/incidents/playbooks/:id/steps', description: 'Add playbook step', auth: true }
      ],
      webhooks: [
        { method: 'POST', path: '/api/v1/webhooks', description: 'Subscribe to incident webhooks', auth: true },
        { method: 'GET', path: '/api/v1/webhooks', description: 'List webhook subscriptions', auth: true },
        { method: 'DELETE', path: '/api/v1/webhooks/:id', description: 'Unsubscribe from webhooks', auth: true }
      ]
    }
  });
});

// ============ ERROR HANDLING ============
app.use(errorHandler);

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'NOT_FOUND',
    message: 'Endpoint not found'
  });
});

// ============ START SERVER ============
const server = app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════════╗
║        🔒 CYBER SPLOI PRODUCTION API SERVER               ║
║════════════════════════════════════════════════════════════║
║                                                            ║
║  API URL:   http://localhost:${PORT}                           ║
║  Docs:      http://localhost:${PORT}/api/docs                 ║
║  Health:    http://localhost:${PORT}/health                  ║
║                                                            ║
║  Environment: ${process.env.NODE_ENV || 'development'}                                    ║
║  Database:    ${process.env.DATABASE_URL || 'SQLite (local)'}                    ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
  `);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('\nShutting down gracefully...');
  server.close(async () => {
    const prisma = require('./config/database');
    await prisma.$disconnect();
    process.exit(0);
  });
});

module.exports = app;
