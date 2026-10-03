/**
 * Phase 5 Security Hardening Middleware
 * 
 * Provides:
 * - Rate limiting per organization
 * - Request signing & verification
 * - Input sanitization
 * - RBAC validation
 * - Audit logging
 */

const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const prisma = require('../config/database');

// Rate limiting: 100 incidents per hour per org
const incidentRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: (req, res) => {
    const tier = req.organization?.tier || 'free';
    return tier === 'enterprise' ? 10000 : tier === 'pro' ? 1000 : 100;
  },
  keyGenerator: (req, res) => req.organizationId,
  skip: (req, res) => !req.organizationId,
});

// Validate request signature
const validateSignature = (req, res, next) => {
  const signature = req.headers['x-signature'];
  if (!signature) return res.status(401).json({ success: false, error: 'Missing signature' });

  const secret = process.env.API_SECRET || '';
  const payload = JSON.stringify(req.body);
  const expectedSignature = crypto.createHmac('sha256', secret).update(payload).digest('hex');

  if (signature !== expectedSignature) {
    return res.status(401).json({ success: false, error: 'Invalid signature' });
  }

  next();
};

// Sanitize incident inputs
const sanitizeIncident = (req, res, next) => {
  if (req.body.title) req.body.title = String(req.body.title).substring(0, 500);
  if (req.body.description) req.body.description = String(req.body.description).substring(0, 5000);
  if (req.body.severity) {
    const validSeverities = ['critical', 'high', 'medium', 'low', 'info'];
    req.body.severity = validSeverities.includes(req.body.severity) ? req.body.severity : 'medium';
  }
  if (req.body.indicators && Array.isArray(req.body.indicators)) {
    req.body.indicators = req.body.indicators.slice(0, 100).map(i => String(i).substring(0, 200));
  }
  next();
};

// RBAC validation - check if user can modify incidents
const canModifyIncident = async (req, res, next) => {
  try {
    const role = req.userRole || 'member'; // obtained from auth middleware
    const allowedRoles = ['owner', 'admin', 'analyst'];

    if (!allowedRoles.includes(role)) {
      return res.status(403).json({ success: false, error: 'Insufficient permissions' });
    }

    next();
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

// Audit logging middleware
const auditLog = async (req, res, next) => {
  const originalSend = res.send;

  res.send = function (data) {
    // Log after response
    if (req.organizationId && (req.method !== 'GET')) {
      const logEntry = {
        organizationId: req.organizationId,
        userId: req.userId,
        action: `${req.method} ${req.path}`,
        resource: req.path,
        statusCode: res.statusCode,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        timestamp: new Date(),
      };

      // Async log (don't block response)
      setImmediate(() => {
        console.log('AUDIT', logEntry);
        // In production, persist to audit log table:
        // prisma.auditLog.create({ data: logEntry }).catch(console.error);
      });
    }

    res.send = originalSend;
    return originalSend.call(this, data);
  };

  next();
};

// Input validation: ensure organizationId matches authenticated org
const validateOrgContext = (req, res, next) => {
  const bodyOrgId = req.body?.organizationId;
  const queryOrgId = req.query?.organizationId;
  const authOrgId = req.organizationId;

  const contextOrgId = bodyOrgId || queryOrgId;
  if (contextOrgId && contextOrgId !== authOrgId) {
    return res.status(403).json({ success: false, error: 'Organization mismatch' });
  }

  next();
};

module.exports = {
  incidentRateLimiter,
  validateSignature,
  sanitizeIncident,
  canModifyIncident,
  auditLog,
  validateOrgContext,
};
