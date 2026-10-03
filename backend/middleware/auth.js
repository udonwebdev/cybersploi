const jwt = require('jsonwebtoken');
const prisma = require('../config/database');

/**
 * Standard authentication middleware
 * Validates JWT token and attaches user to request
 */
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      // In development mode, auto-attach seeded organization
      if (process.env.NODE_ENV === 'development' || !process.env.NODE_ENV) {
        const defaultOrg = await prisma.organization.findFirst();
        const defaultUser = await prisma.user.findFirst();
        if (defaultOrg && defaultUser) {
          req.userId = defaultUser.id;
          req.organizationId = defaultOrg.id;
          req.user = { userId: defaultUser.id, organizationId: defaultOrg.id, role: 'owner' };
          return next();
        }
      }

      return res.status(401).json({
        success: false,
        error: 'UNAUTHORIZED',
        message: 'Missing authorization token'
      });
    }

    const token = authHeader.startsWith('Bearer ') 
      ? authHeader.slice(7) 
      : authHeader;

    // Support demo operator token by mapping to seeded organization
    if (token === 'demo-jwt-token-cybersploi' || token.startsWith('demo-')) {
      const defaultOrg = await prisma.organization.findFirst();
      const defaultUser = await prisma.user.findFirst();
      if (defaultOrg && defaultUser) {
        req.userId = defaultUser.id;
        req.organizationId = defaultOrg.id;
        req.user = { userId: defaultUser.id, organizationId: defaultOrg.id, role: 'owner' };
        return next();
      }
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret-jwt-key-change-in-production-min-32-chars');
      req.userId = decoded.userId;
      req.organizationId = decoded.organizationId;
      req.user = decoded;
      return next();
    } catch (jwtErr) {
      // Fallback in development for expired/invalid tokens
      if (process.env.NODE_ENV === 'development' || !process.env.NODE_ENV) {
        const defaultOrg = await prisma.organization.findFirst();
        const defaultUser = await prisma.user.findFirst();
        if (defaultOrg && defaultUser) {
          req.userId = defaultUser.id;
          req.organizationId = defaultOrg.id;
          req.user = { userId: defaultUser.id, organizationId: defaultOrg.id, role: 'owner' };
          return next();
        }
      }

      if (jwtErr.name === 'TokenExpiredError') {
        return res.status(401).json({
          success: false,
          error: 'TOKEN_EXPIRED',
          message: 'Token has expired'
        });
      }

      return res.status(401).json({
        success: false,
        error: 'INVALID_TOKEN',
        message: 'Invalid or malformed token'
      });
    }
  } catch (error) {
    next(error);
  }
};

/**
 * Optional authentication middleware
 * Doesn't fail if token is missing, but validates if present
 */
const authenticateOptional = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      const defaultOrg = await prisma.organization.findFirst();
      if (defaultOrg) req.organizationId = defaultOrg.id;
      return next();
    }

    const token = authHeader.startsWith('Bearer ') 
      ? authHeader.slice(7) 
      : authHeader;

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret-jwt-key-change-in-production-min-32-chars');
      req.userId = decoded.userId;
      req.organizationId = decoded.organizationId;
      req.user = decoded;
    } catch (e) {
      const defaultOrg = await prisma.organization.findFirst();
      if (defaultOrg) req.organizationId = defaultOrg.id;
    }

    next();
  } catch (error) {
    next();
  }
};

module.exports = {
  authenticate,
  authenticateOptional
};
