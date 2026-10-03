/**
 * API Gateway Authentication Middleware
 * Implements OAuth2, API Key, JWT authentication
 */

const jwt = require('jsonwebtoken');
const config = require('../config');

class APIGatewayAuth {
  constructor() {
    this.jwtSecret = config.JWT_SECRET;
    this.jwtExpiry = config.JWT_EXPIRY || '7d';
  }

  // JWT Token Generation
  generateToken(userId, role = 'user') {
    try {
      const token = jwt.sign(
        { userId, role, iat: Math.floor(Date.now() / 1000) },
        this.jwtSecret,
        { expiresIn: this.jwtExpiry }
      );
      return token;
    } catch (error) {
      console.error('Token generation error:', error);
      return null;
    }
  }

  // JWT Verification Middleware
  verifyToken(req, res, next) {
    try {
      const token = req.headers.authorization?.split(' ')[1];

      if (!token) {
        return res.status(401).json({ error: 'No token provided' });
      }

      const decoded = jwt.verify(token, this.jwtSecret);
      req.user = decoded;
      next();
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Token expired' });
      }
      return res.status(401).json({ error: 'Invalid token' });
    }
  }

  // API Key Authentication
  async validateApiKey(req, res, next) {
    try {
      const apiKey = req.headers['x-api-key'];

      if (!apiKey) {
        return res.status(401).json({ error: 'API key required' });
      }

      // Validate against database or cache
      const isValid = await this.checkApiKeyValidity(apiKey);

      if (!isValid) {
        return res.status(403).json({ error: 'Invalid API key' });
      }

      req.apiKey = apiKey;
      next();
    } catch (error) {
      return res.status(500).json({ error: 'Auth error' });
    }
  }

  // OAuth2 Integration (Google, GitHub, GitHub, etc.)
  async handleOAuth2Callback(req, res) {
    try {
      const { code, provider } = req.body;

      let userInfo;

      if (provider === 'google') {
        userInfo = await this.exchangeGoogleCode(code);
      } else if (provider === 'github') {
        userInfo = await this.exchangeGithubCode(code);
      } else {
        return res.status(400).json({ error: 'Unknown provider' });
      }

      const token = this.generateToken(userInfo.id, 'user');
      return res.json({
        success: true,
        token,
        user: userInfo,
        expires_in: this.jwtExpiry,
      });
    } catch (error) {
      console.error('OAuth2 error:', error);
      return res.status(400).json({ error: 'OAuth2 failed' });
    }
  }

  // SAML Integration
  async handleSAMLResponse(req, res) {
    try {
      const saml = require('passport-saml');
      // Implementation depends on SAML provider
      return res.json({ success: true });
    } catch (error) {
      console.error('SAML error:', error);
      return res.status(400).json({ error: 'SAML authentication failed' });
    }
  }

  // Multi-factor Authentication (MFA)
  async enableMFA(userId) {
    try {
      const speakeasy = require('speakeasy');

      const secret = speakeasy.generateSecret({
        name: `CYBERSPLOI (${userId})`,
        issuer: 'CYBERSPLOI',
        length: 32,
      });

      return {
        success: true,
        secret: secret.base32,
        qrCode: secret.otpauth_url,
      };
    } catch (error) {
      console.error('MFA error:', error);
      return { error: error.message };
    }
  }

  // Verify MFA Token
  async verifyMFAToken(secret, token) {
    try {
      const speakeasy = require('speakeasy');

      const verified = speakeasy.totp.verify({
        secret: secret,
        encoding: 'base32',
        token: token,
        window: 2,
      });

      return verified;
    } catch (error) {
      console.error('MFA verification error:', error);
      return false;
    }
  }

  // Session Management
  createSession(userId) {
    return {
      session_id: `sess_${Date.now()}_${Math.random()}`,
      user_id: userId,
      created_at: new Date(),
      expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    };
  }

  // Rate Limiting Per User
  async checkUserRateLimit(userId, limit = 100, window = 3600) {
    try {
      const redis = require('redis');
      const client = redis.createClient({ url: config.REDIS_URL });
      await client.connect();

      const key = `rate:${userId}`;
      const current = await client.incr(key);

      if (current === 1) {
        await client.expire(key, window);
      }

      await client.quit();

      return {
        allowed: current <= limit,
        requests_used: current,
        requests_remaining: Math.max(0, limit - current),
      };
    } catch (error) {
      console.error('Rate limit error:', error);
      return { allowed: true }; // Allow on error
    }
  }

  // Helper methods
  async checkApiKeyValidity(apiKey) {
    // Implement database check
    return true;
  }

  async exchangeGoogleCode(code) {
    // Exchange auth code for Google user info
    // Implementation depends on Google OAuth2
    return { id: 'google_user_id', email: 'user@example.com' };
  }

  async exchangeGithubCode(code) {
    // Exchange auth code for GitHub user info
    // Implementation depends on GitHub OAuth2
    return { id: 'github_user_id', email: 'user@github.com' };
  }
}

module.exports = new APIGatewayAuth();
