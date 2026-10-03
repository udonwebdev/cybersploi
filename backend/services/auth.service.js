const prisma = require('../config/database');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { ROLES, JWT_EXPIRY } = require('../config/constants');

class AuthService {
  /**
   * Register a new user
   */
  static async register(data) {
    const { email, password, firstName, lastName, username } = data;

    // Check if user exists
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [
          { email },
          { username }
        ]
      }
    });

    if (existingUser) {
      const field = existingUser.email === email ? 'email' : 'username';
      throw {
        statusCode: 409,
        error: 'DUPLICATE_USER',
        message: `User with this ${field} already exists`
      };
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        firstName,
        lastName,
        username,
        emailVerified: process.env.NODE_ENV === 'development' // Auto-verify in dev
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        username: true,
        createdAt: true
      }
    });

    // Create default organization
    const organization = await prisma.organization.create({
      data: {
        name: `${firstName} ${lastName}'s Organization`,
        ownerId: user.id
      }
    });

    // Add user to organization
    await prisma.user_Organization.create({
      data: {
        userId: user.id,
        organizationId: organization.id,
        role: ROLES.OWNER
      }
    });

    // Generate tokens
    const tokens = this.generateTokens(user.id, organization.id);

    return {
      user,
      organization,
      ...tokens
    };
  }

  /**
   * Login user
   */
  static async login(email, password) {
    const user = await prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        username: true,
        password: true,
        organizations: {
          select: {
            organizationId: true,
            role: true,
            organization: {
              select: {
                id: true,
                name: true
              }
            }
          },
          take: 1
        }
      }
    });

    if (!user) {
      throw {
        statusCode: 401,
        error: 'INVALID_CREDENTIALS',
        message: 'Invalid email or password'
      };
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      throw {
        statusCode: 401,
        error: 'INVALID_CREDENTIALS',
        message: 'Invalid email or password'
      };
    }

    // Get organization
    const orgData = user.organizations[0];
    const organizationId = orgData?.organizationId;

    if (!organizationId) {
      throw {
        statusCode: 400,
        error: 'NO_ORGANIZATION',
        message: 'User has no organization'
      };
    }

    // Generate tokens
    const tokens = this.generateTokens(user.id, organizationId);

    // Remove password from response
    delete user.password;

    return {
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        username: user.username
      },
      organization: orgData.organization,
      role: orgData.role,
      ...tokens
    };
  }

  /**
   * Refresh access token
   */
  static async refreshToken(refreshToken) {
    try {
      const decoded = jwt.verify(
        refreshToken, 
        process.env.JWT_SECRET || 'dev-secret-key',
        { algorithms: ['HS256'] }
      );

      const user = await prisma.user.findUnique({
        where: { id: decoded.userId },
        select: { id: true, email: true, firstName: true }
      });

      if (!user) {
        throw { statusCode: 401, error: 'USER_NOT_FOUND', message: 'User not found' };
      }

      // Generate new tokens
      const tokens = this.generateTokens(decoded.userId, decoded.organizationId);
      return tokens;
    } catch (error) {
      throw {
        statusCode: 401,
        error: 'INVALID_REFRESH_TOKEN',
        message: 'Invalid or expired refresh token'
      };
    }
  }

  /**
   * Generate JWT tokens
   */
  static generateTokens(userId, organizationId) {
    const accessToken = jwt.sign(
      { userId, organizationId },
      process.env.JWT_SECRET || 'dev-secret-key',
      { expiresIn: process.env.JWT_EXPIRY || '7d' }
    );

    const refreshToken = jwt.sign(
      { userId, organizationId },
      process.env.JWT_SECRET || 'dev-secret-key',
      { expiresIn: '30d' }
    );

    return {
      accessToken,
      refreshToken,
      accessTokenExpiry: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
    };
  }

  /**
   * Verify email token
   */
  static async verifyEmail(token) {
    const user = await prisma.user.findFirst({
      where: {
        verificationToken: token,
        verificationTokenExpires: {
          gt: new Date()
        }
      }
    });

    if (!user) {
      throw {
        statusCode: 400,
        error: 'INVALID_TOKEN',
        message: 'Invalid or expired verification token'
      };
    }

    await prisma.user.update({
      where: { id: user.id },
      data: {
        emailVerified: true,
        verificationToken: null,
        verificationTokenExpires: null
      }
    });

    return { message: 'Email verified successfully' };
  }
}

module.exports = AuthService;
