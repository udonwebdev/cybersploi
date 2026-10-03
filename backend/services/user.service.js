const prisma = require('../config/database');

class UserService {
  /**
   * Get current user
   */
  static async getCurrentUser(userId) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        username: true,
        avatar: true,
        emailVerified: true,
        createdAt: true,
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
          }
        }
      }
    });

    if (!user) {
      throw {
        statusCode: 404,
        error: 'USER_NOT_FOUND',
        message: 'User not found'
      };
    }

    return user;
  }

  /**
   * Update user profile
   */
  static async updateProfile(userId, data) {
    const { firstName, lastName, avatar } = data;

    const user = await prisma.user.update({
      where: { id: userId },
      data: {
        ...(firstName && { firstName }),
        ...(lastName && { lastName }),
        ...(avatar && { avatar })
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        username: true,
        avatar: true
      }
    });

    return user;
  }

  /**
   * Change password
   */
  static async changePassword(userId, oldPassword, newPassword) {
    const bcrypt = require('bcryptjs');

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, password: true }
    });

    if (!user) {
      throw {
        statusCode: 404,
        error: 'USER_NOT_FOUND',
        message: 'User not found'
      };
    }

    // Verify old password
    const isPasswordValid = await bcrypt.compare(oldPassword, user.password);
    if (!isPasswordValid) {
      throw {
        statusCode: 401,
        error: 'INVALID_PASSWORD',
        message: 'Current password is incorrect'
      };
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await prisma.user.update({
      where: { id: userId },
      data: { password: hashedPassword }
    });

    return { message: 'Password changed successfully' };
  }

  /**
   * List users in organization
   */
  static async getOrganizationUsers(organizationId, options = {}) {
    const { page = 1, limit = 20 } = options;
    const skip = (page - 1) * limit;

    const [users, total] = await Promise.all([
      prisma.user_Organization.findMany({
        where: { organizationId },
        include: {
          user: {
            select: {
              id: true,
              email: true,
              firstName: true,
              lastName: true,
              username: true,
              avatar: true,
              createdAt: true
            }
          }
        },
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' }
      }),
      prisma.user_Organization.count({
        where: { organizationId }
      })
    ]);

    return {
      data: users.map(uo => ({
        ...uo.user,
        role: uo.role,
        joinedAt: uo.createdAt
      })),
      total,
      page,
      limit,
      pages: Math.ceil(total / limit)
    };
  }
}

module.exports = UserService;
