const prisma = require('../config/database');
const { ASSET_TYPES, VERIFICATION_STATUS } = require('../config/constants');
const { v4: uuidv4 } = require('uuid');

class AssetService {
  static formatAsset(asset) {
    return {
      id: asset.id,
      name: asset.description || asset.value,
      target: asset.value,
      value: asset.value,
      type: asset.type,
      criticality: 'HIGH',
      status: asset.verificationStatus || 'verified',
      verificationStatus: asset.verificationStatus || 'verified',
      createdAt: asset.createdAt,
      updatedAt: asset.updatedAt,
      scansCount: asset._count?.scans || 0,
      vulnerabilitiesCount: asset._count?.vulnerabilities || 0
    };
  }

  /**
   * Create asset
   */
  static async createAsset(organizationId, data) {
    const value = (data.value || data.target || data.name || '').trim();
    const type = (data.type || 'domain').toLowerCase();
    const description = data.description || data.name || `Target ${value}`;

    if (!value) {
      throw {
        statusCode: 400,
        error: 'VALIDATION_ERROR',
        message: 'Asset target or value is required'
      };
    }

    // Check for duplicates
    let asset = await prisma.asset.findFirst({
      where: {
        organizationId,
        type,
        value
      }
    });

    if (asset) {
      // Return existing asset formatted
      return this.formatAsset(asset);
    }

    asset = await prisma.asset.create({
      data: {
        organizationId,
        type,
        value,
        description,
        verificationStatus: VERIFICATION_STATUS.VERIFIED || 'verified',
        verificationToken: uuidv4()
      }
    });

    return this.formatAsset(asset);
  }

  /**
   * Get asset by ID
   */
  static async getAsset(organizationId, assetId) {
    const asset = await prisma.asset.findFirst({
      where: { id: assetId, organizationId },
      include: {
        scans: {
          select: {
            id: true,
            type: true,
            status: true,
            progress: true,
            findings: true,
            createdAt: true
          },
          orderBy: { createdAt: 'desc' },
          take: 10
        },
        vulnerabilities: {
          select: {
            id: true,
            title: true,
            severity: true,
            status: true
          },
          orderBy: { severity: 'desc' }
        }
      }
    });

    if (!asset) {
      throw {
        statusCode: 404,
        error: 'ASSET_NOT_FOUND',
        message: 'Asset not found'
      };
    }

    return asset;
  }

  /**
   * List assets
   */
  static async listAssets(organizationId, options = {}) {
    const { page = 1, limit = 20, type, verificationStatus } = options;
    const skip = (page - 1) * limit;

    const where = { organizationId };
    if (type) where.type = type;
    if (verificationStatus) where.verificationStatus = verificationStatus;

    const [assets, total] = await Promise.all([
      prisma.asset.findMany({
        where,
        include: {
          _count: {
            select: {
              scans: true,
              vulnerabilities: true
            }
          }
        },
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' }
      }),
      prisma.asset.count({ where })
    ]);

    return {
      data: assets.map(a => this.formatAsset(a)),
      assets: assets.map(a => this.formatAsset(a)),
      total,
      page,
      limit,
      pages: Math.ceil(total / limit)
    };
  }

  /**
   * Update asset
   */
  static async updateAsset(organizationId, assetId, data) {
    const { description } = data;

    const asset = await prisma.asset.findFirst({
      where: { id: assetId, organizationId }
    });

    if (!asset) {
      throw {
        statusCode: 404,
        error: 'ASSET_NOT_FOUND',
        message: 'Asset not found'
      };
    }

    const updated = await prisma.asset.update({
      where: { id: assetId },
      data: { ...(description && { description }) }
    });

    return updated;
  }

  /**
   * Verify asset
   */
  static async verifyAsset(organizationId, assetId, token) {
    const asset = await prisma.asset.findFirst({
      where: { id: assetId, organizationId }
    });

    if (!asset) {
      throw {
        statusCode: 404,
        error: 'ASSET_NOT_FOUND',
        message: 'Asset not found'
      };
    }

    if (asset.verificationToken !== token) {
      throw {
        statusCode: 400,
        error: 'INVALID_TOKEN',
        message: 'Invalid verification token'
      };
    }

    const verified = await prisma.asset.update({
      where: { id: assetId },
      data: {
        verificationStatus: VERIFICATION_STATUS.VERIFIED,
        verificationToken: null
      }
    });

    return verified;
  }

  /**
   * Delete asset
   */
  static async deleteAsset(organizationId, assetId) {
    const asset = await prisma.asset.findFirst({
      where: { id: assetId, organizationId }
    });

    if (!asset) {
      throw {
        statusCode: 404,
        error: 'ASSET_NOT_FOUND',
        message: 'Asset not found'
      };
    }

    await prisma.asset.delete({
      where: { id: assetId }
    });

    return { message: 'Asset deleted successfully' };
  }
}

module.exports = AssetService;
