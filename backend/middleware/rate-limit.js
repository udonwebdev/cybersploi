/**
 * API Rate Limiting Middleware
 * Implements tier-based rate limiting and throttling
 */

const redis = require('redis');
const config = require('../config');

class RateLimitService {
  constructor() {
    this.redisClient = redis.createClient({
      url: config.REDIS_URL || 'redis://localhost:6379',
    });
    this.redisClient.connect();

    // Rate limit tiers
    this.tiers = {
      free: { requests: 100, window: 3600 },      // 100 requests/hour
      pro: { requests: 1000, window: 3600 },      // 1000 requests/hour
      enterprise: { requests: 10000, window: 3600 }, // 10k requests/hour
    };
  }

  async checkRateLimit(userId, tier = 'free') {
    try {
      const tierConfig = this.tiers[tier] || this.tiers.free;
      const key = `rate_limit:${userId}`;

      // Get current request count
      const current = await this.redisClient.incr(key);

      // Set expiration on first request
      if (current === 1) {
        await this.redisClient.expire(key, tierConfig.window);
      }

      const remaining = Math.max(0, tierConfig.requests - current);
      const resetTime = await this.redisClient.ttl(key);

      return {
        allowed: current <= tierConfig.requests,
        requests_used: current,
        requests_remaining: remaining,
        reset_time: resetTime,
        tier: tier,
      };
    } catch (error) {
      console.error('Rate limit check error:', error);
      // Allow request if redis fails
      return { allowed: true, error: error.message };
    }
  }

  rateLimitMiddleware(tier = 'free') {
    return async (req, res, next) => {
      try {
        const userId = req.user?.id || req.ip;
        const result = await this.checkRateLimit(userId, tier);

        // Set headers
        res.set('X-RateLimit-Limit', this.tiers[tier].requests);
        res.set('X-RateLimit-Remaining', result.requests_remaining);
        res.set('X-RateLimit-Reset', result.reset_time);

        if (!result.allowed) {
          return res.status(429).json({
            error: 'Too many requests',
            retry_after: result.reset_time,
            message: `Rate limit exceeded. Please try again in ${result.reset_time} seconds.`,
          });
        }

        next();
      } catch (error) {
        console.error('Rate limit middleware error:', error);
        next(); // Allow on error
      }
    };
  }

  async resetUserLimit(userId) {
    try {
      const key = `rate_limit:${userId}`;
      await this.redisClient.del(key);
      return { success: true, message: 'User rate limit reset' };
    } catch (error) {
      console.error('Reset error:', error);
      return { error: error.message };
    }
  }

  async getUserStats(userId) {
    try {
      const stats = {};
      for (const [tierName, tierConfig] of Object.entries(this.tiers)) {
        const key = `rate_limit:${userId}:${tierName}`;
        const count = await this.redisClient.get(key);
        stats[tierName] = {
          requests_used: count ? parseInt(count) : 0,
          requests_remaining: Math.max(0, tierConfig.requests - (count ? parseInt(count) : 0)),
          limit: tierConfig.requests,
        };
      }
      return stats;
    } catch (error) {
      console.error('Stats error:', error);
      return { error: error.message };
    }
  }

  async upgradeTier(userId, newTier) {
    try {
      const key = `tier:${userId}`;
      await this.redisClient.set(key, newTier, { EX: 86400 * 365 }); // 1 year expiry
      await this.resetUserLimit(userId);
      return { success: true, new_tier: newTier };
    } catch (error) {
      console.error('Tier upgrade error:', error);
      return { error: error.message };
    }
  }

  async getUserTier(userId) {
    try {
      const key = `tier:${userId}`;
      const tier = await this.redisClient.get(key);
      return tier || 'free';
    } catch (error) {
      console.error('Get tier error:', error);
      return 'free';
    }
  }
}

module.exports = new RateLimitService();
