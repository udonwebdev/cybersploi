import { createClient, RedisClientType } from 'redis';

export interface RateLimitConfig {
  requestsPerSecond?: number;
  concurrency?: number;
}

interface InMemoryBucket {
  tokens: number;
  lastRefillTime: number;
  capacity: number;
  refillRate: number; // tokens per millisecond
}

export class ScopeRateLimiter {
  private static redisClient: RedisClientType | null = null;
  private static redisConnected: boolean = false;
  private static redisInitAttempted: boolean = false;
  private static inMemoryBuckets: Map<string, InMemoryBucket> = new Map();

  /**
   * Initializes Redis connection if available.
   * Silently fails over to memory if Redis is unavailable or unconfigured.
   */
  private static async getRedisClient(): Promise<RedisClientType | null> {
    if (this.redisConnected && this.redisClient) {
      return this.redisClient;
    }
    if (this.redisInitAttempted && !this.redisConnected) {
      return null;
    }

    this.redisInitAttempted = true;
    const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';

    try {
      const client = createClient({
        url: redisUrl,
        socket: {
          connectTimeout: 1000,
          reconnectStrategy: () => false // Do not keep retrying during tests
        }
      }) as RedisClientType;

      client.on('error', () => {
        this.redisConnected = false;
      });

      await client.connect();
      this.redisClient = client;
      this.redisConnected = true;
      return this.redisClient;
    } catch {
      this.redisConnected = false;
      return null;
    }
  }

  /**
   * Parses rate limit configuration with secure defaults
   */
  public static parseRateLimit(config?: string | RateLimitConfig | null): { rps: number; concurrency: number } {
    let rps = 10;
    let concurrency = 5;

    if (!config) return { rps, concurrency };

    let parsed = config;
    if (typeof config === 'string') {
      try {
        parsed = JSON.parse(config);
      } catch {
        return { rps, concurrency };
      }
    }

    if (typeof parsed === 'object' && parsed !== null) {
      const rateObj = parsed as RateLimitConfig;
      if (typeof rateObj.requestsPerSecond === 'number' && rateObj.requestsPerSecond > 0) {
        rps = rateObj.requestsPerSecond;
      }
      if (typeof rateObj.concurrency === 'number' && rateObj.concurrency > 0) {
        concurrency = rateObj.concurrency;
      }
    }

    return { rps, concurrency };
  }

  /**
   * Evaluates token bucket rate limit using Redis or in-memory fallback.
   */
  public static async consumeToken(
    engagementId: string,
    rawConfig?: string | RateLimitConfig | null
  ): Promise<{ allowed: boolean; remainingTokens: number; reason?: string }> {
    const { rps } = this.parseRateLimit(rawConfig);
    const capacity = Math.max(rps, 1);
    const refillRatePerMs = rps / 1000.0;
    const now = Date.now();

    const client = await this.getRedisClient();

    if (client && this.redisConnected) {
      try {
        const key = `ratelimit:scope:${engagementId}`;
        const lastTimeKey = `${key}:ts`;

        // Multi/Transaction token refill in Redis
        const [rawTokens, rawLastTime] = await Promise.all([
          client.get(key),
          client.get(lastTimeKey)
        ]);

        let tokens = rawTokens !== null ? parseFloat(rawTokens) : capacity;
        const lastRefill = rawLastTime !== null ? parseInt(rawLastTime, 10) : now;

        const elapsedMs = Math.max(0, now - lastRefill);
        tokens = Math.min(capacity, tokens + (elapsedMs * refillRatePerMs));

        if (tokens >= 1.0) {
          tokens -= 1.0;
          await Promise.all([
            client.set(key, tokens.toString(), { EX: 60 }),
            client.set(lastTimeKey, now.toString(), { EX: 60 })
          ]);
          return { allowed: true, remainingTokens: Math.floor(tokens) };
        } else {
          await Promise.all([
            client.set(key, tokens.toString(), { EX: 60 }),
            client.set(lastTimeKey, now.toString(), { EX: 60 })
          ]);
          return {
            allowed: false,
            remainingTokens: 0,
            reason: `Rate limit exceeded: ${rps} requests/second allowed for engagement ${engagementId}`
          };
        }
      } catch {
        // Fall back to memory on Redis error
      }
    }

    // In-memory token bucket
    let bucket = this.inMemoryBuckets.get(engagementId);
    if (!bucket) {
      bucket = {
        tokens: capacity,
        lastRefillTime: now,
        capacity,
        refillRate: refillRatePerMs
      };
      this.inMemoryBuckets.set(engagementId, bucket);
    } else {
      // Dynamic config update if changed
      bucket.capacity = capacity;
      bucket.refillRate = refillRatePerMs;
    }

    const elapsedMs = Math.max(0, now - bucket.lastRefillTime);
    bucket.tokens = Math.min(bucket.capacity, bucket.tokens + (elapsedMs * bucket.refillRate));
    bucket.lastRefillTime = now;

    if (bucket.tokens >= 1.0) {
      bucket.tokens -= 1.0;
      return { allowed: true, remainingTokens: Math.floor(bucket.tokens) };
    } else {
      return {
        allowed: false,
        remainingTokens: 0,
        reason: `Rate limit exceeded: ${rps} requests/second allowed for engagement ${engagementId}`
      };
    }
  }

  /**
   * Resets the rate limit bucket for an engagement (useful for test setup).
   */
  public static async resetBucket(engagementId: string): Promise<void> {
    this.inMemoryBuckets.delete(engagementId);
    if (this.redisClient && this.redisConnected) {
      try {
        await this.redisClient.del(`ratelimit:scope:${engagementId}`);
        await this.redisClient.del(`ratelimit:scope:${engagementId}:ts`);
      } catch {
        // Ignore
      }
    }
  }

  /**
   * Cleans up any open Redis connection.
   */
  public static async disconnect(): Promise<void> {
    if (this.redisClient && this.redisConnected) {
      try {
        await this.redisClient.quit();
      } catch {
        // Ignore
      }
      this.redisConnected = false;
      this.redisClient = null;
    }
    this.inMemoryBuckets.clear();
  }

  // ================= CONCURRENCY TRACKING =================
  private static activeConcurrency: Map<string, number> = new Map();

  /**
   * Tries to acquire a concurrency slot for an engagement.
   * Returns true if acquired, false if concurrency limit reached.
   */
  public static acquireConcurrency(engagementId: string, maxConcurrency: number): boolean {
    const current = this.activeConcurrency.get(engagementId) || 0;
    if (current >= maxConcurrency) {
      return false;
    }
    this.activeConcurrency.set(engagementId, current + 1);
    return true;
  }

  /**
   * Releases an active concurrency slot for an engagement.
   */
  public static releaseConcurrency(engagementId: string): void {
    const current = this.activeConcurrency.get(engagementId) || 0;
    if (current > 0) {
      this.activeConcurrency.set(engagementId, current - 1);
    }
  }

  /**
   * Gets currently active concurrent tasks for an engagement.
   */
  public static getConcurrency(engagementId: string): number {
    return this.activeConcurrency.get(engagementId) || 0;
  }

  /**
   * Resets active concurrency counter for an engagement.
   */
  public static resetConcurrency(engagementId: string): void {
    this.activeConcurrency.delete(engagementId);
  }
}

