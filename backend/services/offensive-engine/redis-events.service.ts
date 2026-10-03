import { EventEmitter } from 'events';
import { createClient, RedisClientType } from 'redis';

export interface OffensiveEngineTelemetryEvent {
  engagementId: string;
  actionId?: string;
  correlationId?: string;
  timestamp: string;
  severity: 'INFO' | 'WARN' | 'HIGH' | 'CRITICAL';
  workerId?: string;
  TARGET: string;
  SESSION: string;
  ACTION: string;
  REQUEST?: any;
  RESPONSE?: any;
  OBSERVATION: string;
  DECISION: string;
  NEXT_TEST?: string;
}

export class RedisEventBus {
  private static emitter = new EventEmitter();
  private static redisPublisher: RedisClientType | null = null;
  private static redisSubscriber: RedisClientType | null = null;
  private static isRedisConnected = false;
  private static initAttempted = false;

  // Append-only in-memory rolling buffer (last 500 events per engagement)
  private static eventStore: Map<string, OffensiveEngineTelemetryEvent[]> = new Map();

  private static async initRedis(): Promise<void> {
    if (this.initAttempted) return;
    this.initAttempted = true;

    const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';

    try {
      const pub = createClient({
        url: redisUrl,
        socket: { connectTimeout: 1000, reconnectStrategy: () => false }
      }) as RedisClientType;

      const sub = createClient({
        url: redisUrl,
        socket: { connectTimeout: 1000, reconnectStrategy: () => false }
      }) as RedisClientType;

      pub.on('error', () => { this.isRedisConnected = false; });
      sub.on('error', () => { this.isRedisConnected = false; });

      await Promise.all([pub.connect(), sub.connect()]);

      this.redisPublisher = pub;
      this.redisSubscriber = sub;
      this.isRedisConnected = true;

      // Subscribe to central engine event channel
      await this.redisSubscriber.subscribe('cybersploi:engine:events', (message) => {
        try {
          const evt: OffensiveEngineTelemetryEvent = JSON.parse(message);
          this.emitter.emit(`event:${evt.engagementId}`, evt);
          this.emitter.emit('event:all', evt);
        } catch {}
      });
    } catch {
      this.isRedisConnected = false;
    }
  }

  /**
   * Publishes a telemetry event to both Redis (if connected) and in-process subscribers.
   */
  public static async publish(event: OffensiveEngineTelemetryEvent): Promise<void> {
    const enriched: OffensiveEngineTelemetryEvent = {
      ...event,
      timestamp: event.timestamp || new Date().toISOString()
    };

    // Store in rolling event buffer
    const list = this.eventStore.get(enriched.engagementId) || [];
    list.push(enriched);
    if (list.length > 500) list.shift();
    this.eventStore.set(enriched.engagementId, list);

    // Emit in-process
    this.emitter.emit(`event:${enriched.engagementId}`, enriched);
    this.emitter.emit('event:all', enriched);

    // Try Redis publish
    if (!this.initAttempted) {
      await this.initRedis();
    }
    if (this.isRedisConnected && this.redisPublisher) {
      try {
        await this.redisPublisher.publish('cybersploi:engine:events', JSON.stringify(enriched));
      } catch {
        this.isRedisConnected = false;
      }
    }
  }

  /**
   * Subscribes a listener function to events for a specific engagement (for SSE or UI streaming).
   */
  public static subscribe(
    engagementId: string,
    listener: (event: OffensiveEngineTelemetryEvent) => void
  ): () => void {
    const channel = `event:${engagementId}`;
    this.emitter.on(channel, listener);
    return () => {
      this.emitter.off(channel, listener);
    };
  }

  /**
   * Returns recent events for an engagement from memory buffer.
   */
  public static getRecentEvents(engagementId: string): OffensiveEngineTelemetryEvent[] {
    return this.eventStore.get(engagementId) || [];
  }

  /**
   * Disconnects Redis clients cleanly.
   */
  public static async disconnect(): Promise<void> {
    if (this.redisPublisher) {
      try { await this.redisPublisher.quit(); } catch {}
      this.redisPublisher = null;
    }
    if (this.redisSubscriber) {
      try { await this.redisSubscriber.quit(); } catch {}
      this.redisSubscriber = null;
    }
    this.isRedisConnected = false;
    this.initAttempted = false;
    this.eventStore.clear();
  }
}
