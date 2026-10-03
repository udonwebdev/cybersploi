import crypto from 'crypto';

export type EventSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface FabricEvent {
  eventId: string;
  engagementId: string;
  partition: number;
  eventType: string;
  severity: EventSeverity;
  targetKey: string;
  latencyMs: number;
  timestamp: string;
  evidenceHash?: string;
  payload: Record<string, any>;
}

export interface DeadLetterItem {
  event: FabricEvent;
  failureReason: string;
  failedAttempts: number;
  queuedAt: string;
  lastAttemptAt: string;
}

export interface ColumnarBatch {
  batchId: string;
  rowCount: number;
  timestamp: string;
  columns: {
    event_id: string[];
    engagement_id: string[];
    partition: number[];
    event_type: string[];
    severity: string[];
    target_key: string[];
    latency_ms: number[];
    evidence_hash: (string | null)[];
    payload_json: string[];
    created_at: string[];
  };
}

export class EventFabricService {
  private static numPartitions = 8;
  private static ringBufferSize = 500;
  private static ringBuffer: FabricEvent[] = [];
  private static bufferHead = 0;
  private static isBufferFull = false;

  private static deadLetterQueue: DeadLetterItem[] = [];
  private static subscribers: Map<string, (event: FabricEvent) => Promise<boolean>> = new Map();
  private static eventCount = 0;

  /**
   * Determine partition index using consistent hash
   */
  public static getPartition(key: string): number {
    const hash = crypto.createHash('md5').update(key).digest();
    return hash.readUInt32BE(0) % this.numPartitions;
  }

  /**
   * Emit an event into the fabric
   */
  public static async emit(
    engagementId: string,
    eventType: string,
    targetKey: string,
    severity: EventSeverity,
    payload: Record<string, any> = {},
    options: { latencyMs?: number; evidenceHash?: string } = {}
  ): Promise<FabricEvent> {
    const partition = this.getPartition(`${engagementId}:${targetKey}`);
    const eventId = `EVT-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;

    const event: FabricEvent = {
      eventId,
      engagementId,
      partition,
      eventType,
      severity,
      targetKey,
      latencyMs: options.latencyMs ?? 0,
      timestamp: new Date().toISOString(),
      evidenceHash: options.evidenceHash,
      payload
    };

    // Store in circular ring buffer
    if (this.ringBuffer.length < this.ringBufferSize) {
      this.ringBuffer.push(event);
    } else {
      this.ringBuffer[this.bufferHead] = event;
      this.isBufferFull = true;
    }
    this.bufferHead = (this.bufferHead + 1) % this.ringBufferSize;
    this.eventCount++;

    // Dispatch to registered subscribers with backpressure / DLQ safety
    for (const [subId, handler] of this.subscribers.entries()) {
      try {
        const success = await handler(event);
        if (!success) {
          this.sendToDLQ(event, `Subscriber ${subId} returned false`);
        }
      } catch (err: any) {
        this.sendToDLQ(event, `Subscriber ${subId} threw: ${err.message || String(err)}`);
      }
    }

    return event;
  }

  /**
   * Subscribe to the event fabric
   */
  public static subscribe(
    subscriberId: string,
    handler: (event: FabricEvent) => Promise<boolean>
  ): void {
    this.subscribers.set(subscriberId, handler);
  }

  /**
   * Unsubscribe from the event fabric
   */
  public static unsubscribe(subscriberId: string): void {
    this.subscribers.delete(subscriberId);
  }

  /**
   * Replay events from the ring buffer
   */
  public static replay(options: {
    engagementId?: string;
    partition?: number;
    sinceTimestamp?: string;
    limit?: number;
  } = {}): FabricEvent[] {
    let events = [...this.ringBuffer];

    // Order correctly if buffer has wrapped around
    if (this.isBufferFull) {
      events = [
        ...this.ringBuffer.slice(this.bufferHead),
        ...this.ringBuffer.slice(0, this.bufferHead)
      ];
    }

    if (options.engagementId) {
      events = events.filter(e => e.engagementId === options.engagementId);
    }
    if (options.partition !== undefined) {
      events = events.filter(e => e.partition === options.partition);
    }
    if (options.sinceTimestamp) {
      const since = new Date(options.sinceTimestamp).getTime();
      events = events.filter(e => new Date(e.timestamp).getTime() >= since);
    }

    const limit = options.limit || 100;
    return events.slice(-limit);
  }

  /**
   * Enqueue to Dead Letter Queue
   */
  private static sendToDLQ(event: FabricEvent, failureReason: string): void {
    const existing = this.deadLetterQueue.find(item => item.event.eventId === event.eventId);
    if (existing) {
      existing.failedAttempts++;
      existing.lastAttemptAt = new Date().toISOString();
      existing.failureReason = failureReason;
    } else {
      this.deadLetterQueue.push({
        event,
        failureReason,
        failedAttempts: 1,
        queuedAt: new Date().toISOString(),
        lastAttemptAt: new Date().toISOString()
      });
    }

    // Keep DLQ capped at 200 items
    if (this.deadLetterQueue.length > 200) {
      this.deadLetterQueue.shift();
    }
  }

  /**
   * Get Dead Letter Queue items
   */
  public static getDeadLetterQueue(): DeadLetterItem[] {
    return [...this.deadLetterQueue];
  }

  /**
   * Retry items from the Dead Letter Queue
   */
  public static async retryDLQ(): Promise<{ retried: number; recovered: number; stillFailing: number }> {
    const items = [...this.deadLetterQueue];
    this.deadLetterQueue = [];
    let recovered = 0;
    let stillFailing = 0;

    for (const item of items) {
      let allPassed = true;
      for (const [subId, handler] of this.subscribers.entries()) {
        try {
          const success = await handler(item.event);
          if (!success) allPassed = false;
        } catch {
          allPassed = false;
        }
      }

      if (allPassed) {
        recovered++;
      } else {
        item.failedAttempts++;
        item.lastAttemptAt = new Date().toISOString();
        this.deadLetterQueue.push(item);
        stillFailing++;
      }
    }

    return { retried: items.length, recovered, stillFailing };
  }

  /**
   * Generate Columnar Batch (ClickHouse / OLAP ingestion format)
   */
  public static exportColumnarBatch(events: FabricEvent[]): ColumnarBatch {
    const batchId = `BATCH-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;

    const columns: ColumnarBatch['columns'] = {
      event_id: [],
      engagement_id: [],
      partition: [],
      event_type: [],
      severity: [],
      target_key: [],
      latency_ms: [],
      evidence_hash: [],
      payload_json: [],
      created_at: []
    };

    for (const e of events) {
      columns.event_id.push(e.eventId);
      columns.engagement_id.push(e.engagementId);
      columns.partition.push(e.partition);
      columns.event_type.push(e.eventType);
      columns.severity.push(e.severity);
      columns.target_key.push(e.targetKey);
      columns.latency_ms.push(e.latencyMs);
      columns.evidence_hash.push(e.evidenceHash || null);
      columns.payload_json.push(JSON.stringify(e.payload));
      columns.created_at.push(e.timestamp);
    }

    return {
      batchId,
      rowCount: events.length,
      timestamp: new Date().toISOString(),
      columns
    };
  }

  /**
   * Status and telemetry health of the fabric
   */
  public static getTelemetryStatus() {
    return {
      totalEventsProcessed: this.eventCount,
      activePartitions: this.numPartitions,
      ringBufferUsage: this.ringBuffer.length,
      ringBufferCapacity: this.ringBufferSize,
      deadLetterQueueSize: this.deadLetterQueue.length,
      activeSubscribers: this.subscribers.size
    };
  }

  /**
   * Reset ring buffer and DLQ (useful for tests)
   */
  public static reset(): void {
    this.ringBuffer = [];
    this.bufferHead = 0;
    this.isBufferFull = false;
    this.deadLetterQueue = [];
    this.subscribers.clear();
    this.eventCount = 0;
  }
}
