import * as crypto from 'crypto';
import { RedisEventBus } from './redis-events.service';

export interface TelemetryEvent {
  engagementId: string;
  targetId: string;
  workerId: string;
  timestamp: string;
  latencyMs: number;
  statusCode?: number;
  errorClass?: string;
  rateLimitEvent?: boolean;
  requestMetadata?: Record<string, any>;
  responseMetadata?: Record<string, any>;
  syntheticTrafficMetadata?: {
    protocol: string;
    bytesSent: number;
    bytesReceived: number;
  };
  scanState?: string;
  findingState?: string;
}

export type CircuitBreakerState = 'CLOSED' | 'THROTTLED' | 'OPEN';

export interface AnomalyDetectionReport {
  timestamp: string;
  windowSize: number;
  error5xxRatePercent: number;
  p95LatencyMs: number;
  rateLimitEventsCount: number;
  circuitBreakerState: CircuitBreakerState;
  suggestedConcurrency: number;
  anomaliesDetected: string[];
}

export class TelemetryPipelineService {
  private static eventBuffer: TelemetryEvent[] = [];
  private static slidingWindow: TelemetryEvent[] = [];
  private static maxWindowSize: number = 100;
  private static baselineP95LatencyMs: number = 100;

  // Circuit breaker state
  private static circuitBreakerState: CircuitBreakerState = 'CLOSED';
  private static configuredMaxConcurrency: number = 10;
  private static currentConcurrencyLimit: number = 10;

  /**
   * Sanitizes and redacts sensitive credentials or tokens in metadata.
   */
  public static redactSensitiveData(data: any): any {
    if (!data) return data;
    if (typeof data === 'string') {
      return data
        .replace(/(Bearer\s+)[A-Za-z0-9-_.]+/gi, '$1[REDACTED_TOKEN]')
        .replace(/(password["']?\s*[:=]\s*["']?)[^"',\s]+/gi, '$1[REDACTED_SECRET]')
        .replace(/(ASIA[A-Z0-9]{16})/g, '[REDACTED_ACCESS_KEY]')
        .replace(/(aws_secret_access_key["']?\s*[:=]\s*["']?)[^"',\s]+/gi, '$1[REDACTED_SECRET]');
    }
    if (typeof data === 'object') {
      const sanitized: Record<string, any> = Array.isArray(data) ? [] : {};
      for (const [k, v] of Object.entries(data)) {
        const lowerKey = k.toLowerCase();
        if (lowerKey.includes('authorization') || lowerKey.includes('cookie') || lowerKey.includes('password') || lowerKey.includes('token') || lowerKey.includes('secret')) {
          sanitized[k] = '[REDACTED_CREDENTIAL_REF]';
        } else {
          sanitized[k] = this.redactSensitiveData(v);
        }
      }
      return sanitized;
    }
    return data;
  }

  /**
   * Ingests a telemetry event into the pipeline stream.
   */
  public static ingest(event: TelemetryEvent): AnomalyDetectionReport {
    // 1. Redact sensitive values
    const cleanEvent: TelemetryEvent = {
      ...event,
      requestMetadata: this.redactSensitiveData(event.requestMetadata),
      responseMetadata: this.redactSensitiveData(event.responseMetadata)
    };

    // 2. Buffer event
    this.eventBuffer.push(cleanEvent);
    this.slidingWindow.push(cleanEvent);
    if (this.slidingWindow.length > this.maxWindowSize) {
      this.slidingWindow.shift();
    }

    // 3. Evaluate sliding-window anomalies
    return this.evaluateSlidingWindow(event.engagementId);
  }

  /**
   * Evaluates the sliding window to detect spikes in latency, 5xx error rates, or rate limits.
   * Automatically reduces concurrency when safety thresholds are breached.
   */
  public static evaluateSlidingWindow(engagementId?: string): AnomalyDetectionReport {
    const window = this.slidingWindow;
    const count = window.length;

    if (count === 0) {
      return {
        timestamp: new Date().toISOString(),
        windowSize: 0,
        error5xxRatePercent: 0,
        p95LatencyMs: 0,
        rateLimitEventsCount: 0,
        circuitBreakerState: this.circuitBreakerState,
        suggestedConcurrency: this.currentConcurrencyLimit,
        anomaliesDetected: []
      };
    }

    // Calculate 5xx error rate
    const errors5xx = window.filter(e => (e.statusCode && e.statusCode >= 500) || e.errorClass?.includes('5xx'));
    const error5xxRatePercent = Math.round((errors5xx.length / count) * 100);

    // Calculate p95 latency
    const latencies = window.map(e => e.latencyMs).sort((a, b) => a - b);
    const p95LatencyMs = latencies[Math.floor(count * 0.95)] || 0;

    // Calculate rate limit events (HTTP 429)
    const rateLimitEvents = window.filter(e => e.rateLimitEvent || e.statusCode === 429);
    const rateLimitEventsCount = rateLimitEvents.length;

    const anomalies: string[] = [];

    // Anomaly Conditions
    if (error5xxRatePercent >= 15) {
      anomalies.push(`ELEVATED_5XX_RATE: ${error5xxRatePercent}% 5xx responses observed`);
    }

    if (p95LatencyMs > this.baselineP95LatencyMs * 2.5) {
      anomalies.push(`LATENCY_SPIKE: p95 latency (${p95LatencyMs}ms) exceeds 2.5x baseline`);
    }

    if (rateLimitEventsCount >= 2) {
      anomalies.push(`TARGET_RATE_LIMITING: ${rateLimitEventsCount} rate-limit (429) events in window`);
    }

    // Circuit breaker state machine
    if (anomalies.length >= 2 || error5xxRatePercent >= 30) {
      // Severe degradation -> OPEN (emergency throttle / pause)
      this.circuitBreakerState = 'OPEN';
      this.currentConcurrencyLimit = 1;

      if (engagementId) {
        RedisEventBus.publish({
          engagementId,
          actionId: 'circuit_breaker_open',
          timestamp: new Date().toISOString(),
          severity: 'HIGH',
          TARGET: 'all_in_scope',
          SESSION: 'telemetry_safeguard',
          ACTION: 'CIRCUIT_BREAKER_TRIPPED',
          DECISION: 'THROTTLED_TO_MINIMUM',
          OBSERVATION: `Target safety boundary activated: Concurrency throttled to 1. Anomalies: ${anomalies.join('; ')}`,
          NEXT_TEST: 'COOL_DOWN'
        });
      }
    } else if (anomalies.length >= 1) {
      // Moderate degradation -> THROTTLED (reduce concurrency by 50%)
      this.circuitBreakerState = 'THROTTLED';
      this.currentConcurrencyLimit = Math.max(1, Math.floor(this.configuredMaxConcurrency / 2));
    } else {
      // Normal healthy conditions -> CLOSED
      this.circuitBreakerState = 'CLOSED';
      this.currentConcurrencyLimit = this.configuredMaxConcurrency;
    }

    return {
      timestamp: new Date().toISOString(),
      windowSize: count,
      error5xxRatePercent,
      p95LatencyMs,
      rateLimitEventsCount,
      circuitBreakerState: this.circuitBreakerState,
      suggestedConcurrency: this.currentConcurrencyLimit,
      anomaliesDetected: anomalies
    };
  }

  /**
   * Resets the telemetry sliding window for test isolation.
   */
  public static reset(): void {
    this.eventBuffer = [];
    this.slidingWindow = [];
    this.circuitBreakerState = 'CLOSED';
    this.currentConcurrencyLimit = this.configuredMaxConcurrency;
  }

  public static getCircuitBreakerState(): CircuitBreakerState {
    return this.circuitBreakerState;
  }

  public static getCurrentConcurrencyLimit(): number {
    return this.currentConcurrencyLimit;
  }
}
