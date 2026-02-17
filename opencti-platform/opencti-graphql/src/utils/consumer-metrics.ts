// Shared utilities for stream consumer/producer metrics computation.
// Centralises event-ID parsing, rate rounding, timeLag / estimatedOutOfDepth
// derivation and the mapping to the GraphQL StreamCollectionConsumer shape so
// that every call-site (sseMiddleware, stream domain, connector domain) uses
// exactly the same logic.

import type { StreamInfo } from '../database/stream/stream-utils';

export interface DerivedMetrics {
  timeLag: number;
  estimatedOutOfDepth: number | null;
}

/**
 * Extract the epoch-millisecond timestamp encoded in a Redis stream event ID
 * (format: `<ms>-<seq>`).  Returns 0 when the input is missing or invalid.
 */
export const parseEventIdTimestamp = (eventId: string | null | undefined): number => {
  if (!eventId) return 0;
  const ts = parseInt(eventId.split('-')[0], 10);
  return Number.isNaN(ts) || ts <= 0 ? 0 : ts;
};

/**
 * Round a number to two decimal places.
 */
export const roundRate = (value: number): number => Math.round(value * 100) / 100;

/**
 * Compute `timeLag` and `estimatedOutOfDepth` from raw inputs.
 *
 * This is the **single source of truth** for this calculation and is called
 * by both the SSE middleware (heartbeat) and the stream domain resolver.
 */
export const computeProcessingLagMetrics = (lastEventId: string, streamInfo: StreamInfo, deliveryRate: number, productionRate: number): DerivedMetrics => {
  const headTimestamp = parseEventIdTimestamp(streamInfo.lastEventId);
  const startTimestamp = parseEventIdTimestamp(streamInfo.firstEventId);
  const consumerTimestamp = parseEventIdTimestamp(lastEventId);
  // Time lag
  let timeLag = 0;
  if (consumerTimestamp > 0 && headTimestamp > 0) {
    timeLag = Math.max(0, (headTimestamp - consumerTimestamp) / 1000);
  }
  // Estimated out-of-depth
  let estimatedOutOfDepth: number = 0;
  if (consumerTimestamp > 0 && consumerTimestamp < startTimestamp) {
    // Consumer is already behind the stream buffer
    estimatedOutOfDepth = 0;
  } else if (deliveryRate > 0 && productionRate > deliveryRate) {
    const bufferSeconds = consumerTimestamp > 0 ? (consumerTimestamp - startTimestamp) / 1000 : 0;
    const netLagRate = productionRate - deliveryRate;
    if (netLagRate > 0 && bufferSeconds > 0) {
      estimatedOutOfDepth = bufferSeconds / netLagRate;
    }
  }
  return {
    timeLag: roundRate(timeLag),
    estimatedOutOfDepth: roundRate(estimatedOutOfDepth),
  };
};
