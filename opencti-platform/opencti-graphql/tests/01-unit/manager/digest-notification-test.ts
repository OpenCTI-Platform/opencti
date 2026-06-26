import { afterEach, describe, expect, it, vi } from 'vitest';
import type { KnowledgeNotificationEvent } from '../../../src/manager/notificationManager';

// Mock the stream layer so collectDigestContent is driven with canned batches (no Redis needed).
const fetchRangeNotificationsMock = vi.fn();
vi.mock('../../../src/database/stream/stream-handler', () => ({
  fetchRangeNotifications: (...args: unknown[]) => fetchRangeNotificationsMock(...args),
  storeNotificationEvent: vi.fn(),
  createStreamProcessor: vi.fn(),
}));

import { collectDigestContent, DEFAULT_MAX_DIGEST_CONTENT_SIZE } from '../../../src/manager/notificationManager';

let objSeq = 0;
const liveEvent = (notificationId: string, userId = 'user-1'): KnowledgeNotificationEvent => {
  objSeq += 1;
  return {
    version: '1',
    type: 'live',
    notification_id: notificationId,
    targets: [{ user: { user_id: userId, user_email: '', notifiers: [], user_service_account: false }, type: 'live', message: 'm' }],
    data: { id: `obj-${objSeq}` } as KnowledgeNotificationEvent['data'],
    origin: {},
  };
};

// Byte size of an event, mirroring how collectDigestContent measures the retained content.
const eventBytes = (event: KnowledgeNotificationEvent) => Buffer.byteLength(JSON.stringify(event));

// Wrap events the way rawFetchRangeNotifications delivers them: paired with their stored byte size.
const sizedBatch = (events: KnowledgeNotificationEvent[]) => events.map((event) => ({ event, byteSize: eventBytes(event) }));

// Make the mocked fetchRangeNotifications deliver the given batches, honouring an early-stop (false).
const driveBatches = (batches: KnowledgeNotificationEvent[][]) => {
  fetchRangeNotificationsMock.mockImplementation(async (_start, _end, callback) => {
    for (let i = 0; i < batches.length; i += 1) {
      const shouldContinue = await callback(sizedBatch(batches[i]));
      if (shouldContinue === false) break;
    }
  });
};

describe('collectDigestContent', () => {
  afterEach(() => {
    vi.clearAllMocks();
    objSeq = 0; // keep tests isolated: the generated obj ids restart from 1 for each test
  });

  it('keeps only the events whose notification_id belongs to the digest triggers', async () => {
    driveBatches([[
      liveEvent('trigger-A'),
      liveEvent('trigger-B'),
      liveEvent('trigger-A'),
      liveEvent('trigger-C'),
    ]]);
    const { content, truncated } = await collectDigestContent(new Date(1), new Date(2), ['trigger-A', 'trigger-B']);
    expect(truncated).toBe(false);
    expect(content).toHaveLength(3);
    expect(content.map((c) => c.notification_id).sort()).toEqual(['trigger-A', 'trigger-A', 'trigger-B']);
  });

  it('accumulates matching events across multiple batches', async () => {
    driveBatches([
      [liveEvent('trigger-A'), liveEvent('trigger-X')],
      [liveEvent('trigger-A')],
    ]);
    const { content, truncated } = await collectDigestContent(new Date(1), new Date(2), ['trigger-A']);
    expect(truncated).toBe(false);
    expect(content).toHaveLength(2);
  });

  it('caps the content at the byte budget and reports truncation', async () => {
    const events = Array.from({ length: 10 }, () => liveEvent('trigger-A'));
    driveBatches([events]);
    // Budget sized for exactly 3 events: truncation triggers when the cumulative byte size reaches it.
    const budget = eventBytes(events[0]) + eventBytes(events[1]) + eventBytes(events[2]);
    const { content, truncated, byteSize } = await collectDigestContent(new Date(1), new Date(2), ['trigger-A'], budget);
    expect(truncated).toBe(true);
    expect(content).toHaveLength(3);
    expect(byteSize).toBeGreaterThanOrEqual(budget);
  });

  it('stops requesting further batches once the byte budget is reached', async () => {
    const firstBatch = [liveEvent('trigger-A'), liveEvent('trigger-A'), liveEvent('trigger-A')];
    const secondBatch = [liveEvent('trigger-A')];
    let batchesConsumed = 0;
    fetchRangeNotificationsMock.mockImplementation(async (_start, _end, callback) => {
      const batches = [firstBatch, secondBatch];
      for (let b = 0; b < batches.length; b += 1) {
        batchesConsumed += 1;

        const shouldContinue = await callback(sizedBatch(batches[b]));
        if (shouldContinue === false) break;
      }
    });
    // Budget sized for 2 events: truncation hits inside the first batch.
    const budget = eventBytes(firstBatch[0]) + eventBytes(firstBatch[1]);
    const { content, truncated } = await collectDigestContent(new Date(1), new Date(2), ['trigger-A'], budget);
    expect(truncated).toBe(true);
    expect(content).toHaveLength(2);
    expect(batchesConsumed).toBe(1); // the second batch is never requested
  });

  it('exposes a strictly positive default cap', () => {
    expect(DEFAULT_MAX_DIGEST_CONTENT_SIZE).toBeGreaterThan(0);
  });
});
