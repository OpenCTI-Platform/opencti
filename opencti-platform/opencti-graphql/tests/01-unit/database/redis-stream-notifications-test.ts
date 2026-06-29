import { afterEach, describe, expect, it, vi } from 'vitest';
import type { StreamNotifEvent } from '../../../src/types/event';

// Mock the Redis layer before importing the module under test, so no real connection is opened.
const mockClient = { call: vi.fn() };
vi.mock('../../../src/database/redis', () => ({
  getClientBase: vi.fn(() => mockClient),
  getClientXRANGE: vi.fn(() => mockClient),
  createRedisClient: vi.fn(),
}));

import { fetchRangeNotifications } from '../../../src/database/stream/stream-handler';

// Build a raw XRANGE entry [id, [field, jsonValue, ...]] the way mapJSToStream stores it.
const buildEntry = (id: string, obj: Record<string, unknown>): [string, string[]] => {
  const fields: string[] = [];
  Object.entries(obj).forEach(([k, v]) => {
    fields.push(k, JSON.stringify(v));
  });
  return [id, fields];
};
const liveEntry = (seq: number, notificationId: string) => buildEntry(`${1000 + seq}-0`, {
  version: '1',
  type: 'live',
  notification_id: notificationId,
  data: { id: `obj-${seq}` },
});

describe('rawFetchRangeNotifications (notification range pagination)', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('paginates with an exclusive cursor, stops on a short batch and keeps only live events', async () => {
    let callCount = 0;
    mockClient.call.mockImplementation((...args: unknown[]) => {
      const count = args[5] as number; // ['XRANGE', stream, startId, endId, 'COUNT', count]
      callCount += 1;
      if (callCount === 1) {
        // A full batch (== COUNT) forces another iteration.
        return Array.from({ length: count }, (_, i) => liveEntry(i, 'trigger-A'));
      }
      if (callCount === 2) {
        // A short batch ends the loop; the non-live entry must be filtered out.
        return [
          liveEntry(count, 'trigger-A'),
          buildEntry(`${1000 + count + 1}-0`, { version: '1', type: 'digest', notification_id: 'trigger-A' }),
        ];
      }
      return [];
    });

    const received: Array<{ event: StreamNotifEvent; byteSize: number }> = [];
    await fetchRangeNotifications<StreamNotifEvent>(new Date(1), new Date(2), (events) => {
      received.push(...events);
    });

    // Only two XRANGE calls: the short second batch ends iteration without an extra empty call.
    expect(mockClient.call).toHaveBeenCalledTimes(2);
    const firstCallArgs = mockClient.call.mock.calls[0];
    const secondCallArgs = mockClient.call.mock.calls[1];
    const batchSize = firstCallArgs[5] as number;

    // First call is inclusive of the start id and carries the COUNT batch size.
    expect(firstCallArgs[0]).toBe('XRANGE');
    expect(firstCallArgs[2]).toBe('1'); // new Date(1).getTime()
    expect(firstCallArgs[3]).toBe('2'); // new Date(2).getTime()
    expect(firstCallArgs[4]).toBe('COUNT');

    // Second call excludes the last id processed in the first batch (the '(' prefix).
    expect(secondCallArgs[2]).toBe(`(${1000 + (batchSize - 1)}-0`);

    // All live events are delivered; the 'digest' entry of the second batch is filtered out.
    expect(received).toHaveLength(batchSize + 1);
    expect(received.every((e) => e.event.type === 'live')).toBe(true);
    // Byte size comes from the raw stored fields (no re-serialization of the parsed object).
    const firstEntryFields = liveEntry(0, 'trigger-A')[1];
    const expectedFirstByteSize = firstEntryFields.reduce((acc, s) => acc + Buffer.byteLength(s), 0);
    expect(received[0].byteSize).toBe(expectedFirstByteSize);
  });

  it('does not duplicate or skip events sharing a timestamp across batch boundaries', async () => {
    // All entries share the millisecond '5' and differ only by sequence (5-0, 5-1, ...): the cursor
    // must advance on the full "ms-seq" id, not on the millisecond, otherwise it would re-read or skip.
    const sameTsEntry = (seq: number) => buildEntry(`5-${seq}`, {
      version: '1',
      type: 'live',
      notification_id: 'trigger-A',
      data: { id: `evt-${seq}` },
    });
    let batchSize = 0;
    let callCount = 0;
    mockClient.call.mockImplementation((...args: unknown[]) => {
      const count = args[5] as number;
      callCount += 1;
      if (callCount === 1) {
        batchSize = count;
        return Array.from({ length: count }, (_, i) => sameTsEntry(i)); // 5-0 .. 5-(N-1)
      }
      if (callCount === 2) {
        return [sameTsEntry(count), sameTsEntry(count + 1)]; // 5-N, 5-(N+1): short batch -> ends loop
      }
      return [];
    });

    const received: Array<{ event: StreamNotifEvent; byteSize: number }> = [];
    await fetchRangeNotifications<StreamNotifEvent>(new Date(0), new Date(10), (events) => {
      received.push(...events);
    });

    // The second XRANGE excludes the exact full id (ms-seq) of the last entry of the first batch.
    expect(mockClient.call.mock.calls[1][2]).toBe(`(5-${batchSize - 1}`);
    // Every event is delivered exactly once: no duplicate, no skip.
    const ids = received.map((e) => (e.event as unknown as { data: { id: string } }).data.id);
    expect(ids).toHaveLength(batchSize + 2);
    expect(new Set(ids).size).toBe(batchSize + 2);
  });

  it('stops early when the callback returns false', async () => {
    // Always return a full batch: without the early-stop the loop would never end.
    mockClient.call.mockImplementation((...args: unknown[]) => {
      const count = args[5] as number;
      return Array.from({ length: count }, (_, i) => liveEntry(i, 'trigger-A'));
    });

    let batches = 0;
    await fetchRangeNotifications(new Date(1), new Date(2), () => {
      batches += 1;
      return false;
    });

    expect(batches).toBe(1);
    expect(mockClient.call).toHaveBeenCalledTimes(1);
  });

  it('does not invoke the callback when the range is empty', async () => {
    mockClient.call.mockResolvedValue([]);
    const callback = vi.fn();
    await fetchRangeNotifications(new Date(1), new Date(2), callback);
    expect(callback).not.toHaveBeenCalled();
    expect(mockClient.call).toHaveBeenCalledTimes(1);
  });
});
