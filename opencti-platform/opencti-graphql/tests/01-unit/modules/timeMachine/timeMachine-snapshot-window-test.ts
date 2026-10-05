import { afterEach, describe, expect, it, vi } from 'vitest';

// The manager state, the history index and the retention are canned: the bounds of the snapshot windows are under test.
const redisGetManagerEventStateMock = vi.fn();
const redisSetManagerEventStateMock = vi.fn();
vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/redis')>()),
  redisGetManagerEventState: (...args: unknown[]) => redisGetManagerEventStateMock(...args),
  redisSetManagerEventState: (...args: unknown[]) => redisSetManagerEventStateMock(...args),
}));
const elRawSearchMock = vi.fn();
vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elRawSearch: (...args: unknown[]) => elRawSearchMock(...args),
}));
vi.mock('../../../../src/modules/retentionRules/retentionRules-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/retentionRules/retentionRules-domain')>()),
  listRules: () => Promise.resolve([]),
}));

import { nextWindowStart, snapshotHandler } from '../../../../src/manager/snapshotManager';

const DAY_MS = 24 * 3600 * 1000;
const MARGIN_MS = 60000;

// The watermark aggregation answers the newest history event; the changed elements aggregations find nothing
const cannedHistoryIndex = (watermark: string | null) => {
  elRawSearchMock.mockImplementation((_context: unknown, _user: unknown, _type: unknown, { body }: { body: any }) => {
    if (body.aggs?.watermark) {
      return Promise.resolve({ aggregations: { watermark: { value: watermark ? Date.parse(watermark) : null } } });
    }
    return Promise.resolve({ aggregations: { elements: { buckets: [] } } });
  });
};

const writtenState = () => JSON.parse(redisSetManagerEventStateMock.mock.calls[0][1]);

describe('Snapshot window bounds', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('should start the next window below the history watermark, never back and never without one', () => {
    const cursor = '2026-09-01T00:00:00.000Z';
    expect(nextWindowStart(cursor, '2026-09-08T00:00:00.000Z')).toBe('2026-09-07T23:59:00.000Z');
    expect(nextWindowStart(cursor, '2026-09-01T00:00:30.000Z')).toBe(cursor);
    expect(nextWindowStart(cursor, null)).toBe(cursor);
  });

  it('should read again the events of a window that the history manager had not indexed yet', async () => {
    const lastWindowEnd = new Date(Date.now() - 8 * DAY_MS).toISOString();
    const watermark = new Date(Date.now() - 3600000).toISOString();
    redisGetManagerEventStateMock.mockResolvedValue(JSON.stringify({ cursor: lastWindowEnd, last_window_end: lastWindowEnd }));
    cannedHistoryIndex(watermark);
    await snapshotHandler();
    // The watermark is measured before the changed elements are read
    expect(elRawSearchMock.mock.calls[0][3].body.aggs.watermark).toBeDefined();
    expect(elRawSearchMock.mock.calls[1][3].body.aggs.elements).toBeDefined();
    const state = writtenState();
    expect(state.cursor).toBe(new Date(Date.parse(watermark) - MARGIN_MS).toISOString());
    expect(Math.abs(Date.parse(state.last_window_end) - Date.now())).toBeLessThan(60000);
  });

  it('should keep the weekly schedule on the end of the last window, whatever the lower bound of the next one', async () => {
    const lastWindowEnd = new Date(Date.now() - DAY_MS).toISOString();
    const cursor = new Date(Date.now() - 10 * DAY_MS).toISOString();
    redisGetManagerEventStateMock.mockResolvedValue(JSON.stringify({ cursor, last_window_end: lastWindowEnd }));
    cannedHistoryIndex(null);
    await snapshotHandler();
    expect(elRawSearchMock).not.toHaveBeenCalled();
    expect(redisSetManagerEventStateMock).not.toHaveBeenCalled();
  });

  it('should keep the lower bound in place when no history event is searchable', async () => {
    const cursor = new Date(Date.now() - 8 * DAY_MS).toISOString();
    redisGetManagerEventStateMock.mockResolvedValue(JSON.stringify({ cursor }));
    cannedHistoryIndex(null);
    await snapshotHandler();
    expect(writtenState().cursor).toBe(cursor);
  });
});
