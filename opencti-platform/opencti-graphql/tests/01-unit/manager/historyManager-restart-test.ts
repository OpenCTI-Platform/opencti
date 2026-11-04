import { describe, expect, it, vi } from 'vitest';
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/fixed';
import { createStreamProcessor } from '../../../src/database/stream/stream-handler';
import { topEntitiesList } from '../../../src/database/middleware-loader';
import { lockResources } from '../../../src/lock/master-lock';
import historyManager, { type HistoryData } from '../../../src/manager/historyManager';
import { ENTITY_TYPE_HISTORY } from '../../../src/schema/internalObject';
import { INDEX_HISTORY } from '../../../src/database/utils';
import { FilterMode, FilterOperator, OrderingMode } from '../../../src/generated/graphql';

vi.mock('set-interval-async/fixed', () => ({
  setIntervalAsync: vi.fn(() => ({})),
  clearIntervalAsync: vi.fn(async () => {}),
}));

vi.mock('../../../src/database/stream/stream-handler', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../src/database/stream/stream-handler')>(),
  createStreamProcessor: vi.fn(),
}));

vi.mock('../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../src/database/middleware-loader')>(),
  topEntitiesList: vi.fn(),
}));

vi.mock('../../../src/lock/master-lock', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../src/lock/master-lock')>(),
  lockResources: vi.fn(),
}));

describe('History manager restart', () => {
  it('resumes from the latest indexed event after the stream stops', async () => {
    const unlock = vi.fn(async () => {});
    vi.mocked(lockResources).mockResolvedValue({ signal: new AbortController().signal, unlock });
    vi.mocked(topEntitiesList)
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([{ timestamp: '2026-09-10T12:34:56.789Z' } as HistoryData]);

    const starts: Array<ReturnType<typeof vi.fn<(eventId: string | undefined) => Promise<void>>>> = [];
    const shutdowns: Array<ReturnType<typeof vi.fn<() => Promise<void>>>> = [];
    vi.mocked(createStreamProcessor).mockImplementation(() => {
      const start = vi.fn(async (_eventId: string | undefined) => {});
      const shutdown = vi.fn(async () => {});
      starts.push(start);
      shutdowns.push(shutdown);
      return { start, shutdown, running: () => false, info: async () => ({}) };
    });

    await historyManager.start();
    try {
      expect(topEntitiesList).not.toHaveBeenCalled();
      const tick = vi.mocked(setIntervalAsync).mock.calls[0][0];
      await tick();
      await tick();

      expect(topEntitiesList).toHaveBeenCalledTimes(2);
      expect(topEntitiesList).toHaveBeenCalledWith(
        expect.anything(),
        expect.anything(),
        [ENTITY_TYPE_HISTORY],
        expect.objectContaining({
          first: 1,
          indices: [INDEX_HISTORY],
          orderBy: ['timestamp'],
          orderMode: OrderingMode.Desc,
          filters: {
            mode: FilterMode.And,
            filters: [{ key: ['event_access'], values: [], operator: FilterOperator.Nil }],
            filterGroups: [],
          },
        }),
      );
      expect(lockResources).toHaveBeenCalledTimes(2);
      expect(vi.mocked(lockResources).mock.invocationCallOrder[0]).toBeLessThan(vi.mocked(topEntitiesList).mock.invocationCallOrder[0]);
      expect(vi.mocked(lockResources).mock.invocationCallOrder[1]).toBeLessThan(vi.mocked(topEntitiesList).mock.invocationCallOrder[1]);
      expect(starts).toHaveLength(2);
      expect(starts[0]).toHaveBeenCalledWith('0-0');
      expect(starts[1]).toHaveBeenCalledWith('1789043696000-0');
      expect(shutdowns[0]).toHaveBeenCalledOnce();
      expect(shutdowns[1]).toHaveBeenCalledOnce();
      expect(unlock).toHaveBeenCalledTimes(2);
    } finally {
      await historyManager.shutdown();
      expect(clearIntervalAsync).toHaveBeenCalledOnce();
    }
  });
});
