import { beforeEach, describe, expect, it, vi } from 'vitest';
import { commitRotationCursors, loadRotatingPage, MAX_ROTATING_PAGE_ATTEMPTS, rotationCursors } from '../../../../src/modules/curation/curation-scan';

const state = vi.hoisted(() => ({ redis: {} as Record<string, string> }));

vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/redis')>()),
  redisGetManagerEventState: vi.fn(async (key: string) => state.redis[key] ?? null),
  redisSetManagerEventState: vi.fn(async (key: string, value: string) => {
    state.redis[key] = value;
  }),
}));

const CURSOR_KEY = 'curation_scan_rotation_staleness_Malware';
const ATTEMPTS_KEY = 'curation_scan_rotation_attempts_staleness_Malware';

const pageAfter = (endCursor: string, hasNextPage = true) => vi.fn(async (_after: string | undefined) => ({
  edges: [{ node: { internal_id: 'malware-id' } }],
  pageInfo: { hasNextPage, endCursor },
}));

describe('rotating scan pages', () => {
  beforeEach(() => {
    state.redis = {};
  });

  it('moves the cursor once the scan commits it, so a page whose processing fails is read again at the next scan', async () => {
    state.redis[CURSOR_KEY] = 'cursor-1';
    const loadPage = pageAfter('cursor-2');
    const failed = rotationCursors();
    expect(await loadRotatingPage('staleness_Malware', failed, loadPage)).toEqual([{ internal_id: 'malware-id' }]);
    expect(state.redis[CURSOR_KEY]).toBe('cursor-1');
    const retried = rotationCursors();
    await loadRotatingPage('staleness_Malware', retried, loadPage);
    expect(loadPage.mock.calls.map(([after]) => after)).toEqual(['cursor-1', 'cursor-1']);
    await commitRotationCursors(retried);
    expect(state.redis[CURSOR_KEY]).toBe('cursor-2');
    expect(state.redis[ATTEMPTS_KEY]).toBe('0');
  });

  it('moves past a page before its last attempt, so a page whose processing always fails never blocks the pages after it', async () => {
    state.redis[CURSOR_KEY] = 'cursor-1';
    const loadPage = pageAfter('cursor-2');
    for (let attempt = 1; attempt < MAX_ROTATING_PAGE_ATTEMPTS; attempt += 1) {
      await loadRotatingPage('staleness_Malware', rotationCursors(), loadPage);
      expect(state.redis[CURSOR_KEY]).toBe('cursor-1');
    }
    const last = rotationCursors();
    await loadRotatingPage('staleness_Malware', last, loadPage);
    expect(loadPage).toHaveBeenCalledTimes(MAX_ROTATING_PAGE_ATTEMPTS);
    expect(state.redis[CURSOR_KEY]).toBe('cursor-2');
    expect(state.redis[ATTEMPTS_KEY]).toBe('0');
    expect(last.size).toBe(0);
  });

  it('goes back to the start after the last page, and starts over from a cursor that can no longer be resumed', async () => {
    state.redis[CURSOR_KEY] = 'stale-cursor';
    state.redis[ATTEMPTS_KEY] = String(MAX_ROTATING_PAGE_ATTEMPTS - 1);
    const lastPage = pageAfter('cursor-9', false);
    const loadPage = vi.fn(async (after: string | undefined) => {
      if (after) throw new Error('Cursor expired');
      return lastPage(after);
    });
    const cursors = rotationCursors();
    await loadRotatingPage('staleness_Malware', cursors, loadPage);
    expect(loadPage.mock.calls.map(([after]) => after)).toEqual(['stale-cursor', undefined]);
    expect(state.redis[ATTEMPTS_KEY]).toBe('1');
    await commitRotationCursors(cursors);
    expect(state.redis[CURSOR_KEY]).toBe('');
  });
});
