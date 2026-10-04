import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext } from '../../../../src/types/user';

const { deleteByQuery } = vi.hoisted(() => ({ deleteByQuery: vi.fn() }));

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elRawDeleteByQuery: deleteByQuery,
}));

const { purgeScorecardSnapshots, SNAPSHOT_PURGE_MAX_DOCS } = await import('../../../../src/modules/sourceIntelligence/sourceIntelligence-store');

describe('Source intelligence scorecard snapshots purge', () => {
  beforeEach(() => {
    deleteByQuery.mockReset();
  });

  it('should delete at most a bounded batch of expired snapshots per computation, never a live scorecard', async () => {
    deleteByQuery.mockResolvedValue({ deleted: SNAPSHOT_PURGE_MAX_DOCS });
    const now = new Date('2026-10-04T00:00:00.000Z').getTime();

    const deleted = await purgeScorecardSnapshots({} as AuthContext, 30, now);

    expect(deleted).toBe(SNAPSHOT_PURGE_MAX_DOCS);
    const [request] = deleteByQuery.mock.calls[0];
    expect(request.max_docs).toBe(SNAPSHOT_PURGE_MAX_DOCS);
    expect(request.body.query.bool.filter).toEqual([
      { term: { is_live: false } },
      { range: { 'snapshot_date.keyword': { lt: '2026-09-04' } } },
    ]);
  });
});
