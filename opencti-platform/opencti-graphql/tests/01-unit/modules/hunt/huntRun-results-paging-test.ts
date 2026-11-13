import { beforeEach, describe, expect, it, vi } from 'vitest';
import { internalFindByIds } from '../../../../src/database/middleware-loader';
import { findByIds } from '../../../../src/modules/hunt/hunt-loaders';
import { findHuntRunResultIds, findHuntRunResults } from '../../../../src/modules/hunt/huntRun/huntRun-domain';
import type { BasicStoreEntityHuntRun } from '../../../../src/modules/hunt/huntRun/huntRun-types';
import type { AuthUser } from '../../../../src/types/user';
import type { BasicStoreObject } from '../../../../src/types/store';
import { testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  internalFindByIds: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-loaders', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-loaders')>(),
  findByIds: vi.fn(),
}));

const RESULT_COUNT = 120;
const resultIds = Array.from({ length: RESULT_COUNT }, (_, index) => `indicator--${index}`);
// The reader cannot read every tenth result
const readable = resultIds.filter((_, index) => index % 10 !== 0)
  .map((standardId) => ({ internal_id: `internal-${standardId}`, standard_id: standardId }) as BasicStoreObject);

const run = (updatedAt: string) => ({
  internal_id: 'run-paging',
  result_ids: resultIds,
  updated_at: updatedAt,
}) as unknown as BasicStoreEntityHuntRun;

const reader = (id: string) => ({ id, internal_id: id }) as AuthUser;

describe('Hunt run results paging', () => {
  beforeEach(() => {
    vi.mocked(internalFindByIds).mockReset();
    vi.mocked(internalFindByIds).mockResolvedValue(readable as never);
    vi.mocked(findByIds).mockReset();
    vi.mocked(findByIds).mockImplementation(async (_context, _user, ids) => ids.map((id) => ({ internal_id: id }) as BasicStoreObject) as never);
  });

  it('should resolve the access to the results again for every page a reader reads', async () => {
    const user = reader('user-paging');
    const current = run('2026-10-05T03:00:00.000Z');
    const pages = [];
    let after: string | null = null;
    do {
      const page = await findHuntRunResults(testContext, user, current, 25, after);
      pages.push(page);
      after = page.pageInfo.hasNextPage ? page.pageInfo.endCursor : null;
    } while (after);
    expect(pages.length).toBe(5);
    expect(pages[0].pageInfo.globalCount).toBe(readable.length);
    expect(pages.flatMap((page) => page.edges.map((edge) => edge.node.internal_id))).toEqual(readable.map((element) => element.internal_id));
    expect(await findHuntRunResultIds(testContext, user, current)).toEqual(readable.map((element) => element.standard_id));
    // An access change applies to the next page: no access resolution outlives the call that made it
    expect(internalFindByIds).toHaveBeenCalledTimes(pages.length + 1);
    // Every page loads its own objects with the access of the reader
    expect(findByIds).toHaveBeenCalledTimes(5);
  });

  it('should continue after the objects deleted or hidden since the readable ids were resolved', async () => {
    const user = reader('user-stale');
    const current = run('2026-10-05T03:20:00.000Z');
    const gone = new Set(readable.slice(25, 50).map((element) => element.internal_id));
    vi.mocked(findByIds).mockImplementation(async (_context, _user, ids) => ids.filter((id) => !gone.has(id)).map((id) => ({ internal_id: id }) as BasicStoreObject) as never);
    const pages = [];
    let after: string | null = null;
    do {
      const page = await findHuntRunResults(testContext, user, current, 25, after);
      pages.push(page);
      after = page.pageInfo.hasNextPage ? page.pageInfo.endCursor : null;
    } while (after);
    expect(pages.length).toBe(5);
    expect(pages[1].edges).toEqual([]);
    expect(pages[1].pageInfo.endCursor).toEqual(readable[49].internal_id);
    expect(pages.flatMap((page) => page.edges.map((edge) => edge.node.internal_id)))
      .toEqual(readable.map((element) => element.internal_id).filter((id) => !gone.has(id)));
  });

  it('should resolve the access again for another reader and for a new version of the run', async () => {
    await findHuntRunResults(testContext, reader('user-a'), run('2026-10-05T03:10:00.000Z'), 25);
    await findHuntRunResults(testContext, reader('user-b'), run('2026-10-05T03:10:00.000Z'), 25);
    await findHuntRunResults(testContext, reader('user-a'), run('2026-10-05T03:11:00.000Z'), 25);
    expect(internalFindByIds).toHaveBeenCalledTimes(3);
  });
});
