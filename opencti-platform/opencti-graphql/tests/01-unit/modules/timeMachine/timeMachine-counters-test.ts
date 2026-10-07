import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext } from '../../../../src/types/user';

// The search engine is canned: the shape of the batched aggregation and the reading of its buckets are under test.
const elRawSearchMock = vi.fn();
vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  buildDataRestrictions: async () => ({ must: [], must_not: [] }),
  elRawSearch: (...args: unknown[]) => elRawSearchMock(...args),
}));

import { countRelationshipsByTypeForElements } from '../../../../src/modules/timeMachine/timeMachine-counters';
import { SYSTEM_USER } from '../../../../src/utils/access';

describe('Relationship counts of a batch of elements', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('should count the relationships of every element by type with one aggregation', async () => {
    elRawSearchMock.mockResolvedValue({
      aggregations: {
        per_element: {
          buckets: {
            'element-a': { doc_count: 3, per_type: { buckets: [{ key: 'uses', doc_count: 2 }, { key: 'targets', doc_count: 1 }] } },
            'element-b': { doc_count: 0, per_type: { buckets: [] } },
          },
        },
      },
    });
    const counts = await countRelationshipsByTypeForElements({} as AuthContext, SYSTEM_USER, ['element-a', 'element-b'], '2026-01-01T00:00:00.000Z');
    expect(elRawSearchMock).toHaveBeenCalledTimes(1);
    const { body } = elRawSearchMock.mock.calls[0][3];
    expect(Object.keys(body.aggs.per_element.filters.filters)).toEqual(['element-a', 'element-b']);
    expect(body.query.bool.must).toContainEqual({ range: { created_at: { lte: '2026-01-01T00:00:00.000Z' } } });
    expect([...(counts.get('element-a') ?? new Map())]).toEqual([['uses', 2], ['targets', 1]]);
    expect(counts.get('element-b')?.size).toBe(0);
  });

  it('should not query the engine without elements', async () => {
    expect((await countRelationshipsByTypeForElements({} as AuthContext, SYSTEM_USER, [], '2026-01-01T00:00:00.000Z')).size).toBe(0);
    expect(elRawSearchMock).not.toHaveBeenCalled();
  });
});
