import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { computeVisibleDegreeMetrics, VISIBLE_DEGREE_MAX_PER_ENTITY } from '../../../../src/modules/graphAnalytics/graphAnalytics-store';
import { elAggregationSearch, elFindByIds, elList } from '../../../../src/database/engine';
import { GRAPH_ANALYTICS_MANAGER_USER } from '../../../../src/utils/access';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elAggregationSearch: vi.fn(),
  elList: vi.fn(),
  elFindByIds: vi.fn(),
}));

const context = { source: 'test', otp_mandatory: false } as unknown as AuthContext;
const bucket = (key: string, count: number) => ({ key, relationships: { doc_count: count, types: { buckets: [{ key: 'uses', doc_count: count }] } } });
const relation = (id: string, fromId: string, toId: string) => ({ internal_id: id, fromId, toId, relationship_type: 'uses' });

describe('graph analytics degree of a restricted reader', () => {
  beforeEach(() => {
    vi.mocked(elAggregationSearch).mockReset();
    vi.mocked(elList).mockReset();
    vi.mocked(elFindByIds).mockReset();
  });

  it('should only count relationships whose other end is accessible, and leave uncountable entities without a degree', async () => {
    vi.mocked(elAggregationSearch).mockResolvedValue({
      connections: { selected: { entities: { buckets: [bucket('a', 2), bucket('b', 1), bucket('hub', VISIBLE_DEGREE_MAX_PER_ENTITY + 1)] } } },
    } as never);
    // a uses the accessible x and the hidden y; b uses a
    vi.mocked(elList).mockResolvedValue([relation('r1', 'a', 'x'), relation('r2', 'a', 'y'), relation('r3', 'b', 'a')] as never);
    vi.mocked(elFindByIds).mockResolvedValue([{ internal_id: 'x' }] as never);
    const degrees = await computeVisibleDegreeMetrics(context, GRAPH_ANALYTICS_MANAGER_USER, ['a', 'b', 'hub', 'lonely']);
    expect(degrees.get('a')).toEqual({ degree: 2, degree_by_type: [{ relationship_type: 'uses', count: 2 }] });
    expect(degrees.get('b')).toEqual({ degree: 1, degree_by_type: [{ relationship_type: 'uses', count: 1 }] });
    expect(degrees.get('hub')).toBeNull();
    expect(degrees.get('lonely')).toEqual({ degree: 0, degree_by_type: [] });
    // the entity beyond the bound is never listed
    expect(elList).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(vi.mocked(elList).mock.calls[0][3])).not.toContain('hub');
  });
});
