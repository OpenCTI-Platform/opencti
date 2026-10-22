import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { findGraphClusters, GRAPH_CLUSTERS_LIST_MAX, rankGraphClusters } from '../../../../src/modules/graphAnalytics/graphAnalytics-domain';
import { loadGraphClusters } from '../../../../src/modules/graphAnalytics/graphAnalytics-store';
import { elAggregationSearch, elList } from '../../../../src/database/engine';
import { SYSTEM_USER } from '../../../../src/utils/access';
import { READ_ENTITIES_INDICES } from '../../../../src/database/utils';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elAggregationSearch: vi.fn(),
  elList: vi.fn(),
}));
vi.mock('../../../../src/modules/graphAnalytics/graphAnalytics-store', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/graphAnalytics/graphAnalytics-store')>()),
  loadGraphClusters: vi.fn(),
}));

const context = { source: 'test', otp_mandatory: false } as unknown as AuthContext;
const cluster = (id: string) => ({ internal_id: id, name: `Cluster ${id}`, cluster_kind: 'infrastructure' });

describe('graph analytics cluster list', () => {
  beforeEach(() => {
    vi.mocked(elAggregationSearch).mockReset();
    vi.mocked(elList).mockReset();
    vi.mocked(loadGraphClusters).mockReset();
  });

  it('should rank the largest visible clusters in one aggregation and one search, whatever the number of clusters', async () => {
    vi.mocked(elAggregationSearch).mockResolvedValue({
      largest: { sum_other_doc_count: 42, buckets: [{ key: 'c-big', doc_count: 9 }, { key: 'c-small', doc_count: 3 }] },
    } as never);
    vi.mocked(elList).mockResolvedValue([cluster('c-small'), cluster('c-big')] as never);
    vi.mocked(loadGraphClusters).mockImplementation(async (_c, _u, ids) => ids.map((id) => cluster(id)) as never);
    const connection = await findGraphClusters(context, SYSTEM_USER, { first: 25 });
    expect(elAggregationSearch).toHaveBeenCalledTimes(1);
    expect(vi.mocked(elAggregationSearch).mock.calls[0][4]).toMatchObject({ largest: { terms: { size: GRAPH_CLUSTERS_LIST_MAX, shard_size: GRAPH_CLUSTERS_LIST_MAX } } });
    expect(elList).toHaveBeenCalledTimes(1);
    expect(connection.edges.map(({ node }) => [node.internal_id, node.members_count])).toEqual([['c-big', 9], ['c-small', 3]]);
    expect(connection.pageInfo.globalCount).toBe(2);
  });

  it('should find a cluster by the name of a representative the reader sees, its stored name being only a tooltip', async () => {
    vi.mocked(elAggregationSearch).mockResolvedValue({
      largest: { sum_other_doc_count: 0, buckets: [{ key: 'c-big', doc_count: 9 }, { key: 'c-small', doc_count: 3 }] },
    } as never);
    vi.mocked(elList).mockImplementation((async (_context: unknown, _user: unknown, indices: unknown, opts: { search?: string | null }) => {
      // the entities the reader can access that match the search, then the clusters by stored name, then all of them
      if (indices === READ_ENTITIES_INDICES) return [{ internal_id: 'apt28' }];
      if (opts.search) return [];
      return [{ ...cluster('c-big'), representative_ids: ['apt28'] }, { ...cluster('c-small'), representative_ids: ['other'] }];
    }) as never);
    vi.mocked(loadGraphClusters).mockImplementation(async (_c, _u, ids) => ids.map((id) => cluster(id)) as never);
    const connection = await findGraphClusters(context, SYSTEM_USER, { first: 25, search: 'Fancy Bear' });
    expect(vi.mocked(elList).mock.calls[0][3]).toMatchObject({ search: 'Fancy Bear' });
    expect(connection.edges.map(({ node }) => node.internal_id)).toEqual(['c-big']);
  });

  it('should never rank by the stored name, which readers do not see', () => {
    const entries = [{ id: 'b', members_count: 1, cluster: cluster('b') }, { id: 'a', members_count: 1, cluster: cluster('a') }] as never;
    expect(rankGraphClusters(entries, 'name')).toBe(entries);
  });

  it('should list nothing without visible members', async () => {
    vi.mocked(elAggregationSearch).mockResolvedValue({ largest: { sum_other_doc_count: 0, buckets: [] } } as never);
    const connection = await findGraphClusters(context, SYSTEM_USER, { first: 25 });
    expect(connection.edges).toEqual([]);
    expect(elList).not.toHaveBeenCalled();
  });
});
