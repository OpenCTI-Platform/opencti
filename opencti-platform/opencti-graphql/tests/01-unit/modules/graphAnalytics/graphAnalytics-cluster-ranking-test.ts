import { describe, expect, it } from 'vitest';
import { rankGraphClusters, type RankedGraphCluster } from '../../../../src/modules/graphAnalytics/graphAnalytics-domain';
import type { BasicStoreEntityGraphCluster } from '../../../../src/modules/graphAnalytics/graphAnalytics-types';
import { OrderingMode } from '../../../../src/generated/graphql';

const entry = (id: string, score: number, membersCount = 3): RankedGraphCluster => ({
  id,
  members_count: membersCount,
  cluster: { internal_id: id, name: `Cluster ${id}`, members_count: 99, sort: [score, `graph-cluster--${id}`] } as unknown as BasicStoreEntityGraphCluster,
});

describe('Graph clusters ranking', () => {
  it('should rank the search matches of every identifier chunk together by relevance', () => {
    // two chunks, each ranked by the engine within itself
    const firstChunk = [entry('a', 4.2), entry('b', 1.1)];
    const secondChunk = [entry('c', 9.7), entry('d', 2.5)];
    const ranked = rankGraphClusters([...firstChunk, ...secondChunk], '_score');
    expect(ranked.map((cluster) => cluster.id)).toEqual(['c', 'a', 'd', 'b']);
    const ascending = rankGraphClusters([...firstChunk, ...secondChunk], '_score', OrderingMode.Asc);
    expect(ascending.map((cluster) => cluster.id)).toEqual(['b', 'd', 'a', 'c']);
  });

  it('should rank by the visible members count, not the stored one, and break ties by id', () => {
    const ranked = rankGraphClusters([entry('b', 0, 5), entry('a', 0, 5), entry('c', 0, 12)], 'members_count');
    expect(ranked.map((cluster) => cluster.id)).toEqual(['c', 'a', 'b']);
  });

  it('should keep the order of the matches for an unknown ordering', () => {
    const entries = [entry('b', 1), entry('a', 2)];
    expect(rankGraphClusters(entries, 'unknown').map((cluster) => cluster.id)).toEqual(['b', 'a']);
  });
});
