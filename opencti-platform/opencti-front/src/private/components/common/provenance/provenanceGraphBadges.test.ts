import { describe, expect, it } from 'vitest';
import { provenanceGraphBadgeProvider } from './provenanceGraphBadges';
import { badgesOfNode, graphBadgeProviders } from '../../../../components/graph/badges';
import { graphNode } from '../../../../utils/tests/graphTestData';

const helpers = { t_i18n: (message: string) => `t:${message}` };
type Raw = NonNullable<ReturnType<typeof graphNode>['raw']>;
const withRaw = (fields: Record<string, unknown>) => graphNode({ raw: fields as unknown as Raw });

describe('provenance graph badges', () => {
  it('is registered on every graph', () => {
    expect(graphBadgeProviders().map((provider) => provider.id)).toContain('provenance');
  });

  it('flags stale knowledge and source conflicts', () => {
    const badges = provenanceGraphBadgeProvider.badgesFor(withRaw({ freshness_stale: true, has_conflicts: true }), helpers);
    expect(badges.map(({ key, tone, label }) => ({ key, tone, label }))).toEqual([
      { key: 'provenance-stale', tone: 'warning', label: 't:Stale knowledge' },
      { key: 'provenance-conflicts', tone: 'error', label: 't:Has source conflicts' },
    ]);
    expect(badges.every((badge) => badge.icon)).toBe(true);
  });

  it('returns nothing for fresh, consistent knowledge or when the graph did not fetch the fields', () => {
    expect(provenanceGraphBadgeProvider.badgesFor(withRaw({ freshness_stale: false, has_conflicts: false }), helpers)).toEqual([]);
    expect(provenanceGraphBadgeProvider.badgesFor(withRaw({ freshness_stale: null }), helpers)).toEqual([]);
    expect(provenanceGraphBadgeProvider.badgesFor(graphNode({ raw: undefined }), helpers)).toEqual([]);
  });

  it('draws its badges after the built-in ones', () => {
    const keys = badgesOfNode(withRaw({ freshness_stale: true }), helpers).map((badge) => badge.key);
    expect(keys[keys.length - 1]).toBe('provenance-stale');
  });
});
