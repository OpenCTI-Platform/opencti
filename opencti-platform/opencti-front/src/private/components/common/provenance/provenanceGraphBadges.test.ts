import { describe, expect, it } from 'vitest';
import { sourceConflictsGraphBadgeProvider, staleKnowledgeGraphBadgeProvider } from './provenanceGraphBadges';
import { badgesOfNode, graphBadgeProviders } from '../../../../components/graph/badges';
import { graphNode } from '../../../../utils/tests/graphTestData';

const helpers = { t_i18n: (message: string) => `t:${message}` };
type Raw = NonNullable<ReturnType<typeof graphNode>['raw']>;
const withRaw = (fields: Record<string, unknown>) => graphNode({ raw: fields as unknown as Raw });

describe('provenance graph badges', () => {
  it('is registered on every graph, one provider per state', () => {
    expect(graphBadgeProviders().map((provider) => provider.id)).toEqual(expect.arrayContaining(['provenance-stale', 'provenance-conflicts']));
  });

  it('flags stale knowledge and source conflicts, each with what it means', () => {
    const node = withRaw({ freshness_stale: true, has_conflicts: true });
    const [stale] = staleKnowledgeGraphBadgeProvider.badgesFor(node, helpers);
    const [conflicts] = sourceConflictsGraphBadgeProvider.badgesFor(node, helpers);
    expect(stale).toMatchObject({ key: 'provenance-stale', tone: 'warning', label: 't:Stale knowledge', tooltip: 't:No source has asserted it during the stale period' });
    expect(conflicts).toMatchObject({ key: 'provenance-conflicts', tone: 'error', label: 't:Has source conflicts', tooltip: 't:Its sources assert conflicting values' });
    expect(stale.icon && conflicts.icon).toBeTruthy();
  });

  it('returns nothing for fresh, consistent knowledge or when the graph did not fetch the fields', () => {
    const fresh = withRaw({ freshness_stale: false, has_conflicts: false });
    expect(staleKnowledgeGraphBadgeProvider.badgesFor(fresh, helpers)).toEqual([]);
    expect(sourceConflictsGraphBadgeProvider.badgesFor(fresh, helpers)).toEqual([]);
    expect(staleKnowledgeGraphBadgeProvider.badgesFor(withRaw({ freshness_stale: null }), helpers)).toEqual([]);
    expect(sourceConflictsGraphBadgeProvider.badgesFor(graphNode({ raw: undefined }), helpers)).toEqual([]);
  });

  it('puts a source conflict before stale knowledge, being more severe', () => {
    const keys = badgesOfNode(withRaw({ freshness_stale: true, has_conflicts: true }), helpers).map((badge) => badge.key);
    expect(keys.indexOf('provenance-conflicts')).toBeLessThan(keys.indexOf('provenance-stale'));
  });
});
