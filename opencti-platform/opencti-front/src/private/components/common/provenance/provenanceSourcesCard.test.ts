import { describe, expect, it } from 'vitest';
import { buildSourcesCardModel, type ProvenanceAssertion, type ProvenanceConflict } from './provenanceUtils';
import { PROVENANCE_SOURCE_LINK_RESOLVERS, type ProvenanceSourceLinkResolver, resolveProvenanceSourceLink } from './provenanceSourceLinks';

const assertion = (source_id: string, last_asserted_at: string, source_kind = 'connector'): ProvenanceAssertion => ({
  source_id,
  source_kind,
  source_name: `Source ${source_id}`,
  first_asserted_at: '2026-01-01T00:00:00.000Z',
  last_asserted_at,
  assert_count: 1,
  confidence: 50,
});

describe('buildSourcesCardModel', () => {
  it('returns null when no source asserted the element', () => {
    expect(buildSourcesCardModel(null, null)).toBeNull();
    expect(buildSourcesCardModel([], [{ field: 'description', values: [] }])).toBeNull();
  });

  it('lists the most recent sources first and counts the sources left to the panel', () => {
    const assertions = ['01', '02', '03', '04', '05', '06', '07'].map((day) => assertion(`s${day}`, `2026-09-${day}T00:00:00.000Z`));
    const model = buildSourcesCardModel(assertions, null);
    expect(model?.sources.map((source) => source.source_id)).toEqual(['s07', 's06', 's05', 's04', 's03']);
    expect(model?.hiddenSourcesCount).toBe(2);
    expect(model?.conflictingFields).toEqual([]);
  });

  it('keeps every source under the limit', () => {
    const model = buildSourcesCardModel([assertion('a', '2026-09-01T00:00:00.000Z'), assertion('b', '2026-09-02T00:00:00.000Z')], null, 2, 5);
    expect(model?.sources.map((source) => source.source_id)).toEqual(['b', 'a']);
    expect(model?.hiddenSourcesCount).toBe(0);
  });

  it('counts the sources whose detail is no longer kept among the sources left to the panel', () => {
    const model = buildSourcesCardModel([assertion('a', '2026-09-01T00:00:00.000Z'), assertion('b', '2026-09-02T00:00:00.000Z')], null, 240, 1);
    expect(model?.sources.map((source) => source.source_id)).toEqual(['b']);
    expect(model?.hiddenSourcesCount).toBe(239);
  });

  it('only reports the fields that still have alternative values', () => {
    const conflicts: ProvenanceConflict[] = [
      { field: 'description', values: [{ value_hash: 'h1', display: 'Other', adoptable: true, source_id: 's1', last_asserted_at: '2026-09-01T00:00:00.000Z' }] },
      { field: 'primary_motivation', values: [] },
    ];
    expect(buildSourcesCardModel([assertion('a', '2026-09-01T00:00:00.000Z')], conflicts)?.conflictingFields).toEqual(['description']);
  });
});

describe('resolveProvenanceSourceLink', () => {
  it('links an author source to its entity and leaves other kinds unlinked by default', () => {
    expect(resolveProvenanceSourceLink(assertion('org-1', '2026-09-01T00:00:00.000Z', 'author'))).toBe('/dashboard/id/org-1');
    expect(resolveProvenanceSourceLink(assertion('connector-1', '2026-09-01T00:00:00.000Z', 'connector'))).toBeNull();
    expect(resolveProvenanceSourceLink(assertion('user-1', '2026-09-01T00:00:00.000Z', 'user'))).toBeNull();
  });

  it('uses the first resolver returning a link', () => {
    const scorecard: ProvenanceSourceLinkResolver = (source) => (source.source_kind === 'connector' ? `/scorecard/${source.source_id}` : null);
    const resolvers = [scorecard, ...PROVENANCE_SOURCE_LINK_RESOLVERS];
    expect(resolveProvenanceSourceLink(assertion('connector-1', '2026-09-01T00:00:00.000Z'), resolvers)).toBe('/scorecard/connector-1');
    expect(resolveProvenanceSourceLink(assertion('org-1', '2026-09-01T00:00:00.000Z', 'author'), resolvers)).toBe('/dashboard/id/org-1');
    expect(resolveProvenanceSourceLink(assertion('feed-1', '2026-09-01T00:00:00.000Z', 'feed'), [])).toBeNull();
  });
});
