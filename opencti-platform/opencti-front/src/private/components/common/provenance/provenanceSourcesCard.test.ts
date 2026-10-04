import { describe, expect, it } from 'vitest';
import { buildSourcesCardModel, groupConflictValues, groupProceduresByText, isAssertedOnce, type ProvenanceAssertion, type ProvenanceConflict } from './provenanceUtils';
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
    expect(model?.totalSourcesCount).toBe(7);
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
    expect(model?.totalSourcesCount).toBe(240);
  });

  it('only reports the labels of the fields that still have alternative values', () => {
    const value = { value_hash: 'h1', display: 'Other', adoptable: true, source_id: 's1', last_asserted_at: '2026-09-01T00:00:00.000Z' };
    const conflicts: ProvenanceConflict[] = [
      { field: 'x_opencti_description', field_label: 'Description', values: [value] },
      { field: 'primary_motivation', field_label: 'Primary motivation', values: [] },
      { field: 'x_custom_field', values: [value] },
    ];
    expect(buildSourcesCardModel([assertion('a', '2026-09-01T00:00:00.000Z')], conflicts)?.conflictingFields).toEqual(['Description', 'x_custom_field']);
  });
});

describe('isAssertedOnce', () => {
  it('compares the assertion instants, not their formatted dates', () => {
    expect(isAssertedOnce({ first_asserted_at: '2026-06-01T00:00:00.000Z', last_asserted_at: '2026-06-01T00:00:00Z' })).toBe(true);
    // Distinct assertions, although both read "3 months ago" at the end of September
    expect(isAssertedOnce({ first_asserted_at: '2026-06-01T00:00:00.000Z', last_asserted_at: '2026-06-20T00:00:00.000Z' })).toBe(false);
    expect(isAssertedOnce({ first_asserted_at: '2026-06-01T00:00:00.000Z', last_asserted_at: '2026-06-01T00:00:01.000Z' })).toBe(false);
  });
});

describe('groupConflictValues', () => {
  it('shows a value proposed by several sources once, with every proposal', () => {
    const proposal = (value_hash: string, source_id: string, adoptable = true) => ({
      value_hash, display: `Value ${value_hash}`, adoptable, source_id, source_name: `Source ${source_id}`, last_asserted_at: '2026-09-01T00:00:00.000Z',
    });
    const groups = groupConflictValues([proposal('h1', 'a', false), proposal('h2', 'a'), proposal('h1', 'b')]);
    expect(groups.map((group) => [group.value_hash, group.adoptable, group.proposals.map((value) => value.source_id)])).toEqual([
      ['h1', true, ['a', 'b']],
      ['h2', true, ['a']],
    ]);
  });
});

describe('groupProceduresByText', () => {
  it('shows a procedure asserted by several sources once, with every named source and the latest assertion', () => {
    const groups = groupProceduresByText([
      { text: 'Spearphishing attachment', source_id: 'a', last_asserted_at: '2026-09-01T00:00:00.000Z' },
      { text: ' spearphishing ATTACHMENT', source_id: 'b', last_asserted_at: '2026-09-03T00:00:00.000Z' },
      { text: 'Spearphishing attachment', source_id: 'unknown', last_asserted_at: '2026-09-02T00:00:00.000Z' },
      { text: 'Drive-by compromise', source_id: 'b', last_asserted_at: null },
    ], [assertion('a', '2026-09-01T00:00:00.000Z'), assertion('b', '2026-09-03T00:00:00.000Z')]);
    expect(groups).toEqual([
      { text: 'Spearphishing attachment', sourceNames: ['Source a', 'Source b'], lastAssertedAt: '2026-09-03T00:00:00.000Z' },
      { text: 'Drive-by compromise', sourceNames: ['Source b'], lastAssertedAt: null },
    ]);
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
