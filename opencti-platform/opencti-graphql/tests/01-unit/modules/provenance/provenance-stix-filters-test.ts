import { describe, expect, it } from 'vitest';
import { FilterMode, FilterOperator } from '../../../../src/generated/graphql';
import { buildProvenanceStixExtension, withProvenanceStixExtension } from '../../../../src/modules/provenance/provenance-stix';
import { adaptFilterToFreshnessDaysFilterKey, buildFreshnessDaysSorting } from '../../../../src/modules/provenance/provenance-filters';
import { computeFreshnessDays, describeProposalSource } from '../../../../src/modules/provenance/provenance-domain';
import { STIX_EXT_OCTI_PROVENANCE } from '../../../../src/types/stix-2-1-extensions';
import type { StoreAssertion } from '../../../../src/modules/provenance/provenance-types';

const assertion = (sourceId: string, kind: StoreAssertion['source_kind'], first: string, last: string, count: number): StoreAssertion => ({
  source_id: sourceId,
  source_kind: kind,
  source_name: `Source ${sourceId}`,
  first_asserted_at: first,
  last_asserted_at: last,
  assert_count: count,
  confidence: 50,
  work_id: null,
});

describe('Provenance STIX extension', () => {
  it('should summarize assertions without any source identity', () => {
    const extension = buildProvenanceStixExtension({
      entity_type: 'Malware',
      x_opencti_assertions: [
        assertion('a', 'connector', '2026-01-01T00:00:00.000Z', '2026-09-01T00:00:00.000Z', 3),
        assertion('b', 'user', '2025-06-01T00:00:00.000Z', '2026-02-01T00:00:00.000Z', 1),
      ],
      x_opencti_conflicts: [{ field: 'description', values: [{ value_hash: 'h', display: 'x', value: '"x"', source_id: 'b', source_kind: 'user', source_name: 'jane@acme.io', confidence: 10, last_asserted_at: '2026-02-01T00:00:00.000Z' }] }],
      freshness_stale: false,
    });
    expect(extension).toEqual({
      extension_type: 'property-extension',
      corroboration_count: 2,
      assertions_count: 4,
      first_asserted: '2025-06-01T00:00:00.000Z',
      last_asserted: '2026-09-01T00:00:00.000Z',
      single_sourced: false,
      has_conflicts: true,
      conflicting_fields: ['description'],
      freshness_stale: false,
      sources_by_kind: { connector: 1, feed: 0, author: 0, user: 1, inference: 0, emulation: 0 },
    });
    expect(JSON.stringify(extension)).not.toContain('jane@acme.io');
    expect(JSON.stringify(extension)).not.toContain('Source a');
  });

  it('should count the sources whose detail is no longer kept', () => {
    const extension = buildProvenanceStixExtension({
      entity_type: 'Malware',
      x_opencti_assertions: [assertion('a', 'connector', '2026-01-01T00:00:00.000Z', '2026-09-01T00:00:00.000Z', 3)],
      corroboration_count: 240,
    });
    expect(extension?.corroboration_count).toEqual(240);
    expect(extension?.single_sourced).toEqual(false);
    const single = buildProvenanceStixExtension({
      entity_type: 'Malware',
      x_opencti_assertions: [assertion('a', 'connector', '2026-01-01T00:00:00.000Z', '2026-09-01T00:00:00.000Z', 3)],
    });
    expect(single?.corroboration_count).toEqual(1);
    expect(single?.single_sourced).toEqual(true);
  });

  it('should leave elements without provenance untouched', () => {
    const stix: { id: string; extensions: Record<string, unknown> } = { id: 'malware--1', extensions: { other: {} } };
    expect(withProvenanceStixExtension({ entity_type: 'Malware' }, stix)).toBe(stix);
    const enriched = withProvenanceStixExtension({
      entity_type: 'Malware',
      x_opencti_assertions: [assertion('a', 'feed', '2026-01-01T00:00:00.000Z', '2026-01-02T00:00:00.000Z', 1)],
    }, stix);
    expect(enriched.extensions[STIX_EXT_OCTI_PROVENANCE]).toMatchObject({ corroboration_count: 1, single_sourced: true });
    expect(enriched.extensions.other).toEqual({});
  });
});

describe('Provenance freshness', () => {
  const reference = new Date('2026-10-03T12:00:00.000Z');

  it('should compute the days since the last assertion', () => {
    expect(computeFreshnessDays('2026-10-03T00:00:00.000Z', reference)).toEqual(0);
    expect(computeFreshnessDays('2026-10-01T11:00:00.000Z', reference)).toEqual(2);
    expect(computeFreshnessDays(null, reference)).toBeNull();
    expect(computeFreshnessDays('not a date', reference)).toBeNull();
  });

  it('should convert freshness comparisons to last assertion ranges', () => {
    const gte = adaptFilterToFreshnessDaysFilterKey({ key: ['freshness_days'], values: ['30'], operator: FilterOperator.Gte }, reference);
    expect(gte.newFilterGroup.filterGroups[0].filters).toEqual([
      { key: ['last_asserted_at'], values: ['2026-09-03T12:00:00.000Z'], operator: FilterOperator.Lte, mode: FilterMode.Or },
    ]);
    const lt = adaptFilterToFreshnessDaysFilterKey({ key: ['freshness_days'], values: ['7'], operator: FilterOperator.Lt }, reference);
    expect(lt.newFilterGroup.filterGroups[0].filters[0]).toMatchObject({ operator: FilterOperator.Gt, values: ['2026-09-26T12:00:00.000Z'] });
    const eq = adaptFilterToFreshnessDaysFilterKey({ key: ['freshness_days'], values: ['1'], operator: FilterOperator.Eq }, reference);
    expect(eq.newFilterGroup.filterGroups[0].mode).toEqual(FilterMode.And);
    expect(eq.newFilterGroup.filterGroups[0].filters).toHaveLength(2);
    const nil = adaptFilterToFreshnessDaysFilterKey({ key: ['freshness_days'], values: [], operator: FilterOperator.Nil }, reference);
    expect(nil.newFilterGroup.filters).toEqual([{ key: ['last_asserted_at'], values: [], operator: FilterOperator.Nil }]);
  });

  it('should reject invalid freshness values', () => {
    expect(() => adaptFilterToFreshnessDaysFilterKey({ key: ['freshness_days'], values: ['abc'], operator: FilterOperator.Gt }, reference)).toThrow();
    expect(() => adaptFilterToFreshnessDaysFilterKey({ key: ['freshness_days'], values: ['-1'], operator: FilterOperator.Gt }, reference)).toThrow();
    expect(() => adaptFilterToFreshnessDaysFilterKey({ key: ['freshness_days'], values: ['7days'], operator: FilterOperator.Gt }, reference)).toThrow();
    expect(() => adaptFilterToFreshnessDaysFilterKey({ key: ['freshness_days'], values: ['1.9'], operator: FilterOperator.Gt }, reference)).toThrow();
  });

  it('should sort fresh first when ascending', () => {
    expect(buildFreshnessDaysSorting('asc')).toEqual({ last_asserted_at: { order: 'desc', missing: 0 } });
    expect(buildFreshnessDaysSorting('desc')).toEqual({ last_asserted_at: { order: 'asc', missing: 0 } });
  });

  it('should never write user or author names in history messages', () => {
    expect(describeProposalSource({ source_kind: 'user', source_name: 'Jane Analyst', source_id: 'user-id' })).toEqual('a user source');
    expect(describeProposalSource({ source_kind: 'author', source_name: 'ACME', source_id: 'identity-id' })).toEqual('an author source');
    expect(describeProposalSource({ source_kind: 'feed', source_name: 'Abuse feed', source_id: 'feed-id' })).toEqual('`Abuse feed`');
  });
});
