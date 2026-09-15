import { describe, expect, it } from 'vitest';
import { remapUserInJsonValue, remapUserInJsonString } from '../../../../src/modules/userMerge/userMerge-jsonRemap';
import {
  USER_MERGE_FILTER_ACKNOWLEDGED_ROWS,
  USER_MERGE_FILTER_TARGETS,
  userMergeFilterCoveredRows,
  userMergeFilterFieldPaths,
} from '../../../../src/modules/userMerge/userMerge-filterTargets';
import { USER_MERGE_REGISTER } from '../../../../src/modules/userMerge/userMerge-register';
import { rewriteUserInPirCriteria } from '../../../../src/modules/userMerge/userMerge-filtersHandler';

interface PirCriterion { filters: string; weight: number }

const SOURCE = 'aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa';
const TARGET = 'bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb';
const OTHER = 'cccccccc-3333-4333-8333-cccccccccccc';

const filterGroup = (values: unknown[], key = 'creator_id') => JSON.stringify({
  mode: 'and',
  filters: [{ key: [key], values, operator: 'eq', mode: 'or' }],
  filterGroups: [],
});

describe('userMerge filter remapping', () => {
  it('should rewrite the source id where it is a filter value', () => {
    const result = remapUserInJsonString(filterGroup([SOURCE]), SOURCE, TARGET);
    expect(result.changed).toBe(true);
    expect(result.parsed).toBe(true);
    expect(result.counters).toEqual({ rewritten: 1, deduplicated: 0 });
    expect(JSON.parse(result.json).filters[0].values).toEqual([TARGET]);
  });

  it('should leave the other users of the same filter alone', () => {
    const result = remapUserInJsonString(filterGroup([OTHER, SOURCE]), SOURCE, TARGET);
    expect(JSON.parse(result.json).filters[0].values).toEqual([OTHER, TARGET]);
  });

  // A filter naming both users must not end up holding the target id twice: computePirScore
  // divides by the sum of every criterion weight, and the UI keys its filter chips by value.
  it('should collapse the repetition the rewrite creates, whichever order the two ids are in', () => {
    const forward = remapUserInJsonString(filterGroup([SOURCE, TARGET]), SOURCE, TARGET);
    expect(JSON.parse(forward.json).filters[0].values).toEqual([TARGET]);
    expect(forward.counters.deduplicated).toEqual(1);
    const backward = remapUserInJsonString(filterGroup([TARGET, SOURCE]), SOURCE, TARGET);
    expect(JSON.parse(backward.json).filters[0].values).toEqual([TARGET]);
    expect(backward.counters.deduplicated).toEqual(1);
  });

  // A list touched by the merge comes out canonical: a repetition that predated the rewrite is
  // collapsed too, rather than leaving the list half-cleaned.
  it('should collapse a repetition that predated the rewrite', () => {
    const raw = filterGroup([TARGET, TARGET, SOURCE]);
    const result = remapUserInJsonString(raw, SOURCE, TARGET);
    expect(JSON.parse(result.json).filters[0].values).toEqual([TARGET]);
    expect(result.counters.deduplicated).toEqual(2);
  });

  it('should leave a list it did not rewrite untouched, repetition included', () => {
    const raw = filterGroup([TARGET, TARGET]);
    const result = remapUserInJsonString(raw, SOURCE, TARGET);
    expect(result.changed).toBe(false);
    expect(result.json).toEqual(raw);
  });

  it('should reach the values nested in a sub-group', () => {
    const raw = JSON.stringify({
      mode: 'and',
      filters: [],
      filterGroups: [{ mode: 'or', filters: [{ key: ['creator_id'], values: [SOURCE], operator: 'eq', mode: 'or' }], filterGroups: [] }],
    });
    const result = remapUserInJsonString(raw, SOURCE, TARGET);
    expect(JSON.parse(result.json).filterGroups[0].filters[0].values).toEqual([TARGET]);
  });

  // regardingOf and dynamicFrom carry filter objects as values, not plain ids.
  it('should reach the values nested in a composite key', () => {
    const raw = filterGroup([{ key: 'creator_id', values: [SOURCE] }], 'regardingOf');
    const result = remapUserInJsonString(raw, SOURCE, TARGET);
    expect(JSON.parse(result.json).filters[0].values[0].values).toEqual([TARGET]);
  });

  it('should say nothing changed when the id is absent', () => {
    const raw = filterGroup([OTHER]);
    const result = remapUserInJsonString(raw, SOURCE, TARGET);
    expect(result).toEqual({ json: raw, changed: false, parsed: true, counters: { rewritten: 0, deduplicated: 0 } });
  });

  // A filter combining the user with a numeric or boolean criterion — confidence, score, revoked.
  it('should walk past a value that is neither a string nor a structure', () => {
    const raw = JSON.stringify({
      mode: 'and',
      filters: [
        { key: ['creator_id'], values: [SOURCE], operator: 'eq', mode: 'or' },
        { key: ['confidence'], values: [50, true, null], operator: 'gt', mode: 'or' },
      ],
      filterGroups: [],
    });
    const result = remapUserInJsonString(raw, SOURCE, TARGET);
    expect(result.changed).toBe(true);
    const filters = JSON.parse(result.json).filters;
    expect(filters[0].values).toEqual([TARGET]);
    expect(filters[1].values).toEqual([50, true, null]);
  });

  // The two are reported apart by the handler, because they call for opposite follow-ups.
  it('should tell an unreadable filter from one mentioning the id as free text', () => {
    const broken = remapUserInJsonString(`{ not json ${SOURCE}`, SOURCE, TARGET);
    expect(broken).toMatchObject({ changed: false, parsed: false });
    const textual = remapUserInJsonString(filterGroup([`created by ${SOURCE}`], 'name'), SOURCE, TARGET);
    expect(textual).toMatchObject({ changed: false, parsed: true });
  });

  it('should be a no-op on replay', () => {
    const once = remapUserInJsonString(filterGroup([SOURCE]), SOURCE, TARGET);
    const twice = remapUserInJsonString(once.json, SOURCE, TARGET);
    expect(twice.changed).toBe(false);
    expect(twice.json).toEqual(once.json);
  });

  it('should remap an already parsed filter group without serializing it', () => {
    const parsed = { mode: 'and', filters: [{ key: ['creator_id'], values: [SOURCE] }], filterGroups: [] };
    const result = remapUserInJsonValue(parsed, SOURCE, TARGET);
    expect(result.changed).toBe(true);
    expect(result.payload.filters[0].values).toEqual([TARGET]);
  });
});

describe('userMerge PIR criteria remapping', () => {
  const target = USER_MERGE_FILTER_TARGETS.find((entry) => entry.shape === 'criteria-array')!;
  const candidateOf = (criteria: unknown[]) => ({ id: 'pir-1', index: 'opencti_internal_objects', source: { [target.path]: criteria } });

  it('should remap each criterion filter in place', () => {
    const result = rewriteUserInPirCriteria(candidateOf([{ filters: filterGroup([SOURCE]), weight: 3 }]), target, SOURCE, TARGET);
    expect(result).toMatchObject({ mergedCriteria: 0 });
    const criteria = (result as { doc: Record<string, PirCriterion[]> }).doc[target.path];
    expect(criteria).toEqual([{ filters: filterGroup([TARGET]), weight: 3 }]);
  });

  // computePirScore counts a match once per distinct filter string but divides by the sum of
  // every criterion weight, so two criteria made identical would deflate every score.
  it('should fold the criteria a remap made identical, keeping the highest weight', () => {
    const candidate = candidateOf([
      { filters: filterGroup([SOURCE]), weight: 2 },
      { filters: filterGroup([TARGET]), weight: 5 },
    ]);
    const result = rewriteUserInPirCriteria(candidate, target, SOURCE, TARGET);
    expect(result).toMatchObject({ mergedCriteria: 1 });
    expect((result as { doc: Record<string, PirCriterion[]> }).doc[target.path]).toEqual([{ filters: filterGroup([TARGET]), weight: 5 }]);
  });

  it('should keep criteria that stay distinct after the remap', () => {
    const candidate = candidateOf([
      { filters: filterGroup([SOURCE]), weight: 2 },
      { filters: filterGroup([OTHER]), weight: 5 },
    ]);
    const result = rewriteUserInPirCriteria(candidate, target, SOURCE, TARGET);
    expect(result).toMatchObject({ mergedCriteria: 0 });
    expect((result as { doc: Record<string, PirCriterion[]> }).doc[target.path]).toHaveLength(2);
  });

  it('should report an unreadable criterion instead of rewriting it', () => {
    const result = rewriteUserInPirCriteria(candidateOf([{ filters: `{ broken ${SOURCE}`, weight: 1 }]), target, SOURCE, TARGET);
    expect(result).toEqual('unparsable');
  });

  it('should leave a PIR that does not name the source alone', () => {
    expect(rewriteUserInPirCriteria(candidateOf([{ filters: filterGroup([OTHER]), weight: 1 }]), target, SOURCE, TARGET)).toBeUndefined();
  });
});

describe('userMerge filter targets', () => {
  it('should name register rows that exist', () => {
    const known = USER_MERGE_REGISTER.map((row) => row.id);
    userMergeFilterCoveredRows().forEach((rowId) => expect(known).toContain(rowId));
  });

  it('should claim each row once', () => {
    const claimed = userMergeFilterCoveredRows();
    expect(claimed.length).toEqual(USER_MERGE_FILTER_TARGETS.length + USER_MERGE_FILTER_ACKNOWLEDGED_ROWS.length);
  });

  // Two entity types can hold a field of the same name, and the disjointness check compares
  // the declared paths literally.
  it('should qualify the written paths by entity type', () => {
    userMergeFilterFieldPaths().forEach((path) => expect(path).toContain('.'));
    expect(userMergeFilterFieldPaths()).toContain('Pir.pir_criteria');
  });

  it('should give a reason for every row it claims without writing', () => {
    USER_MERGE_FILTER_ACKNOWLEDGED_ROWS.forEach((row) => expect(row.reason.length).toBeGreaterThan(0));
  });
});
