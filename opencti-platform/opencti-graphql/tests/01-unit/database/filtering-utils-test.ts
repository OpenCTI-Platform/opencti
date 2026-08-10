import { describe, expect, it } from 'vitest';
// Registers all entity/relation modules so schemaAttributesDefinition / schemaRelationsRefDefinition
// are populated, without requiring a live DB/ES stack (pure in-memory schema registration).
import '../../../src/modules/index';
import { checkFiltersValidity } from '../../../src/utils/filtering/filtering-utils';
import { buildRefRelationKey } from '../../../src/schema/general';
import { RELATION_OBJECT, RELATION_CREATED_BY } from '../../../src/schema/stixRefRelationship';
import type { FilterGroup } from '../../../src/generated/graphql';

describe('Filtering utils', () => {
  it('should reject a filter key containing an extra invalid segment after the first dot', () => {
    // "name" alone is a valid schema key, but the full composed key carries extra content
    // after the first dot that should not be accepted.
    const composedKey = "name.']; ctx._source.value = true; //";
    const filterGroup = {
      mode: 'or',
      filters: [
        { key: [composedKey], values: ['a'], operator: 'only_eq_to' },
      ],
      filterGroups: [],
    } as FilterGroup;

    expect(() => checkFiltersValidity(filterGroup)).toThrowError('Incorrect filter keys containing invalid characters');
  });

  it('should not reject legitimate ref-relation keys with a non-schema second segment (e.g. wildcard or sub-field)', () => {
    // buildRefRelationKey(TYPE, '*') / buildRefRelationKey(TYPE) are used all over the domain
    // layer (container.js, note.js, opinion.js, report.js, grouping-domain.ts, ...) to filter
    // by a relation ref. Their second segment ('*' or 'internal_id') is a marker/sub-field,
    // not itself a registered top-level schema attribute — it must not be rejected.
    const wildcardKey = buildRefRelationKey(RELATION_OBJECT, '*'); // "rel_object.*"
    const defaultFieldKey = buildRefRelationKey(RELATION_CREATED_BY); // "rel_created-by.internal_id"
    const filterGroup = {
      mode: 'and',
      filters: [
        { key: [wildcardKey], values: ['some-id'] },
        { key: [defaultFieldKey], values: ['some-id'] },
      ],
      filterGroups: [],
    } as FilterGroup;

    expect(() => checkFiltersValidity(filterGroup)).not.toThrow();
  });

  it('should not reject an unsupported operator at the format-check stage (checkFiltersValidity only checks keys and shape)', () => {
    // isFilterFormatCorrect does not special-case any particular operator value, so a filter
    // group with an operator outside the public enum still passes the format/key checks: it
    // has a valid key and no invalid characters. This is expected: operator support is
    // enforced later, at query-build time, by buildLocalMustFilter (see engine-test.js for
    // that check, and tests/03-integration/01-database/filtering-utils-test.ts for the real
    // end-to-end proof with a raw JSON-string filter input against a live search engine).
    const filterGroup = {
      mode: 'or',
      filters: [
        { key: ['name'], values: ['return true;'], operator: 'internal_script' },
      ],
      filterGroups: [],
    } as unknown as FilterGroup;

    expect(() => checkFiltersValidity(filterGroup)).not.toThrow();
  });
});
