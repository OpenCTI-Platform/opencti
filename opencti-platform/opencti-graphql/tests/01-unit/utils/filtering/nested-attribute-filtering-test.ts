import { describe, expect, it } from 'vitest';
import { type Filter, FilterOperator } from '../../../../src/generated/graphql';
import { adaptFilterToGenericNestedFilterKey } from '../../../../src/utils/filtering/filtering-completeSpecialFilterKeys';
import { coverageInformation } from '../../../../src/schema/attribute-definition';
import { isGenericNestedFilterAttribute } from '../../../../src/schema/schema-attributes';

const filter = (overrides: Partial<Filter>) => ({ key: ['coverage_information'], operator: 'eq', mode: 'and', values: [], ...overrides } as Filter);
const adapt = (f: Filter) => adaptFilterToGenericNestedFilterKey(f, coverageInformation);

describe('adaptFilterToGenericNestedFilterKey', () => {
  it('converts name and score sub-filters to one nested filter', () => {
    expect(adapt(filter({
      values: [
        { key: 'coverage_name', operator: 'eq', values: ['detection'] },
        { key: 'coverage_score', operator: 'lt', values: ['20'] },
      ] as any,
    }))).toEqual({
      key: ['coverage_information'],
      operator: 'eq',
      mode: 'or',
      values: [],
      nested: [
        { key: 'coverage_name', operator: 'eq', values: ['detection'] },
        { key: 'coverage_score', operator: 'lt', values: ['20'] },
      ],
    });
  });
  it('defaults sub-filter operators to eq and drops sub-filters without value', () => {
    expect(adapt(filter({ values: [{ key: 'coverage_name', values: [] }, { key: 'coverage_score', values: ['0'] }] as any }))?.nested)
      .toEqual([{ key: 'coverage_score', operator: 'eq', values: ['0'] }]);
  });
  it('converts nil and not_nil', () => {
    expect(adapt(filter({ operator: FilterOperator.Nil }))).toMatchObject({ nested: [], negateNested: true });
    expect(adapt(filter({ operator: FilterOperator.NotNil }))?.negateNested).toBeUndefined();
    expect(adapt(filter({ operator: FilterOperator.NotNil }))?.nested).toEqual([]);
  });
  it('ignores an eq filter without any sub-filter value, like any filter without value', () => {
    expect(adapt(filter({ values: [] }))).toBeNull();
    expect(adapt(filter({ values: [{ key: 'coverage_name', values: [] }, { key: 'coverage_score', operator: 'lt', values: [] }] as any }))).toBeNull();
  });
  it('keeps the operator of each sub-filter, like the other filters', () => {
    expect(adapt(filter({ values: [{ key: 'coverage_score', operator: 'not_eq', values: ['20'] }] as any }))?.nested)
      .toEqual([{ key: 'coverage_score', operator: 'not_eq', values: ['20'] }]);
  });
  it('rejects unknown sub-filter keys and operators other than eq, nil and not_nil on the nested filter', () => {
    expect(() => adapt(filter({ values: [{ key: 'unknown', values: ['a'] }] as any }))).toThrow(/sub-filter key/);
    expect(() => adapt(filter({ operator: FilterOperator.NotEq }))).toThrow(/operator/);
  });
});

describe('isGenericNestedFilterAttribute', () => {
  it('needs a filterable nested attribute with at least one filterable mapping', () => {
    expect(isGenericNestedFilterAttribute(coverageInformation)).toBe(true);
    expect(isGenericNestedFilterAttribute({ ...coverageInformation, isFilterable: false })).toBe(false);
    const withoutFilterableMapping = { ...coverageInformation, mappings: coverageInformation.mappings.map((mapping) => ({ ...mapping, isFilterable: false })) };
    expect(isGenericNestedFilterAttribute(withoutFilterableMapping)).toBe(false);
  });
});
