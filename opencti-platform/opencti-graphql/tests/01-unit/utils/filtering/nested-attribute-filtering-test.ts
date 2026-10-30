import { describe, expect, it } from 'vitest';
import { type Filter, FilterOperator } from '../../../../src/generated/graphql';
import { adaptFilterToGenericNestedFilterKey } from '../../../../src/utils/filtering/filtering-completeSpecialFilterKeys';
import { hasCoveredCoverageInformation } from '../../../../src/schema/attribute-definition';

const filter = (overrides: Partial<Filter>) => ({ key: ['coverage_information'], operator: 'eq', mode: 'and', values: [], ...overrides } as Filter);
const adapt = (f: Filter) => adaptFilterToGenericNestedFilterKey(f, hasCoveredCoverageInformation);

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
    expect(adapt(filter({ values: [{ key: 'coverage_name', values: [] }, { key: 'coverage_score', values: ['0'] }] as any })).nested)
      .toEqual([{ key: 'coverage_score', operator: 'eq', values: ['0'] }]);
  });
  it('converts nil and not_nil, and eq without any value as not_nil', () => {
    expect(adapt(filter({ operator: FilterOperator.Nil }))).toMatchObject({ nested: [], negateNested: true });
    expect(adapt(filter({ operator: FilterOperator.NotNil })).negateNested).toBeUndefined();
    expect(adapt(filter({ operator: FilterOperator.NotNil })).nested).toEqual([]);
    expect(adapt(filter({ values: [{ key: 'coverage_score', operator: 'lt', values: [] }] as any })).nested).toEqual([]);
  });
  it('rejects unknown sub-filter keys and invalid operators', () => {
    expect(() => adapt(filter({ values: [{ key: 'unknown', values: ['a'] }] as any }))).toThrow(/sub-filter key/);
    expect(() => adapt(filter({ values: [{ key: 'coverage_score', operator: 'not_eq', values: ['20'] }] as any }))).toThrow(/operator/);
    expect(() => adapt(filter({ values: [{ key: 'coverage_name', operator: 'gt', values: ['detection'] }] as any }))).toThrow(/operator/);
    expect(() => adapt(filter({ operator: FilterOperator.NotEq }))).toThrow(/operator/);
  });
});
