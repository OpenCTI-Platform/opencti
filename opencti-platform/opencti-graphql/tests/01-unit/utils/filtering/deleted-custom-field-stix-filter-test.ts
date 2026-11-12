import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as cacheModule from '../../../../src/database/cache';
import { deletedCustomFieldStixFilterTester } from '../../../../src/modules/customField/custom-field-stix-utils';
import { validateFilterGroupForStixMatch } from '../../../../src/utils/filtering/filtering-stix/stix-filtering';
import { FilterOperator } from '../../../../src/generated/graphql';

const CONTEXT = {} as any;
const USER = { id: 'user-1' } as any;

const makeFilterGroup = (key: string, operator: string, values: string[]) => ({
  mode: 'and',
  filters: [{ key: [key], values, operator, mode: 'or' }],
  filterGroups: [],
}) as any;

describe('Stix filters on a deleted custom field', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    // No custom field definition: the custom field has been deleted
    vi.spyOn(cacheModule, 'getEntitiesListFromCache').mockResolvedValue([]);
  });

  it('tests a deleted custom field as a custom field the stix does not have', () => {
    const stix = { extensions: {} } as any;
    const filter = (operator: FilterOperator, values: string[]) => ({ key: ['x_opencti_cf_deleted'], values, operator, mode: 'or' }) as any;
    expect(deletedCustomFieldStixFilterTester(stix, filter(FilterOperator.Eq, ['a']))).toBe(false);
    expect(deletedCustomFieldStixFilterTester(stix, filter(FilterOperator.NotNil, []))).toBe(false);
    expect(deletedCustomFieldStixFilterTester(stix, filter(FilterOperator.NotEq, ['a']))).toBe(true);
    expect(deletedCustomFieldStixFilterTester(stix, filter(FilterOperator.Nil, []))).toBe(true);
  });

  it('rejects saving a filter on an unknown custom field, as any unknown key', async () => {
    // A typo, a custom field never created or an alias
    await expect(validateFilterGroupForStixMatch(CONTEXT, USER, makeFilterGroup('x_opencti_cf_deleted', 'not_eq', ['a'])))
      .rejects.toThrow('The filter key x_opencti_cf_deleted does not match any existing custom field');
  });

  it('still rejects an unknown filter key that is not a custom field', async () => {
    await expect(validateFilterGroupForStixMatch(CONTEXT, USER, makeFilterGroup('unknown_key', 'eq', ['a'])))
      .rejects.toThrow('Stix filtering is not compatible with the provided filter key');
  });
});
