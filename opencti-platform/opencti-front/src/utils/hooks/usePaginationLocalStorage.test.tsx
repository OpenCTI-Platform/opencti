import { beforeEach, describe, expect, it } from 'vitest';
import { testRenderHook } from '../tests/test-render';
import { expectNoFrontendIds } from '../tests/filtersTestHelpers';
import { usePaginationLocalStorage } from './useLocalStorage';
import type { FilterGroup } from '../filters/filtersHelpers-types';
import type { PaginationOptions } from '../../components/list_lines';

const nestedFilters = {
  mode: 'and',
  filters: [
    { id: 'root-filter-1', key: 'entity_type', values: ['Report'], operator: 'eq', mode: 'or' },
  ],
  filterGroups: [
    {
      id: 'group-1',
      mode: 'or',
      filters: [
        { id: 'nested-filter-1', key: 'objectLabel', values: ['label-1'], operator: 'eq', mode: 'or' },
      ],
      filterGroups: [
        {
          id: 'group-1-1',
          mode: 'and',
          filters: [
            { id: 'nested-filter-2', key: 'createdBy', values: ['id-1'], operator: 'eq', mode: 'or' },
          ],
          filterGroups: [],
        },
      ],
    },
  ],
} as unknown as FilterGroup;

const flatFilters = {
  mode: 'and',
  filters: [
    { id: 'root-filter-1', key: 'entity_type', values: ['Report'], operator: 'eq', mode: 'or' },
    { id: 'root-filter-2', key: 'objectLabel', values: [], operator: 'eq', mode: 'or' },
  ],
  filterGroups: [],
} as unknown as FilterGroup;

describe('usePaginationLocalStorage paginationOptions', () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it('should not leak frontend-only ids in nested filter groups', () => {
    const { hook } = testRenderHook(() => usePaginationLocalStorage<PaginationOptions>(
      'test-nested-filters',
      { filters: nestedFilters },
      true,
    ));
    const { filters } = hook.result.current.paginationOptions;
    expect(filters).toBeDefined();
    expectNoFrontendIds(filters as FilterGroup);
  });

  it('should keep the flat case output unchanged', () => {
    const { hook } = testRenderHook(() => usePaginationLocalStorage<PaginationOptions>(
      'test-flat-filters',
      { filters: flatFilters },
      true,
    ));
    const { filters } = hook.result.current.paginationOptions;
    expect(filters).toStrictEqual({
      mode: 'and',
      filters: [
        { key: 'entity_type', values: ['Report'], operator: 'eq', mode: 'or' },
      ],
      filterGroups: [],
    });
  });
});
