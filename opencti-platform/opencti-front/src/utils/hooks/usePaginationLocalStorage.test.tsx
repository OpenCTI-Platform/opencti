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

describe('usePaginationLocalStorage filter group ids', () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it('should give an id to every filter group of the state and stay stable across re-renders', () => {
    const groupWithoutIds = {
      mode: 'and',
      filters: [],
      filterGroups: [
        { mode: 'or', filters: [], filterGroups: [{ mode: 'and', filters: [], filterGroups: [] }] },
      ],
    } as unknown as FilterGroup;
    const { hook } = testRenderHook(() => usePaginationLocalStorage<PaginationOptions>(
      'test-group-ids',
      { filters: groupWithoutIds },
      true,
    ));
    const filters = hook.result.current.viewStorage.filters as FilterGroup;
    expect(filters.id).toBeDefined();
    expect(filters.filterGroups[0].id).toBeDefined();
    expect(filters.filterGroups[0].filterGroups[0].id).toBeDefined();
    // no new uuid on re-render: the state value must be referentially stable
    hook.rerender();
    hook.rerender();
    expect(hook.result.current.viewStorage.filters).toBe(filters);
  });

  it('should preserve the group ids already persisted', () => {
    const { hook } = testRenderHook(() => usePaginationLocalStorage<PaginationOptions>(
      'test-existing-group-ids',
      { filters: nestedFilters },
      true,
    ));
    const filters = hook.result.current.viewStorage.filters as FilterGroup;
    expect(filters.filterGroups[0].id).toEqual('group-1');
    expect(filters.filterGroups[0].filterGroups[0].id).toEqual('group-1-1');
  });
});
