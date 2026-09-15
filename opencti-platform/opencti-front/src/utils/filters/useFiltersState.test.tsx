import { describe, expect, it } from 'vitest';
import { act } from 'react';
import { testRenderHook } from '../tests/test-render';
import useFiltersState from './useFiltersState';
import type { FilterGroup } from './filtersHelpers-types';

const initFilters = {
  id: 'root',
  mode: 'and',
  filters: [
    { id: 'f-root', key: 'entity_type', values: ['Report'], operator: 'eq', mode: 'or' },
  ],
  filterGroups: [
    {
      id: 'group-1',
      mode: 'or',
      filters: [
        { id: 'f-d2', key: 'objectLabel', values: ['label-1'], operator: 'eq', mode: 'or' },
      ],
      filterGroups: [],
    },
  ],
} as unknown as FilterGroup;

describe('useFiltersState nested groups helpers', () => {
  it('should expose the new helpers', () => {
    const { hook } = testRenderHook(() => useFiltersState(initFilters));
    const [, helpers] = hook.result.current;
    expect(typeof helpers.handleAddFilterGroup).toEqual('function');
    expect(typeof helpers.handleRemoveFilterGroup).toEqual('function');
  });

  it('should add a group in the root and in a nested group', () => {
    const { hook } = testRenderHook(() => useFiltersState(initFilters));
    act(() => hook.result.current[1].handleAddFilterGroup());
    expect(hook.result.current[0].filterGroups).toHaveLength(2);
    act(() => hook.result.current[1].handleAddFilterGroup('group-1'));
    expect(hook.result.current[0].filterGroups[0].filterGroups).toHaveLength(1);
  });

  it('should remove a nested group', () => {
    const { hook } = testRenderHook(() => useFiltersState(initFilters));
    act(() => hook.result.current[1].handleRemoveFilterGroup('group-1'));
    expect(hook.result.current[0].filterGroups).toEqual([]);
  });

  it('should switch only the mode of the targeted group', () => {
    const { hook } = testRenderHook(() => useFiltersState(initFilters));
    act(() => hook.result.current[1].handleSwitchGlobalMode('group-1'));
    expect(hook.result.current[0].mode).toEqual('and');
    expect(hook.result.current[0].filterGroups[0].mode).toEqual('and');
    act(() => hook.result.current[1].handleSwitchGlobalMode());
    expect(hook.result.current[0].mode).toEqual('or');
  });

  it('should add a filter in a nested group and reset latestAddFilterId', () => {
    const { hook } = testRenderHook(() => useFiltersState(initFilters));
    act(() => hook.result.current[1].handleAddFilterWithEmptyValue({ id: 'f-new', key: 'createdBy', values: [] }, 'group-1'));
    expect(hook.result.current[0].filterGroups[0].filters.map((f) => f.id)).toEqual(['f-d2', 'f-new']);
    expect(hook.result.current[1].getLatestAddFilterId()).toBeUndefined();
  });

  it('should keep the root behaviour of handleAddFilterWithEmptyValue', () => {
    const { hook } = testRenderHook(() => useFiltersState(initFilters));
    act(() => hook.result.current[1].handleAddFilterWithEmptyValue({ id: 'f-new', key: 'createdBy', values: [] }));
    expect(hook.result.current[0].filters.map((f) => f.id)).toEqual(['f-root', 'f-new']);
    expect(hook.result.current[1].getLatestAddFilterId()).toEqual('f-new');
  });

  it('should remove a filter located in a nested group', () => {
    const { hook } = testRenderHook(() => useFiltersState(initFilters));
    act(() => hook.result.current[1].handleRemoveFilterById('f-d2'));
    expect(hook.result.current[0].filterGroups[0].filters).toEqual([]);
  });

  it('should clear the filter groups on handleClearAllFilters', () => {
    const { hook } = testRenderHook(() => useFiltersState(initFilters));
    act(() => hook.result.current[1].handleClearAllFilters());
    expect(hook.result.current[0].filters).toEqual([]);
    expect(hook.result.current[0].filterGroups).toEqual([]);
  });
});
