import { describe, it, expect, vi } from 'vitest';
import { act } from '@testing-library/react';
import type { Filter } from '../../../utils/filters/filtersHelpers-types';
import { testRenderHook } from '../../../utils/tests/test-render';

const useSearchEntitiesMock = vi.fn((_args: unknown) => [{}, vi.fn()]);

vi.mock('../../../utils/filters/useSearchEntities', () => ({
  default: (args: unknown) => useSearchEntitiesMock(args),
}));

vi.mock('../../../relay/environment', () => ({
  APP_BASE_PATH: '',
  MESSAGING$: { messages$: { subscribe: () => ({}) } },
  environment: {},
  fetchQuery: vi.fn(),
}));

import useFilterEditorState from './useFilterEditorState';

const filter: Filter = { id: 'filter-1', key: 'name', values: ['abc'], operator: 'eq', mode: 'or' };

describe('useFilterEditorState', () => {
  it('seeds inputValues with the edited filter', () => {
    const { hook } = testRenderHook(() => useFilterEditorState({ filter }));
    expect(hook.result.current.inputValues).toEqual([filter]);
  });

  it('starts with empty inputValues when there is no filter yet', () => {
    const { hook } = testRenderHook(() => useFilterEditorState({}));
    expect(hook.result.current.inputValues).toEqual([]);
  });

  it('defaults the search scope to the targets list when no relation types are given', () => {
    const { hook } = testRenderHook(() => useFilterEditorState({ filter }));
    expect(hook.result.current.searchScope.targets).toContain('Organization');
  });

  it('uses the given relation filter types as search scope when provided', () => {
    const availableRelationFilterTypes = { targets: ['Sector'] };
    const { hook } = testRenderHook(() => useFilterEditorState({ filter, availableRelationFilterTypes }));
    expect(hook.result.current.searchScope).toEqual(availableRelationFilterTypes);
  });

  it('merges the search context entity types with the filtered entity types', () => {
    useSearchEntitiesMock.mockClear();
    testRenderHook(() => useFilterEditorState({
      filter,
      entityTypes: ['Report'],
      searchContext: { entityTypes: ['Malware'] },
    }));
    expect(useSearchEntitiesMock).toHaveBeenCalledWith(
      expect.objectContaining({ searchContext: expect.objectContaining({ entityTypes: ['Malware', 'Report'] }) }),
    );
  });

  it('exposes setters that update the returned state', () => {
    const { hook } = testRenderHook(() => useFilterEditorState({ filter }));
    act(() => hook.result.current.setAutocompleteInputValues({ name: 'abc' }));
    expect(hook.result.current.autocompleteInputValues).toEqual({ name: 'abc' });
  });
});
