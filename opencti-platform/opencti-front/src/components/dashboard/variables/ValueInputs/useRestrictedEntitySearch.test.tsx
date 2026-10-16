import { describe, expect, it } from 'vitest';
import { act } from '@testing-library/react';
import { testRenderHook } from '../../../../utils/tests/test-render';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import useRestrictedEntitySearch, { RESTRICTED_ENTITY_SEARCH_SIZE } from './useRestrictedEntitySearch';

const rule: FilterGroup = {
  mode: 'and',
  filters: [{ id: 'front-only', key: 'objectLabel', values: ['label-1'], operator: 'eq', mode: 'or' }],
  filterGroups: [],
};

const answer = (names: [string, string][]) => ({
  data: {
    stixCoreObjects: {
      edges: names.map(([id, name]) => ({ node: { id, entity_type: 'Organization', representative: { main: name } } })),
    },
  },
});

describe('useRestrictedEntitySearch', () => {
  it('searches the entities of the types that match the rule', () => {
    const { relayEnv, hook } = testRenderHook(() => useRestrictedEntitySearch(['Organization'], rule));
    act(() => hook.result.current.search('acme'));
    const operation = relayEnv.mock.getMostRecentOperation();
    expect(operation.request.variables).toEqual({
      search: 'acme',
      types: ['Organization'],
      first: RESTRICTED_ENTITY_SEARCH_SIZE,
      filters: normalizeFilterGroupForBackend(rule),
    });
    act(() => relayEnv.mock.resolve(operation, answer([['org-1', 'Acme Corp']])));
    expect(hook.result.current.options).toEqual([{ value: 'org-1', label: 'Acme Corp', type: 'Organization', group: 'Organization' }]);
  });

  it('keeps only the answer of the last search', () => {
    const { relayEnv, hook } = testRenderHook(() => useRestrictedEntitySearch(['Organization'], rule));
    act(() => hook.result.current.search('a'));
    const first = relayEnv.mock.getMostRecentOperation();
    act(() => hook.result.current.search('ac'));
    const second = relayEnv.mock.getMostRecentOperation();
    act(() => relayEnv.mock.resolve(second, answer([['org-1', 'Acme Corp']])));
    act(() => relayEnv.mock.resolve(first, answer([['org-2', 'Another Corp'], ['org-3', 'Alpha']])));
    expect(hook.result.current.options.map((option) => option.label)).toEqual(['Acme Corp']);
  });

  it('offers nothing when the search fails', () => {
    const { relayEnv, hook } = testRenderHook(() => useRestrictedEntitySearch(['Organization'], rule));
    act(() => hook.result.current.search(''));
    act(() => relayEnv.mock.resolveMostRecentOperation(answer([['org-1', 'Acme Corp']])));
    act(() => hook.result.current.search('x'));
    act(() => relayEnv.mock.rejectMostRecentOperation(new Error('FORBIDDEN_ACCESS')));
    expect(hook.result.current.options).toEqual([]);
  });
});
