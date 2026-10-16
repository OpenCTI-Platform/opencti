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
    // The earlier search was cancelled: its answer can no longer arrive.
    expect(() => relayEnv.mock.resolve(first, answer([['org-2', 'Another Corp']]))).toThrow();
    expect(hook.result.current.options.map((option) => option.label)).toEqual(['Acme Corp']);
  });

  it('drops the options found for another rule', () => {
    let filters = rule;
    const { relayEnv, hook } = testRenderHook(() => useRestrictedEntitySearch(['Organization'], filters));
    act(() => hook.result.current.search(''));
    act(() => relayEnv.mock.resolveMostRecentOperation(answer([['org-1', 'Acme Corp']])));
    expect(hook.result.current.options).toHaveLength(1);
    filters = { ...rule, filters: [{ key: 'objectLabel', values: ['label-2'], operator: 'eq', mode: 'or' }] };
    hook.rerender();
    expect(hook.result.current.options).toEqual([]);
  });

  it('keeps the options when the rule sent does not change', () => {
    let filters = rule;
    const { relayEnv, hook } = testRenderHook(() => useRestrictedEntitySearch(['Organization'], filters));
    act(() => hook.result.current.search(''));
    act(() => relayEnv.mock.resolveMostRecentOperation(answer([['org-1', 'Acme Corp']])));
    // A filter without value yet is not sent.
    filters = { ...rule, filters: [...rule.filters, { id: 'f2', key: 'objectMarking', values: [], operator: 'eq', mode: 'or' }] };
    hook.rerender();
    expect(hook.result.current.options).toHaveLength(1);
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
