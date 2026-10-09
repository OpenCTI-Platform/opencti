import { describe, expect, it } from 'vitest';
import {
  addFilterGroupUtil,
  handleAddFilterWithEmptyValueUtil,
  handleAddRepresentationFilterUtil,
  handleAddSingleValueFilterUtil,
  handleChangeOperatorFiltersUtil,
  handleChangeRepresentationFilterUtil,
  handleRemoveFilterUtil,
  handleRemoveRepresentationFilterUtil,
  handleReplaceFilterValuesUtil,
  handleSwitchGlobalModeUtil,
  handleSwitchLocalModeUtil,
  removeFilterGroupUtil,
  updateGroupById,
} from './filtersManageStateUtil';
import { cleanFilters, extractAllFilters } from './filtersUtils';
import type { Filter, FilterGroup, handleFilterHelpers } from './filtersHelpers-types';

// depth 1 = root, depth 2 = group-1, depth 3 = group-1-1
const buildTree = (): FilterGroup => ({
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
        { id: 'f-d2', key: 'objectLabel', values: ['label-1', 'label-2'], operator: 'eq', mode: 'or' },
      ],
      filterGroups: [
        {
          id: 'group-1-1',
          mode: 'and',
          filters: [
            { id: 'f-d3', key: 'createdBy', values: ['id-1'], operator: 'eq', mode: 'or' },
          ],
          filterGroups: [],
        },
      ],
    },
  ],
});

const deepFreeze = <T>(obj: T): T => {
  Object.getOwnPropertyNames(obj).forEach((prop) => {
    const value = (obj as Record<string, unknown>)[prop];
    if (value && typeof value === 'object') deepFreeze(value);
  });
  return Object.freeze(obj);
};

const frozenTree = () => deepFreeze(buildTree());

const findFilter = (group: FilterGroup, id: string): Filter | undefined => extractAllFilters(group).find((f) => f.id === id);
const findGroup = (group: FilterGroup, id: string): FilterGroup | undefined => {
  if (group.id === id) return group;
  return group.filterGroups.map((g) => findGroup(g, id)).find((g) => g);
};

describe('filtersManageStateUtil - filter level utils recurse the whole tree', () => {
  it('handleChangeOperatorFiltersUtil should change the operator of a filter at depth 2 and 3', () => {
    const atDepth2 = handleChangeOperatorFiltersUtil({ filters: frozenTree(), id: 'f-d2', operator: 'nil' });
    expect(findFilter(atDepth2, 'f-d2')).toEqual({ id: 'f-d2', key: 'objectLabel', values: [], operator: 'nil', mode: 'or' });
    const atDepth3 = handleChangeOperatorFiltersUtil({ filters: frozenTree(), id: 'f-d3', operator: 'not_eq' });
    expect(findFilter(atDepth3, 'f-d3')?.operator).toEqual('not_eq');
    expect(findFilter(atDepth3, 'f-d3')?.values).toEqual(['id-1']);
  });

  it('handleRemoveFilterUtil should remove a filter at depth 2 and 3', () => {
    const atDepth2 = handleRemoveFilterUtil({ filters: frozenTree(), id: 'f-d2' });
    expect(findFilter(atDepth2, 'f-d2')).toBeUndefined();
    expect(extractAllFilters(atDepth2).map((f) => f.id)).toEqual(['f-root', 'f-d3']);
    const atDepth3 = handleRemoveFilterUtil({ filters: frozenTree(), id: 'f-d3' });
    expect(extractAllFilters(atDepth3).map((f) => f.id)).toEqual(['f-root', 'f-d2']);
  });

  it('handleReplaceFilterValuesUtil should replace values at depth 2 and 3', () => {
    const atDepth2 = handleReplaceFilterValuesUtil({ filters: frozenTree(), id: 'f-d2', values: ['x'] });
    expect(findFilter(atDepth2, 'f-d2')?.values).toEqual(['x']);
    const atDepth3 = handleReplaceFilterValuesUtil({ filters: frozenTree(), id: 'f-d3', values: ['y'] });
    expect(findFilter(atDepth3, 'f-d3')?.values).toEqual(['y']);
  });

  it('handleAddRepresentationFilterUtil should add a value at depth 2 and 3', () => {
    const atDepth2 = handleAddRepresentationFilterUtil({ filters: frozenTree(), id: 'f-d2', value: 'label-3' });
    expect(findFilter(atDepth2, 'f-d2')?.values).toEqual(['label-1', 'label-2', 'label-3']);
    const atDepth3 = handleAddRepresentationFilterUtil({ filters: frozenTree(), id: 'f-d3', value: 'id-2' });
    expect(findFilter(atDepth3, 'f-d3')?.values).toEqual(['id-1', 'id-2']);
  });

  it('handleRemoveRepresentationFilterUtil should remove a value at depth 2 and 3', () => {
    const atDepth2 = handleRemoveRepresentationFilterUtil({ filters: frozenTree(), id: 'f-d2', value: 'label-1' });
    expect(findFilter(atDepth2, 'f-d2')?.values).toEqual(['label-2']);
    const atDepth3 = handleRemoveRepresentationFilterUtil({ filters: frozenTree(), id: 'f-d3', value: 'id-1' });
    expect(findFilter(atDepth3, 'f-d3')?.values).toEqual([]);
  });

  it('handleChangeRepresentationFilterUtil should change a value at depth 2 and 3', () => {
    const atDepth2 = handleChangeRepresentationFilterUtil({ filters: frozenTree(), id: 'f-d2', oldValue: 'label-1', newValue: 'label-9' });
    expect(findFilter(atDepth2, 'f-d2')?.values).toEqual(['label-2', 'label-9']);
    const atDepth3 = handleChangeRepresentationFilterUtil({ filters: frozenTree(), id: 'f-d3', oldValue: 'id-1', newValue: 'id-9' });
    expect(findFilter(atDepth3, 'f-d3')?.values).toEqual(['id-9']);
  });

  it('handleAddSingleValueFilterUtil should set a single value at depth 2 and 3', () => {
    const atDepth2 = handleAddSingleValueFilterUtil({ filters: frozenTree(), id: 'f-d2', valueId: 'only' });
    expect(findFilter(atDepth2, 'f-d2')?.values).toEqual(['only']);
    const atDepth3 = handleAddSingleValueFilterUtil({ filters: frozenTree(), id: 'f-d3' });
    expect(findFilter(atDepth3, 'f-d3')?.values).toEqual([]);
  });

  it('handleSwitchLocalModeUtil should switch the local mode at depth 2 and 3', () => {
    const atDepth2 = handleSwitchLocalModeUtil({ filters: frozenTree(), filter: { id: 'f-d2', key: 'objectLabel', values: [], mode: 'or' } });
    expect(findFilter(atDepth2, 'f-d2')?.mode).toEqual('and');
    const atDepth3 = handleSwitchLocalModeUtil({ filters: frozenTree(), filter: { id: 'f-d3', key: 'createdBy', values: [], mode: 'and' } });
    expect(findFilter(atDepth3, 'f-d3')?.mode).toEqual('or');
  });
});

describe('filtersManageStateUtil - root level behaviour is unchanged', () => {
  const flat: FilterGroup = deepFreeze({
    mode: 'and',
    filters: [
      { id: 'a', key: 'entity_type', values: ['Report'], operator: 'eq', mode: 'or' },
      { id: 'b', key: 'objectLabel', values: ['l1'], operator: 'eq', mode: 'or' },
    ],
    filterGroups: [],
  });

  it('should keep the exact same output on a flat filter group', () => {
    expect(handleRemoveFilterUtil({ filters: flat, id: 'a' })).toStrictEqual({
      mode: 'and',
      filters: [{ id: 'b', key: 'objectLabel', values: ['l1'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    });
    expect(handleAddRepresentationFilterUtil({ filters: flat, id: 'b', value: 'l2' })).toStrictEqual({
      mode: 'and',
      filters: [
        { id: 'a', key: 'entity_type', values: ['Report'], operator: 'eq', mode: 'or' },
        { id: 'b', key: 'objectLabel', values: ['l1', 'l2'], operator: 'eq', mode: 'or' },
      ],
      filterGroups: [],
    });
    expect(handleAddFilterWithEmptyValueUtil({ filters: flat, filter: { id: 'c', key: 'createdBy', values: [], operator: 'eq', mode: 'or' } })).toStrictEqual({
      mode: 'and',
      filters: [
        { id: 'a', key: 'entity_type', values: ['Report'], operator: 'eq', mode: 'or' },
        { id: 'b', key: 'objectLabel', values: ['l1'], operator: 'eq', mode: 'or' },
        { id: 'c', key: 'createdBy', values: [], operator: 'eq', mode: 'or' },
      ],
      filterGroups: [],
    });
    expect(handleSwitchGlobalModeUtil({ filters: flat }).mode).toEqual('or');
  });
});

describe('filtersManageStateUtil - updateGroupById', () => {
  it('should target the root group when groupId is undefined', () => {
    const result = updateGroupById(frozenTree(), undefined, (g) => ({ ...g, mode: 'or' }));
    expect(result.mode).toEqual('or');
    expect(result.filterGroups[0].mode).toEqual('or'); // unchanged (was already 'or')
    expect(result.filterGroups[0].filterGroups[0].mode).toEqual('and');
  });

  it('should target a nested group by its id', () => {
    const result = updateGroupById(frozenTree(), 'group-1-1', (g) => ({ ...g, mode: 'or' }));
    expect(result.mode).toEqual('and');
    expect(result.filterGroups[0].filterGroups[0].mode).toEqual('or');
  });

  it('should be a no-op for an unknown group id', () => {
    const tree = frozenTree();
    const result = updateGroupById(tree, 'does-not-exist', (g) => ({ ...g, mode: 'or' }));
    expect(result).toBe(tree);
  });
});

describe('filtersManageStateUtil - group level operations', () => {
  it('should add an empty group in the root group', () => {
    const result = addFilterGroupUtil({ filters: frozenTree() });
    expect(result.filterGroups).toHaveLength(2);
    const added = result.filterGroups[1];
    expect(added.id).toBeDefined();
    expect(added.mode).toEqual('and');
    expect(added.filters).toEqual([]);
    expect(added.filterGroups).toEqual([]);
  });

  it('should add an empty group in a nested group', () => {
    const result = addFilterGroupUtil({ filters: frozenTree(), parentGroupId: 'group-1-1' });
    expect(result.filterGroups).toHaveLength(1);
    const added = findGroup(result, 'group-1-1')?.filterGroups[0];
    expect(added?.mode).toEqual('and');
    expect(added?.id).toBeDefined();
  });

  it('should remove a nested group and everything under it', () => {
    const result = removeFilterGroupUtil({ filters: frozenTree(), groupId: 'group-1' });
    expect(result.filterGroups).toEqual([]);
    expect(extractAllFilters(result).map((f) => f.id)).toEqual(['f-root']);
  });

  it('should remove a deeply nested group only', () => {
    const result = removeFilterGroupUtil({ filters: frozenTree(), groupId: 'group-1-1' });
    expect(findGroup(result, 'group-1-1')).toBeUndefined();
    expect(extractAllFilters(result).map((f) => f.id)).toEqual(['f-root', 'f-d2']);
  });

  it('should never remove the root group', () => {
    const tree = frozenTree();
    const result = removeFilterGroupUtil({ filters: tree, groupId: 'root' });
    expect(result).toBe(tree);
  });

  it('should be a no-op when removing an unknown group', () => {
    const tree = frozenTree();
    expect(removeFilterGroupUtil({ filters: tree, groupId: 'nope' })).toBe(tree);
  });

  it('handleSwitchGlobalModeUtil should switch only the targeted group mode', () => {
    const result = handleSwitchGlobalModeUtil({ filters: frozenTree(), groupId: 'group-1' });
    expect(result.mode).toEqual('and');
    expect(findGroup(result, 'group-1')?.mode).toEqual('and');
    expect(findGroup(result, 'group-1-1')?.mode).toEqual('and');
    const rootSwitch = handleSwitchGlobalModeUtil({ filters: frozenTree() });
    expect(rootSwitch.mode).toEqual('or');
    expect(findGroup(rootSwitch, 'group-1')?.mode).toEqual('or');
    expect(findGroup(rootSwitch, 'group-1-1')?.mode).toEqual('and');
  });

  it('should add a filter into a nested group', () => {
    const newFilter: Filter = { id: 'f-new', key: 'createdBy', values: [], operator: 'eq', mode: 'or' };
    const result = handleAddFilterWithEmptyValueUtil({ filters: frozenTree(), filter: newFilter, groupId: 'group-1-1' });
    expect(findGroup(result, 'group-1-1')?.filters.map((f) => f.id)).toEqual(['f-d3', 'f-new']);
    expect(result.filters.map((f) => f.id)).toEqual(['f-root']);
  });
});

describe('filtersManageStateUtil - non mutation', () => {
  it('should never mutate a deep frozen input', () => {
    const tree = frozenTree();
    const snapshot = JSON.stringify(tree);
    handleRemoveFilterUtil({ filters: tree, id: 'f-d3' });
    handleChangeOperatorFiltersUtil({ filters: tree, id: 'f-d2', operator: 'nil' });
    handleAddRepresentationFilterUtil({ filters: tree, id: 'f-d3', value: 'v' });
    handleRemoveRepresentationFilterUtil({ filters: tree, id: 'f-d2', value: 'label-1' });
    handleChangeRepresentationFilterUtil({ filters: tree, id: 'f-d2', oldValue: 'label-1', newValue: 'z' });
    handleAddSingleValueFilterUtil({ filters: tree, id: 'f-d3', valueId: 'v' });
    handleReplaceFilterValuesUtil({ filters: tree, id: 'f-d3', values: ['v'] });
    handleSwitchLocalModeUtil({ filters: tree, filter: { id: 'f-d3', key: 'createdBy', values: [], mode: 'and' } });
    handleSwitchGlobalModeUtil({ filters: tree, groupId: 'group-1' });
    handleAddFilterWithEmptyValueUtil({ filters: tree, filter: { id: 'x', key: 'k', values: [] }, groupId: 'group-1' });
    addFilterGroupUtil({ filters: tree, parentGroupId: 'group-1' });
    removeFilterGroupUtil({ filters: tree, groupId: 'group-1-1' });
    expect(JSON.stringify(tree)).toEqual(snapshot);
  });
});

describe('filtersUtils tree readers', () => {
  it('extractAllFilters should return the filters of the 3 levels', () => {
    expect(extractAllFilters(frozenTree()).map((f) => f.id)).toEqual(['f-root', 'f-d2', 'f-d3']);
  });

  it('cleanFilters should remove the unavailable filters at every level', () => {
    const removed: string[] = [];
    const helpers = { handleRemoveFilterById: (id: string) => removed.push(id) } as unknown as handleFilterHelpers;
    const keysMap = new Map([['Report', new Map([['entity_type', {}]])]]) as never;
    cleanFilters(frozenTree(), helpers, ['Report'], keysMap);
    expect(removed).toEqual(['f-d2', 'f-d3']);
  });
});
