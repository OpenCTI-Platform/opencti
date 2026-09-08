import { describe, expect, it } from 'vitest';
import { hasSameSavedFilters, isEmptySavedFilterGroup, normalizeSavedFilterGroupString, serializeSavedFilterGroup } from './savedFiltersUtils';
import { ensureFilterGroupIds } from '../../utils/filters/filtersUtils';
import { FilterGroup } from '../../utils/filters/filtersHelpers-types';

const nestedFilterGroup: FilterGroup = {
  mode: 'and',
  filters: [{ key: 'entity_type', values: ['Report'], operator: 'eq', mode: 'or' }],
  filterGroups: [
    {
      mode: 'or',
      filters: [{ key: 'name', values: ['foo'], operator: 'eq', mode: 'or' }],
      filterGroups: [
        {
          mode: 'and',
          filters: [{ key: 'confidence', values: ['50'], operator: 'gt', mode: 'or' }],
          filterGroups: [],
        },
      ],
    },
  ],
};

describe('serializeSavedFilterGroup', () => {
  it('should strip the frontend-only group ids', () => {
    const withIds = ensureFilterGroupIds(nestedFilterGroup);
    expect(serializeSavedFilterGroup(withIds)).not.toContain('"id"');
    expect(serializeSavedFilterGroup(withIds)).toEqual(serializeSavedFilterGroup(nestedFilterGroup));
  });
});

describe('normalizeSavedFilterGroupString', () => {
  it('should strip ids from an old saved row that still contains them', () => {
    const oldRow = JSON.stringify(ensureFilterGroupIds(nestedFilterGroup));
    expect(oldRow).toContain('"id"');
    expect(normalizeSavedFilterGroupString(oldRow)).toEqual(serializeSavedFilterGroup(nestedFilterGroup));
  });

  it('should return undefined on empty input and keep unparsable input as is', () => {
    expect(normalizeSavedFilterGroupString(undefined)).toBeUndefined();
    expect(normalizeSavedFilterGroupString('')).toBeUndefined();
    expect(normalizeSavedFilterGroupString('not json')).toEqual('not json');
  });
});

describe('hasSameSavedFilters', () => {
  it('should not report a dirty state after a save/reload round-trip with nested groups', () => {
    const savedRow = serializeSavedFilterGroup(nestedFilterGroup);
    const reloaded = ensureFilterGroupIds(JSON.parse(savedRow));
    expect(hasSameSavedFilters(savedRow, reloaded)).toBe(true);
  });

  it('should not report a dirty state for an old saved row whose json still contains ids', () => {
    const oldRow = JSON.stringify(ensureFilterGroupIds(nestedFilterGroup));
    const reloaded = ensureFilterGroupIds(JSON.parse(oldRow));
    expect(hasSameSavedFilters(oldRow, reloaded)).toBe(true);
  });

  it('should give the reloaded filter groups usable ids, so they stay editable', () => {
    const savedRow = serializeSavedFilterGroup(nestedFilterGroup);
    const reloaded = ensureFilterGroupIds(JSON.parse(savedRow));
    expect(reloaded.id).toBeDefined();
    expect(reloaded.filterGroups[0].id).toBeDefined();
    expect(reloaded.filterGroups[0].filterGroups[0].id).toBeDefined();
  });

  it('should report a dirty state when a nested filter value is modified', () => {
    const savedRow = serializeSavedFilterGroup(nestedFilterGroup);
    const modified = ensureFilterGroupIds(JSON.parse(savedRow));
    modified.filterGroups[0].filters[0].values = ['bar'];
    expect(hasSameSavedFilters(savedRow, modified)).toBe(false);
  });

  it('should report a dirty state when a nested group is added or removed', () => {
    const savedRow = serializeSavedFilterGroup(nestedFilterGroup);
    const withExtraGroup = ensureFilterGroupIds(JSON.parse(savedRow));
    withExtraGroup.filterGroups.push({ mode: 'and', filters: [{ key: 'name', values: ['x'] }], filterGroups: [] });
    expect(hasSameSavedFilters(savedRow, withExtraGroup)).toBe(false);
  });

  it('should report a dirty state when there is no saved filter yet', () => {
    expect(hasSameSavedFilters(undefined, nestedFilterGroup)).toBe(false);
  });
});

describe('isEmptySavedFilterGroup', () => {
  it('should consider an undefined or empty filter group as empty', () => {
    expect(isEmptySavedFilterGroup(undefined)).toBe(true);
    expect(isEmptySavedFilterGroup({ mode: 'and', filters: [], filterGroups: [] })).toBe(true);
  });

  it('should consider a group holding only empty nested groups as empty', () => {
    expect(isEmptySavedFilterGroup({
      mode: 'and',
      filters: [],
      filterGroups: [{ mode: 'and', filters: [], filterGroups: [{ mode: 'or', filters: [], filterGroups: [] }] }],
    })).toBe(true);
  });

  it('should consider a group holding a nested filter as not empty', () => {
    expect(isEmptySavedFilterGroup(nestedFilterGroup)).toBe(false);
    expect(isEmptySavedFilterGroup({
      mode: 'and',
      filters: [],
      filterGroups: [{ mode: 'and', filters: [{ key: 'name', values: ['a'] }], filterGroups: [] }],
    })).toBe(false);
  });
});
