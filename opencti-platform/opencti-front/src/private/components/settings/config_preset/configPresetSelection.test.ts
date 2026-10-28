import { describe, expect, it } from 'vitest';
import {
  buildConfigPresetItemsFilter,
  buildConfigPresetSelections,
  clearConfigPresetTypeSelection,
  ConfigPresetSelection,
  countConfigPresetCheckedItems,
  countConfigPresetItems,
  getConfigPresetCheckboxState,
  getConfigPresetForcedItems,
  groupConfigPresetTypes,
  isConfigPresetItemSelected,
  isSingletonConfigPresetType,
  selectAllConfigPresetItems,
  toggleConfigPresetItem,
  toggleConfigPresetTypes,
} from './configPresetSelection';

const platformSettings = { key: 'platformSettings', label: 'Platform settings' };
const dataModel = { key: 'dataModel', label: 'Data model' };
const singleton = (key: string, group = platformSettings, dependsOn: { type: string; key: string }[] = []) => ({
  key,
  group,
  items: [{ key, dependsOn }],
  itemsPageInfo: { globalCount: 1 },
});
// The platform configuration depends on the custom default theme
const platform = singleton('platform', platformSettings, [{ type: 'branding', key: 'theme-default' }]);
const hiddenEntityTypes = singleton('hiddenEntityTypes', dataModel);
// 40 themes, the first page holds 3 items
const branding = {
  key: 'branding',
  group: platformSettings,
  items: [{ key: 'theme-0', dependsOn: [] }, { key: 'theme-1', dependsOn: [] }, { key: 'theme-default', dependsOn: [] }],
  itemsPageInfo: { globalCount: 40 },
};
const messages = { key: 'messages', group: platformSettings, items: [{ key: 'banner', dependsOn: [] }, { key: 'login', dependsOn: [] }], itemsPageInfo: { globalCount: 2 } };
const types = [platform, hiddenEntityTypes, branding, messages];
const NO_FORCED = {};

describe('configPresetSelection', () => {
  it('groups the types by export group, in their order', () => {
    expect(groupConfigPresetTypes(types)).toEqual([
      { key: 'platformSettings', label: 'Platform settings', types: [platform, branding, messages] },
      { key: 'dataModel', label: 'Data model', types: [hiddenEntityTypes] },
    ]);
  });

  it('recognizes a singleton type: one item with the key of the type', () => {
    expect(isSingletonConfigPresetType(platform)).toBe(true);
    expect(isSingletonConfigPresetType(branding)).toBe(false);
    expect(isSingletonConfigPresetType({ key: 'branding', items: [{ key: 'theme-1' }] })).toBe(false);
    expect(isSingletonConfigPresetType({ key: 'empty', items: [] })).toBe(false);
  });

  it('selects every item of every type, including the items not loaded yet', () => {
    const all = selectAllConfigPresetItems(types);
    expect(all.branding).toEqual({ mode: 'all', ids: [] });
    expect(isConfigPresetItemSelected(all, 'branding', 'theme-39')).toBe(true);
    expect(countConfigPresetCheckedItems(types, all, NO_FORCED)).toBe(44);
    expect(countConfigPresetItems(types)).toBe(44);
  });

  it('checks or unchecks one item, as an exception of all or as a member of some', () => {
    const allButOne = toggleConfigPresetItem(selectAllConfigPresetItems(types), 'branding', 'theme-1', false);
    expect(allButOne.branding).toEqual({ mode: 'all', ids: ['theme-1'] });
    expect(isConfigPresetItemSelected(allButOne, 'branding', 'theme-1')).toBe(false);
    expect(toggleConfigPresetItem(allButOne, 'branding', 'theme-1', true).branding).toEqual({ mode: 'all', ids: [] });
    const one = toggleConfigPresetItem({}, 'branding', 'theme-1', true);
    expect(one.branding).toEqual({ mode: 'some', ids: ['theme-1'] });
    // No duplicates
    expect(toggleConfigPresetItem(one, 'branding', 'theme-1', true).branding).toEqual({ mode: 'some', ids: ['theme-1'] });
    expect(toggleConfigPresetItem(one, 'branding', 'theme-1', false).branding).toEqual({ mode: 'some', ids: [] });
  });

  it('switches a whole type to all or none, clearing its exceptions', () => {
    const allButOne = toggleConfigPresetItem(selectAllConfigPresetItems(types), 'branding', 'theme-1', false);
    expect(toggleConfigPresetTypes(allButOne, [branding], false).branding).toEqual({ mode: 'some', ids: [] });
    expect(toggleConfigPresetTypes(allButOne, [branding], true).branding).toEqual({ mode: 'all', ids: [] });
    expect(clearConfigPresetTypeSelection(allButOne, 'branding').branding).toEqual({ mode: 'some', ids: [] });
  });

  it('computes the checkbox state of a type or a group from its counts', () => {
    const all = selectAllConfigPresetItems(types);
    expect(getConfigPresetCheckboxState([branding], {}, NO_FORCED)).toBe(false);
    expect(getConfigPresetCheckboxState([branding], all, NO_FORCED)).toBe(true);
    expect(getConfigPresetCheckboxState([branding], toggleConfigPresetItem(all, 'branding', 'theme-1', false), NO_FORCED)).toBe('indeterminate');
    expect(getConfigPresetCheckboxState([platform, messages], toggleConfigPresetTypes(all, [messages], false), NO_FORCED)).toBe('indeterminate');
  });

  it('forces the items a selected item depends on, which count as checked and cannot be excluded', () => {
    const selection: ConfigPresetSelection = { platform: { mode: 'all', ids: [] }, branding: { mode: 'all', ids: ['theme-default', 'theme-1'] } };
    const forced = getConfigPresetForcedItems(types, selection);
    expect(forced).toEqual({ branding: ['theme-default'] });
    expect(countConfigPresetCheckedItems([branding], selection, forced)).toBe(39);
    expect(countConfigPresetCheckedItems([branding], { branding: { mode: 'some', ids: ['theme-1'] } }, forced)).toBe(2);
    // Without the platform configuration, nothing is forced
    expect(getConfigPresetForcedItems(types, toggleConfigPresetItem(selection, 'platform', 'platform', false))).toEqual({});
    expect(getConfigPresetForcedItems(types, toggleConfigPresetTypes(selection, [platform], false))).toEqual({});
  });

  it('builds the items query filters of the sub-view from the selection and the forced items', () => {
    const forced = { branding: ['theme-default'] };
    const allBut: ConfigPresetSelection = { branding: { mode: 'all', ids: ['theme-1', 'theme-default'] } };
    expect(buildConfigPresetItemsFilter(allBut, forced, 'branding', 'all')).toEqual({});
    expect(buildConfigPresetItemsFilter(allBut, forced, 'branding', 'selected')).toEqual({ excludedIds: ['theme-1'] });
    expect(buildConfigPresetItemsFilter(allBut, forced, 'branding', 'excluded')).toEqual({ ids: ['theme-1'] });
    const some: ConfigPresetSelection = { branding: { mode: 'some', ids: ['theme-1'] } };
    expect(buildConfigPresetItemsFilter(some, forced, 'branding', 'selected')).toEqual({ ids: ['theme-1', 'theme-default'] });
    expect(buildConfigPresetItemsFilter(some, forced, 'branding', 'excluded')).toEqual({ excludedIds: ['theme-1', 'theme-default'] });
  });

  it('builds the mutation selections in type order: all with its exclusions, an explicit list, nothing for empty types', () => {
    const selection: ConfigPresetSelection = {
      branding: { mode: 'all', ids: ['theme-1'] },
      platform: { mode: 'all', ids: [] },
      messages: { mode: 'some', ids: [] },
      hiddenEntityTypes: { mode: 'some', ids: ['hiddenEntityTypes'] },
    };
    expect(buildConfigPresetSelections(types, selection)).toEqual([
      { type: 'platform', items: null },
      { type: 'hiddenEntityTypes', items: ['hiddenEntityTypes'] },
      { type: 'branding', items: null, excluded_items: ['theme-1'] },
    ]);
    // A singleton unchecked as an item: all mode with its only item excluded
    expect(buildConfigPresetSelections([platform], toggleConfigPresetItem(selection, 'platform', 'platform', false))).toEqual([]);
    expect(buildConfigPresetSelections(types, {})).toEqual([]);
  });

  it('adds the import mode of the items of a type to its selection, and only the types that have one', () => {
    const selection: ConfigPresetSelection = {
      platform: { mode: 'all', ids: [] },
      hiddenEntityTypes: { mode: 'some', ids: ['hiddenEntityTypes'] },
      branding: { mode: 'all', ids: ['theme-1'] },
    };
    const modes = { 'branding/theme-0': 'COPY', 'branding/theme-default': 'COPY', 'hiddenEntityTypes/hiddenEntityTypes': 'COPY' } as const;
    expect(buildConfigPresetSelections(types, selection, modes)).toEqual([
      { type: 'platform', items: null },
      { type: 'hiddenEntityTypes', items: ['hiddenEntityTypes'], item_modes: [{ key: 'hiddenEntityTypes', mode: 'COPY' }] },
      { type: 'branding', items: null, excluded_items: ['theme-1'], item_modes: [{ key: 'theme-0', mode: 'COPY' }, { key: 'theme-default', mode: 'COPY' }] },
    ]);
    // A type that has no selected item is not sent, the modes with it
    expect(buildConfigPresetSelections(types, { platform: { mode: 'some', ids: [] } }, { 'platform/platform': 'COPY' })).toEqual([]);
  });
});
