import { describe, expect, it } from 'vitest';
import {
  buildConfigPresetSelections,
  countConfigPresetCheckedItems,
  countConfigPresetItems,
  getConfigPresetCheckboxState,
  groupConfigPresetTypes,
  isSingletonConfigPresetType,
  selectAllConfigPresetItems,
  toggleConfigPresetItem,
  toggleConfigPresetTypes,
} from './configPresetSelection';

const platformSettings = { id: 'platformSettings', label: 'Platform settings' };
const dataModel = { id: 'dataModel', label: 'Data model' };
const platform = { id: 'platform', group: platformSettings, items: [{ id: 'platform' }] };
const messages = { id: 'messages', group: platformSettings, items: [{ id: 'messages' }] };
const hiddenEntityTypes = { id: 'hiddenEntityTypes', group: dataModel, items: [{ id: 'hiddenEntityTypes' }] };
// A type listing entities, as entity-backed types will
const templates = { id: 'templates', group: platformSettings, items: [{ id: 'template-1' }, { id: 'template-2' }] };
const types = [platform, hiddenEntityTypes, messages, templates];

describe('configPresetSelection', () => {
  it('groups the types by export group, in catalog order', () => {
    expect(groupConfigPresetTypes(types)).toEqual([
      { id: 'platformSettings', label: 'Platform settings', types: [platform, messages, templates] },
      { id: 'dataModel', label: 'Data model', types: [hiddenEntityTypes] },
    ]);
  });

  it('recognizes a singleton type: one item with the id of the type', () => {
    expect(isSingletonConfigPresetType(platform)).toBe(true);
    expect(isSingletonConfigPresetType(templates)).toBe(false);
    expect(isSingletonConfigPresetType({ id: 'templates', items: [{ id: 'template-1' }] })).toBe(false);
    expect(isSingletonConfigPresetType({ id: 'empty', items: [] })).toBe(false);
  });

  it('selects every item of every type', () => {
    expect(selectAllConfigPresetItems(types)).toEqual({
      platform: ['platform'],
      hiddenEntityTypes: ['hiddenEntityTypes'],
      messages: ['messages'],
      templates: ['template-1', 'template-2'],
    });
  });

  it('counts the items and the checked items of several types, ignoring ids that are not in the catalog', () => {
    const group = [platform, messages, templates];
    expect(countConfigPresetItems(group)).toBe(4);
    expect(countConfigPresetCheckedItems(group, {})).toBe(0);
    expect(countConfigPresetCheckedItems(group, { messages: ['messages', 'unknown'], templates: ['template-2'] })).toBe(2);
    expect(countConfigPresetCheckedItems(group, selectAllConfigPresetItems(types))).toBe(4);
  });

  it('computes the checkbox state of a type or a group from its checked items', () => {
    expect(getConfigPresetCheckboxState([templates], {})).toBe(false);
    expect(getConfigPresetCheckboxState([templates], { templates: [] })).toBe(false);
    expect(getConfigPresetCheckboxState([templates], { templates: ['template-1'] })).toBe('indeterminate');
    expect(getConfigPresetCheckboxState([platform], { platform: ['platform'] })).toBe(true);
    expect(getConfigPresetCheckboxState([platform, messages], { platform: ['platform'] })).toBe('indeterminate');
    expect(getConfigPresetCheckboxState([platform, messages], selectAllConfigPresetItems(types))).toBe(true);
  });

  it('checks or unchecks all the items of a type or a group at once', () => {
    const unchecked = toggleConfigPresetTypes(selectAllConfigPresetItems(types), [platform, templates], false);
    expect(unchecked).toEqual({ platform: [], hiddenEntityTypes: ['hiddenEntityTypes'], messages: ['messages'], templates: [] });
    expect(toggleConfigPresetTypes(unchecked, [templates], true).templates).toEqual(['template-1', 'template-2']);
  });

  it('checks or unchecks one item, without duplicates', () => {
    const withTemplate = toggleConfigPresetItem({}, 'templates', 'template-1', true);
    expect(withTemplate).toEqual({ templates: ['template-1'] });
    expect(toggleConfigPresetItem(withTemplate, 'templates', 'template-1', true)).toEqual({ templates: ['template-1'] });
    expect(toggleConfigPresetItem(withTemplate, 'templates', 'template-1', false)).toEqual({ templates: [] });
  });

  it('builds the mutation selections in catalog order, without empty types', () => {
    const selection = { templates: ['template-2', 'template-1'], platform: ['platform'], messages: [] };
    expect(buildConfigPresetSelections(types, selection)).toEqual([
      { type: 'platform', items: ['platform'] },
      { type: 'templates', items: ['template-1', 'template-2'] },
    ]);
    expect(buildConfigPresetSelections(types, {})).toEqual([]);
  });
});
