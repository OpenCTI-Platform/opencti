import { describe, expect, it } from 'vitest';
import { CUSTOM_VIEW_NAME_MAX_LENGTH, customViewImportSchema } from '../../../../src/modules/customView/customView-import-schema';
import { toB64 } from '../../../../src/utils/base64';

const widget = { id: 'widget1', type: 'number', dataSelection: [] };

describe('Custom view configuration of a bundle (schema)', () => {
  it('accepts a name and an entity type alone, and every field of an export', () => {
    expect(customViewImportSchema.safeParse({ name: 'Executive overview', target_entity_type: 'Report' }).success).toBe(true);
    const full = { name: 'Executive overview', target_entity_type: 'Report', description: 'The executives', manifest: toB64({ config: {}, widgets: { widget1: widget } }) };
    expect(customViewImportSchema.parse(full)).toEqual(full);
  });

  it('trims the name and the entity type, and leaves a field that is null or absent to the view', () => {
    // A view is found by its name: the platform never stores one with spaces around it, so neither does the import look for one
    expect(customViewImportSchema.parse({ name: '  Executive overview  ', target_entity_type: ' Report ' })).toEqual({ name: 'Executive overview', target_entity_type: 'Report' });
    expect(customViewImportSchema.parse({ name: 'x', target_entity_type: 'Report', description: null, manifest: null }))
      .toEqual({ name: 'x', target_entity_type: 'Report', description: null, manifest: null });
  });

  it('trims the description as the platform stores it, so that a padded one is not patched at every overwrite', () => {
    expect(customViewImportSchema.parse({ name: 'x', target_entity_type: 'Report', description: '  The executives \n' }).description).toBe('The executives');
    expect(customViewImportSchema.parse({ name: 'x', target_entity_type: 'Report', description: '   ' }).description).toBe('');
  });

  it.each([
    ['no name', { target_entity_type: 'Report' }],
    ['an empty name', { name: '', target_entity_type: 'Report' }],
    ['a blank name', { name: '    ', target_entity_type: 'Report' }],
    ['a name over the limit', { name: 'a'.repeat(CUSTOM_VIEW_NAME_MAX_LENGTH + 1), target_entity_type: 'Report' }],
    ['a name that is not a string', { name: 42, target_entity_type: 'Report' }],
    // the file import lets the user choose the entity type, a bundle always has it: it is part of the identity of the view
    ['no entity type', { name: 'Executive overview' }],
    ['a blank entity type', { name: 'Executive overview', target_entity_type: '  ' }],
    ['an unknown key', { name: 'Executive overview', target_entity_type: 'Report', unknown: true }],
    // whether a view is shown or the default of its entity type is for the platform that imports it to decide
    ['whether the view is enabled', { name: 'Executive overview', target_entity_type: 'Report', enabled: true }],
    ['whether the view is the default', { name: 'Executive overview', target_entity_type: 'Report', default: true }],
    ['a manifest that is not base64 json', { name: 'Executive overview', target_entity_type: 'Report', manifest: 'not a manifest' }],
    ['a manifest that is not an object', { name: 'Executive overview', target_entity_type: 'Report', manifest: toB64([1]) }],
    ['a widget that is not an object', { name: 'Executive overview', target_entity_type: 'Report', manifest: toB64({ widgets: { widget1: 'text' } }) }],
    ['a widget without data selection', { name: 'Executive overview', target_entity_type: 'Report', manifest: toB64({ widgets: { widget1: { id: 'widget1', type: 'number' } } }) }],
    ['a data selection that holds a null', { name: 'Executive overview', target_entity_type: 'Report', manifest: toB64({ widgets: { widget1: { id: 'widget1', dataSelection: [null] } } }) }],
    ['a data selection that holds a value that is not an object', { name: 'Executive overview', target_entity_type: 'Report', manifest: toB64({ widgets: { widget1: { id: 'widget1', dataSelection: ['text'] } } }) }],
    ['widgets that are a list', { name: 'Executive overview', target_entity_type: 'Report', manifest: toB64({ widgets: [widget] }) }],
  ])('refuses %s', (_label, configuration) => {
    expect(customViewImportSchema.safeParse(configuration).success).toBe(false);
  });

  it('accepts a name of the limit, and a manifest with no widget', () => {
    expect(customViewImportSchema.safeParse({ name: 'a'.repeat(CUSTOM_VIEW_NAME_MAX_LENGTH), target_entity_type: 'Report' }).success).toBe(true);
    expect(customViewImportSchema.safeParse({ name: 'ab', target_entity_type: 'Report', manifest: toB64({ config: {} }) }).success).toBe(true);
    expect(customViewImportSchema.safeParse({ name: 'ab', target_entity_type: 'Report', manifest: '' }).success).toBe(true);
  });
});
