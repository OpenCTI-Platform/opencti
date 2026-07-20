import { describe, it, expect, beforeEach } from 'vitest';
import {
  getCustomFieldDefinitionByLabel,
  getCustomFieldDefinitionByName,
  getCustomFieldDefinitions,
  getCustomFieldDefinitionsForEntityType,
  getCustomFieldSettingForEntityType,
  getCustomFieldValueField,
  setCustomFieldDefinitionsCache,
} from '../../../../src/modules/customField/custom-field-cache';
import type { BasicStoreEntityCustomFieldDefinition } from '../../../../src/modules/customField/custom-field-types';

const makeDefinition = (overrides: Partial<BasicStoreEntityCustomFieldDefinition> = {}): BasicStoreEntityCustomFieldDefinition => ({
  id: 'cf-id-1',
  standard_id: 'custom-field-definition--id-1',
  entity_type: 'CustomFieldDefinition',
  name: 'x_opencti_cf_score',
  label: 'Score',
  description: '',
  field_type: 'integer',
  entity_types: ['Case-Incident'],
  entity_type_settings: [],
  multiple: false,
  ...overrides,
} as unknown as BasicStoreEntityCustomFieldDefinition);

describe('custom-field-cache', () => {
  beforeEach(() => {
    // Reset the module-level cache between tests
    setCustomFieldDefinitionsCache([]);
  });

  it('getCustomFieldDefinitions returns an empty array when nothing is cached', () => {
    expect(getCustomFieldDefinitions()).toEqual([]);
  });

  it('setCustomFieldDefinitionsCache replaces the cache content and getCustomFieldDefinitions reflects it', () => {
    const definitions = [makeDefinition(), makeDefinition({ id: 'cf-id-2', name: 'x_opencti_cf_other' })];
    setCustomFieldDefinitionsCache(definitions);
    expect(getCustomFieldDefinitions()).toEqual(definitions);
  });

  describe('getCustomFieldDefinitionsForEntityType', () => {
    it('returns definitions attached to the given entity type', () => {
      const def = makeDefinition({ entity_types: ['Case-Incident'] });
      setCustomFieldDefinitionsCache([def]);
      expect(getCustomFieldDefinitionsForEntityType('Case-Incident')).toEqual([def]);
    });

    it('excludes definitions not attached to the given entity type', () => {
      const def = makeDefinition({ entity_types: ['Report'] });
      setCustomFieldDefinitionsCache([def]);
      expect(getCustomFieldDefinitionsForEntityType('Case-Incident')).toEqual([]);
    });

    it('excludes definitions with no entity_types at all', () => {
      const def = makeDefinition({ entity_types: undefined });
      setCustomFieldDefinitionsCache([def]);
      expect(getCustomFieldDefinitionsForEntityType('Case-Incident')).toEqual([]);
    });

    it('returns multiple matching definitions attached to several entity types', () => {
      const def1 = makeDefinition({ id: 'cf-1', name: 'x_opencti_cf_a', entity_types: ['Case-Incident', 'Report'] });
      const def2 = makeDefinition({ id: 'cf-2', name: 'x_opencti_cf_b', entity_types: ['Case-Incident'] });
      const def3 = makeDefinition({ id: 'cf-3', name: 'x_opencti_cf_c', entity_types: ['Report'] });
      setCustomFieldDefinitionsCache([def1, def2, def3]);
      expect(getCustomFieldDefinitionsForEntityType('Case-Incident')).toEqual([def1, def2]);
    });
  });

  describe('getCustomFieldSettingForEntityType', () => {
    it('returns the setting matching the entity type', () => {
      const def = makeDefinition({
        entity_type_settings: [
          { entity_type: 'Case-Incident', mandatory: true, default_value: '5' },
          { entity_type: 'Report', mandatory: false },
        ],
      });
      expect(getCustomFieldSettingForEntityType(def, 'Case-Incident')).toEqual({ entity_type: 'Case-Incident', mandatory: true, default_value: '5' });
    });

    it('returns undefined when the definition is not attached to the entity type', () => {
      const def = makeDefinition({ entity_type_settings: [{ entity_type: 'Report', mandatory: false }] });
      expect(getCustomFieldSettingForEntityType(def, 'Case-Incident')).toBeUndefined();
    });

    it('returns undefined when entity_type_settings is empty', () => {
      const def = makeDefinition({ entity_type_settings: [] });
      expect(getCustomFieldSettingForEntityType(def, 'Case-Incident')).toBeUndefined();
    });
  });

  describe('getCustomFieldDefinitionByName', () => {
    it('finds a definition by its technical name', () => {
      const def = makeDefinition({ name: 'x_opencti_cf_score' });
      setCustomFieldDefinitionsCache([def]);
      expect(getCustomFieldDefinitionByName('x_opencti_cf_score')).toEqual(def);
    });

    it('returns undefined when no definition matches the name', () => {
      setCustomFieldDefinitionsCache([makeDefinition({ name: 'x_opencti_cf_score' })]);
      expect(getCustomFieldDefinitionByName('x_opencti_cf_unknown')).toBeUndefined();
    });
  });

  describe('getCustomFieldDefinitionByLabel', () => {
    it('finds a definition by its label', () => {
      const def = makeDefinition({ label: 'Score' });
      setCustomFieldDefinitionsCache([def]);
      expect(getCustomFieldDefinitionByLabel('Score')).toEqual(def);
    });

    it('returns undefined when no definition matches the label', () => {
      setCustomFieldDefinitionsCache([makeDefinition({ label: 'Score' })]);
      expect(getCustomFieldDefinitionByLabel('Unknown label')).toBeUndefined();
    });
  });

  describe('getCustomFieldValueField', () => {
    it.each([
      ['integer', 'int_value'],
      ['string', 'string_value'],
      ['markdown', 'string_value'],
      ['boolean', 'boolean_value'],
      ['date', 'date_value'],
      ['select', 'select_value'],
      ['multi_select', 'select_values'],
    ] as const)('maps field_type %s to value field %s', (fieldType, expected) => {
      expect(getCustomFieldValueField(fieldType)).toEqual(expected);
    });
  });
});
