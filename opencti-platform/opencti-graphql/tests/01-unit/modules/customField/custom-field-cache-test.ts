import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as cacheModule from '../../../../src/database/cache';
import {
  getCustomFieldDefinitionByLabel,
  getCustomFieldDefinitionByName,
  getCustomFieldDefinitions,
  getCustomFieldDefinitionsForEntityType,
  getCustomFieldSettingForEntityType,
  getCustomFieldValueField,
} from '../../../../src/modules/customField/custom-field-cache';
import type { BasicStoreEntityCustomFieldDefinition } from '../../../../src/modules/customField/custom-field-types';

const CONTEXT = {} as any;
const USER = { id: 'user-1' } as any;

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

const seed = (...definitions: BasicStoreEntityCustomFieldDefinition[]) => {
  vi.spyOn(cacheModule, 'getEntitiesListFromCache').mockResolvedValue(definitions);
};

describe('custom-field-cache', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('getCustomFieldDefinitions returns an empty array when the cache is empty', async () => {
    seed();
    expect(await getCustomFieldDefinitions(CONTEXT, USER)).toEqual([]);
  });

  it('getCustomFieldDefinitions reads through the generic cache for the CustomFieldDefinition entity type', async () => {
    const definitions = [makeDefinition(), makeDefinition({ id: 'cf-id-2', name: 'x_opencti_cf_other' })];
    seed(...definitions);
    expect(await getCustomFieldDefinitions(CONTEXT, USER)).toEqual(definitions);
    expect(cacheModule.getEntitiesListFromCache).toHaveBeenCalledWith(CONTEXT, USER, 'CustomFieldDefinition');
  });

  describe('getCustomFieldDefinitionsForEntityType', () => {
    it('returns definitions attached to the given entity type', async () => {
      const def = makeDefinition({ entity_types: ['Case-Incident'] });
      seed(def);
      expect(await getCustomFieldDefinitionsForEntityType(CONTEXT, USER, 'Case-Incident')).toEqual([def]);
    });

    it('excludes definitions not attached to the given entity type', async () => {
      const def = makeDefinition({ entity_types: ['Report'] });
      seed(def);
      expect(await getCustomFieldDefinitionsForEntityType(CONTEXT, USER, 'Case-Incident')).toEqual([]);
    });

    it('excludes definitions with no entity_types at all', async () => {
      const def = makeDefinition({ entity_types: undefined });
      seed(def);
      expect(await getCustomFieldDefinitionsForEntityType(CONTEXT, USER, 'Case-Incident')).toEqual([]);
    });

    it('returns multiple matching definitions attached to several entity types', async () => {
      const def1 = makeDefinition({ id: 'cf-1', name: 'x_opencti_cf_a', entity_types: ['Case-Incident', 'Report'] });
      const def2 = makeDefinition({ id: 'cf-2', name: 'x_opencti_cf_b', entity_types: ['Case-Incident'] });
      const def3 = makeDefinition({ id: 'cf-3', name: 'x_opencti_cf_c', entity_types: ['Report'] });
      seed(def1, def2, def3);
      expect(await getCustomFieldDefinitionsForEntityType(CONTEXT, USER, 'Case-Incident')).toEqual([def1, def2]);
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
    it('finds a definition by its technical name', async () => {
      const def = makeDefinition({ name: 'x_opencti_cf_score' });
      seed(def);
      expect(await getCustomFieldDefinitionByName(CONTEXT, USER, 'x_opencti_cf_score')).toEqual(def);
    });

    it('returns undefined when no definition matches the name', async () => {
      seed(makeDefinition({ name: 'x_opencti_cf_score' }));
      expect(await getCustomFieldDefinitionByName(CONTEXT, USER, 'x_opencti_cf_unknown')).toBeUndefined();
    });
  });

  describe('getCustomFieldDefinitionByLabel', () => {
    it('finds a definition by its label', async () => {
      const def = makeDefinition({ label: 'Score' });
      seed(def);
      expect(await getCustomFieldDefinitionByLabel(CONTEXT, USER, 'Score')).toEqual(def);
    });

    it('returns undefined when no definition matches the label', async () => {
      seed(makeDefinition({ label: 'Score' }));
      expect(await getCustomFieldDefinitionByLabel(CONTEXT, USER, 'Unknown label')).toBeUndefined();
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
