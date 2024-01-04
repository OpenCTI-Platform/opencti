import type { JSONSchemaType } from 'ajv';
import type { AttributeConfiguration, ScaleConfig, StixEntitySetting, StoreEntityEntitySetting } from './entitySetting-types';
import { ENTITY_TYPE_ENTITY_SETTING } from './entitySetting-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import convertEntitySettingToStix from './entitySetting-converter';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { validateEntitySettingCreation, validateEntitySettingUpdate } from './entitySetting-validators';

const TARGET_TYPE = 'target_type';

const scaleConfig: JSONSchemaType<ScaleConfig> = {
  type: 'object',
  properties: {
    better_side: { type: 'string' },
    min: {
      type: 'object',
      properties: {
        value: { type: 'number' },
        color: { type: 'string', pattern: '#[a-zA-Z0-9]{6}' },
        label: { type: 'string', minLength: 1 },
      },
      required: ['value', 'color', 'label'],
    },
    max: {
      type: 'object',
      properties: {
        value: { type: 'number' },
        color: { type: 'string', pattern: '#[a-zA-Z0-9]{6}' },
        label: { type: 'string', minLength: 1 },
      },
      required: ['value', 'color', 'label'],
    },
    ticks: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          value: { type: 'number' },
          color: { type: 'string', pattern: '#[a-zA-Z0-9]{6}' },
          label: { type: 'string', minLength: 1 },
        },
        required: ['value', 'color', 'label'],
      }
    },
  },
  required: ['min', 'max'],
};
const attributeConfiguration: JSONSchemaType<AttributeConfiguration[]> = {
  type: 'array',
  items: {
    type: 'object',
    properties: {
      name: { type: 'string', minLength: 1 },
      mandatory: { type: 'boolean' },
      default_values: {
        type: 'array',
        nullable: true,
        items: { type: 'string' }
      },
      scale: {
        type: 'object',
        properties: {
          local_config: scaleConfig
        },
        nullable: true,
        required: ['local_config'],
      }
    },
    required: ['name']
  },
};

export const ENTITY_SETTING_DEFINITION: ModuleDefinition<StoreEntityEntitySetting, StixEntitySetting> = {
  type: {
    id: 'entitysettings',
    name: ENTITY_TYPE_ENTITY_SETTING,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_ENTITY_SETTING]: [{ src: TARGET_TYPE }]
    },
    resolvers: {
      target_type(data: object) {
        return (data as unknown as string).toUpperCase();
      },
    },
  },
  attributes: [
    { name: 'target_type', label: 'Target type', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'platform_entity_files_ref', label: 'Platform entity files ref', type: 'boolean', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: false },
    { name: 'platform_hidden_type', label: 'Platform hidden type', type: 'boolean', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: false },
    { name: 'enforce_reference', label: 'Enforce reference', type: 'boolean', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: false },
    { name: 'attributes_configuration', label: 'Attributes configuration', type: 'string', format: 'json', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, schemaDef: attributeConfiguration, isFilterable: false },
    { name: 'availableSettings', label: 'Available settings', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'workflow_configuration', label: 'Workflow activated', type: 'boolean', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
  relations: [],
  validators: {
    validatorCreation: validateEntitySettingCreation,
    validatorUpdate: validateEntitySettingUpdate
  },
  representative: (stix: StixEntitySetting) => {
    return stix.target_type;
  },
  converter: convertEntitySettingToStix
};

registerDefinition(ENTITY_SETTING_DEFINITION);
