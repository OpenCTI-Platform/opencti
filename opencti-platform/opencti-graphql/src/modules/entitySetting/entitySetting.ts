import type { StixEntitySetting, StoreEntityEntitySetting } from './entitySetting-types';
import { ENTITY_TYPE_ENTITY_SETTING } from './entitySetting-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import entitySettingResolvers from './entitySetting-resolvers';
import entitySettingTypeDefs from './entitySetting.graphql';
import convertEntitySettingToStix from './entitySetting-converter';
import { attributeConfiguration, } from './entitySetting-utils';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { validateEntitySettingCreation, validateEntitySettingUpdate } from './entitySetting-validators';

const TARGET_TYPE = 'target_type';

const ENTITY_SETTING_DEFINITION: ModuleDefinition<StoreEntityEntitySetting, StixEntitySetting> = {
  type: {
    id: 'entitysettings',
    name: ENTITY_TYPE_ENTITY_SETTING,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  graphql: {
    schema: entitySettingTypeDefs,
    resolver: entitySettingResolvers,
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
    { name: 'target_type', label: 'Target type', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'platform_entity_files_ref', label: 'Platform entity files ref', type: 'boolean', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: false },
    { name: 'platform_hidden_type', label: 'Platform hidden type', type: 'boolean', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: false },
    { name: 'enforce_reference', label: 'Enforce reference', type: 'boolean', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: false },
    { name: 'attributes_configuration', label: 'Attributes configuration', type: 'json', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, schemaDef: attributeConfiguration, isFilterable: false },
    { name: 'availableSettings', label: 'Available settings', type: 'string', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
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
