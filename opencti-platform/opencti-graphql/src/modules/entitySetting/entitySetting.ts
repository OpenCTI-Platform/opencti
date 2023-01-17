import { ENTITY_TYPE_ENTITY_SETTING } from './entitySetting-types';
import type { StixEntitySetting, StoreEntityEntitySetting } from './entitySetting-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import entitySettingResolvers from './entitySetting-resolvers';
import entitySettingTypeDefs from './entitySetting.graphql';
import convertEntitySettingToStix from './entitySetting-converter';
import {
  attributeConfiguration, confidenceScale,
  validateEntitySettingCreation,
  validateEntitySettingUpdate
} from './entitySetting-utils';
import { moduleRegisterDefinition, ModuleRegisterDefinition } from '../../schema/module-register';

const TARGET_TYPE = 'target_type';

const ENTITY_SETTING_DEFINITION: ModuleRegisterDefinition<StoreEntityEntitySetting, StixEntitySetting> = {
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
    { name: 'target_type', type: 'string', mandatoryType: 'internal', multiple: false, upsert: false },
    { name: 'platform_entity_files_ref', type: 'boolean', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'platform_hidden_type', type: 'boolean', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'enforce_reference', type: 'boolean', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'attributes_configuration', type: 'json', mandatoryType: 'no', multiple: false, upsert: false, schemaDef: attributeConfiguration },
    { name: 'confidence_scale', type: 'json', mandatoryType: 'no', multiple: false, upsert: true, schemaDef: confidenceScale },
  ],
  relations: [],
  representative: (stix: StixEntitySetting) => {
    return stix.target_type;
  },
  converter: convertEntitySettingToStix,
  validators: {
    validatorCreation: validateEntitySettingCreation,
    validatorUpdate: validateEntitySettingUpdate
  }
};

moduleRegisterDefinition(ENTITY_SETTING_DEFINITION);
