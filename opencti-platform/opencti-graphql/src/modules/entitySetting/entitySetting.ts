import { ModuleDefinition, registerDefinition } from '../../types/module';
import type { StoreEntityEntitySetting } from './entitySetting-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { ENTITY_TYPE_ENTITY_SETTING } from '../../schema/internalObject';
import entitySettingResolvers from './entitySetting-resolvers';
import entitySettingTypeDefs from './entitySetting.graphql';
import convertEntitySettingToStix from './entitySetting-converter';

const TARGET_TYPE = 'target_type';

const ENTITY_SETTING_DEFINITION: ModuleDefinition<StoreEntityEntitySetting> = {
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
    { name: 'target_type', type: 'string', multiple: false, upsert: false },
    { name: 'platform_entity_files_ref', type: 'boolean', multiple: false, upsert: true },
    { name: 'platform_hidden_type', type: 'boolean', multiple: false, upsert: true },
    { name: 'enforce_reference', type: 'boolean', multiple: false, upsert: true },
  ],
  relations: [],
  converter: convertEntitySettingToStix
};

registerDefinition(ENTITY_SETTING_DEFINITION);
