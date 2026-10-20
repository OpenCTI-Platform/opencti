import { getPlatformHiddenEntityTypes } from '../../entitySetting/entitySetting-domain';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import { dataModelGroup, staticFamily } from './common-configPreset-registry';

const hiddenEntityTypesItem: ConfigPresetItemDefinition = {
  id: 'hiddenEntityTypes',
  label: 'Hidden entity types',
  translatable: true,
  fileName: 'hidden_entity_types.json',
  exporter: async (context, user) => ({ hidden_entity_types: await getPlatformHiddenEntityTypes(context, user) }),
};

export const hiddenEntityTypesFamily: ConfigPresetFamilyDefinition = staticFamily({
  id: 'hiddenEntityTypes',
  label: 'Hidden entity types',
  description: 'Entity types hidden in the platform',
  group: dataModelGroup,
  directory: 'data_model',
}, async () => [hiddenEntityTypesItem]);
