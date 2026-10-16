import { getPlatformHiddenEntityTypes } from '../../entitySetting/entitySetting-domain';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import { dataModelGroup } from './common-configPreset-registry';

const hiddenEntityTypesItem: ConfigPresetItemDefinition = {
  id: 'hiddenEntityTypes',
  label: 'Hidden entity types',
  translatable: true,
  fileName: 'hidden_entity_types.json',
  exporter: async (context, user) => ({ hidden_entity_types: await getPlatformHiddenEntityTypes(context, user) }),
};

export const hiddenEntityTypesFamily: ConfigPresetFamilyDefinition = {
  id: 'hiddenEntityTypes',
  label: 'Hidden entity types',
  group: dataModelGroup,
  directory: 'data_model',
  listItems: async () => [hiddenEntityTypesItem],
};
