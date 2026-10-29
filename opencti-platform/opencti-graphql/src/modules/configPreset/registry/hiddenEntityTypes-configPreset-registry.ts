import { getPlatformHiddenEntityTypes } from '../../entitySetting/entitySetting-domain';
import { importHiddenEntityTypes } from '../../entitySetting/entitySetting-import';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetComputedItem, ConfigPresetImporter } from '../import/configPreset-import-types';
import { dataModelGroup, staticFamily, toAppliedStatus, toComputedItem } from './common-configPreset-registry';

const HIDDEN_ENTITY_TYPES_ID = 'hiddenEntityTypes';
const HIDDEN_ENTITY_TYPES_LABEL = 'Hidden entity types';

const hiddenEntityTypesItem: ConfigPresetItemDefinition = {
  id: HIDDEN_ENTITY_TYPES_ID,
  label: HIDDEN_ENTITY_TYPES_LABEL,
  translatable: true,
  fileName: 'hidden_entity_types.json',
  exporter: async (context, user) => ({ hidden_entity_types: await getPlatformHiddenEntityTypes(context, user) }),
};

const hiddenEntityTypesImporter: ConfigPresetImporter = {
  compute: async (context, user, item, _plan, mode): Promise<ConfigPresetComputedItem> => {
    const label = { label: HIDDEN_ENTITY_TYPES_LABEL, translatable: true };
    if (item.id !== HIDDEN_ENTITY_TYPES_ID) {
      return { ...label, exists: true, conflict: false, status: 'failed', reason: 'Unexpected item id' };
    }
    const result = await importHiddenEntityTypes(context, user, item.configuration, { mode, dryRun: true });
    // The preview shows the types the platform would hide
    const hidden = result.configuration?.hidden_entity_types ?? [];
    return toComputedItem(label, result, result.configuration ? [{ key: 'hidden_entity_types', value: hidden.length > 0 ? [...hidden].sort().join(', ') : null }] : []);
  },
  apply: async (context, user, item, computed, mode) => {
    return toAppliedStatus(await importHiddenEntityTypes(context, user, item.configuration, { mode }), computed);
  },
};

export const hiddenEntityTypesFamily: ConfigPresetFamilyDefinition = {
  ...staticFamily({
    id: 'hiddenEntityTypes',
    label: HIDDEN_ENTITY_TYPES_LABEL,
    description: 'Entity types hidden in the platform',
    group: dataModelGroup,
    directory: 'data_model',
  }, async () => [hiddenEntityTypesItem]),
  importer: hiddenEntityTypesImporter,
};
