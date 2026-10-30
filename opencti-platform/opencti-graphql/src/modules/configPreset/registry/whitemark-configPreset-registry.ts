import type { AuthContext } from '../../../types/user';
import { getWhitemarkConfigPresetConfiguration } from '../../settings/settings-export';
import { importWhitemark } from '../../settings/settings-import';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetComputedItem, ConfigPresetImporter } from '../import/configPreset-import-types';
import { platformSettingsGroup, staticFamily, toAppliedStatus, toComputedItem } from './common-configPreset-registry';

export const WHITEMARK_FAMILY_ID = 'whitemark';
const WHITEMARK_ITEM_ID = 'whitemark';
const WHITEMARK_LABEL = 'Remove Filigran logos';

const getWhitemarkItems = async (_context: AuthContext): Promise<ConfigPresetItemDefinition[]> => [{
  id: WHITEMARK_ITEM_ID,
  label: WHITEMARK_LABEL,
  translatable: true,
  exporter: (context) => getWhitemarkConfigPresetConfiguration(context),
}];

const whitemarkImporter: ConfigPresetImporter = {
  compute: async (context, user, item, _plan, mode): Promise<ConfigPresetComputedItem> => {
    const label = { label: WHITEMARK_LABEL, translatable: true };
    if (item.id !== WHITEMARK_ITEM_ID) {
      return { ...label, exists: true, conflict: false, status: 'failed', reason: 'Unexpected item id' };
    }
    return toComputedItem(label, await importWhitemark(context, user, item.configuration, { mode, dryRun: true }));
  },
  apply: async (context, user, item, computed, mode) => {
    return toAppliedStatus(await importWhitemark(context, user, item.configuration, { mode }), computed);
  },
};

// The whitemark is an Enterprise Edition setting: the platform exports it, and applies it, only with the Enterprise Edition
export const whitemarkFamily: ConfigPresetFamilyDefinition = {
  ...staticFamily({
    id: WHITEMARK_FAMILY_ID,
    label: WHITEMARK_LABEL,
    description: 'Whitemark',
    group: platformSettingsGroup,
    directory: 'platform_settings',
  }, getWhitemarkItems),
  importer: whitemarkImporter,
  requiresEnterpriseEdition: true,
};
