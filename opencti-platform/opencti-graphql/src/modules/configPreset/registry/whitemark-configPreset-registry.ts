import type { AuthContext } from '../../../types/user';
import { getWhitemarkConfigPresetConfiguration } from '../../settings/settings-export';
import { importWhitemark } from '../../settings/settings-import';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetComputedItem, ConfigPresetImporter } from '../import/configPreset-import-types';
import { platformSettingsGroup, staticFamily, toAppliedStatus, toComputedItem, toIsEnabled } from './common-configPreset-registry';

export const WHITEMARK_FAMILY_ID = 'whitemark';
const WHITEMARK_ITEM_ID = 'whitemark';
const WHITEMARK_LABEL = 'Remove Filigran logos';

const getWhitemarkItems = async (context: AuthContext): Promise<ConfigPresetItemDefinition[]> => [{
  id: WHITEMARK_ITEM_ID,
  label: WHITEMARK_LABEL,
  translatable: true,
  isEnabled: toIsEnabled((await getWhitemarkConfigPresetConfiguration(context)).platform_whitemark),
  exporter: (exportContext) => getWhitemarkConfigPresetConfiguration(exportContext),
}];

const whitemarkImporter: ConfigPresetImporter = {
  compute: async (context, user, item, _plan, mode): Promise<ConfigPresetComputedItem> => {
    const label = { label: WHITEMARK_LABEL, translatable: true };
    if (item.id !== WHITEMARK_ITEM_ID) {
      return { ...label, exists: true, conflict: false, status: 'failed', reason: 'Unexpected item id' };
    }
    const result = await importWhitemark(context, user, item.configuration, { mode, dryRun: true });
    // The preview shows the value of the bundle: on, off, or nothing when it does not set it
    return { ...toComputedItem(label, result), isEnabled: toIsEnabled(result.configuration?.platform_whitemark) };
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
    // Nothing to add to the label: the preview shows the value of the setting under it
    description: '',
    group: platformSettingsGroup,
    directory: 'platform_settings',
  }, getWhitemarkItems),
  importer: whitemarkImporter,
  requiresEnterpriseEdition: true,
};
