import { exportPolicies } from '../../settings/settings-export';
import { importPolicies } from '../../settings/settings-import';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetComputedItem, ConfigPresetImporter } from '../import/configPreset-import-types';
import { securityAccessGroup, staticFamily, toAppliedStatus, toComputedItem } from './common-configPreset-registry';

export const POLICIES_FAMILY_ID = 'policies';
const POLICIES_LABEL = 'Policies';

const getPoliciesItems = async (): Promise<ConfigPresetItemDefinition[]> => [{
  id: POLICIES_FAMILY_ID,
  label: POLICIES_LABEL,
  translatable: true,
  exporter: (context, user) => exportPolicies(context, user),
}];

const policiesImporter: ConfigPresetImporter = {
  compute: async (context, user, item, _plan, mode): Promise<ConfigPresetComputedItem> => {
    const label = { label: POLICIES_LABEL, translatable: true };
    if (item.id !== POLICIES_FAMILY_ID) {
      return { ...label, exists: true, conflict: false, status: 'failed', reason: 'Unexpected item id' };
    }
    return toComputedItem(label, await importPolicies(context, user, item.configuration, { mode, dryRun: true }));
  },
  apply: async (context, user, item, computed, mode) => {
    return toAppliedStatus(await importPolicies(context, user, item.configuration, { mode }), computed);
  },
};

export const policiesFamily: ConfigPresetFamilyDefinition = {
  ...staticFamily({
    id: POLICIES_FAMILY_ID,
    label: POLICIES_LABEL,
    description: 'Password policy, users visibility and main organization',
    group: securityAccessGroup,
    directory: 'security_access',
  }, getPoliciesItems),
  importer: policiesImporter,
};
