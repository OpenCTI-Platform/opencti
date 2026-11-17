import type { AuthContext, AuthUser } from '../../../types/user';
import { ConfigImportMode } from '../../configImport/configImport-types';
import { freeConfigImportName } from '../../configImport/configImport-utils';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetComputedItem, ConfigPresetImporter, ConfigPresetImportPlan } from '../import/configPreset-import-types';
import { configPresetPlanKey } from '../import/configPreset-import-types';
import { automationRulesGroup, matchesListArgs, pageConfigPresetItems, toAppliedStatus, toComputedItem } from './common-configPreset-registry';

export const PLAYBOOKS_FAMILY_ID = 'playbooks';

// The playbook domain loads the components and the whole schema: it is loaded on first use, so that importing the registry stays light
const loadPlaybookImport = () => import('../../playbook/playbook-import');
const loadPlaybookExport = () => import('../../playbook/playbook-export');

const fileNameOf = (id: string) => id.replace(/[^\p{L}\p{N} ._()-]/gu, '_');

// Playbook ids are random and names are not unique: the bundle id of a playbook is its name,
// and the next playbooks of the same name are `name (1)`, `name (2)`... by creation date
const playbookItems = async (context: AuthContext, user: AuthUser): Promise<ConfigPresetItemDefinition[]> => {
  const [{ findPlaybooks }, { exportConfigPresetPlaybook }] = await Promise.all([loadPlaybookImport(), loadPlaybookExport()]);
  const playbooks = [...await findPlaybooks(context, user)]
    .sort((a, b) => String(a.created_at).localeCompare(String(b.created_at)) || String(a.internal_id).localeCompare(String(b.internal_id)));
  const ids = new Set<string>();
  const fileNames = new Set<string>();
  const items: ConfigPresetItemDefinition[] = [];
  for (let i = 0; i < playbooks.length; i += 1) {
    const playbook = playbooks[i];
    const id = await freeConfigImportName(playbook.name, async (candidate) => ids.has(candidate));
    if (id) {
      ids.add(id);
      const fileName = (await freeConfigImportName(fileNameOf(id), async (candidate) => fileNames.has(candidate))) ?? id;
      fileNames.add(fileName);
      items.push({
        id,
        label: playbook.name,
        translatable: false,
        fileName: `${fileName}.json`,
        exporter: async (ctx) => exportConfigPresetPlaybook(ctx, playbook),
      });
    }
  }
  return items.sort((a, b) => a.label.localeCompare(b.label) || a.id.localeCompare(b.id));
};

const reservedNames = new WeakMap<ConfigPresetImportPlan, Set<string>>();
const reservedNamesOf = (plan: ConfigPresetImportPlan) => {
  if (!reservedNames.has(plan)) {
    reservedNames.set(plan, new Set());
  }
  return reservedNames.get(plan) as Set<string>;
};

const playbooksImporter: ConfigPresetImporter = {
  compute: async (context, user, item, plan, mode): Promise<ConfigPresetComputedItem> => {
    const { name } = item.configuration;
    const label = { label: typeof name === 'string' && name.trim() ? name : item.id, translatable: false };
    const names = reservedNamesOf(plan);
    const { importConfigPresetPlaybook } = await loadPlaybookImport();
    const result = await importConfigPresetPlaybook(context, user, item.configuration, { mode, dryRun: true, reservedNames: names });
    if (result.status !== 'failed' && result.name) {
      names.add(result.name);
    }
    if (result.status === 'created' && !result.exists) {
      plan.created.add(configPresetPlanKey(PLAYBOOKS_FAMILY_ID, item.id));
    }
    return toComputedItem(label, result);
  },
  apply: async (context, user, item, computed, mode) => {
    const { importConfigPresetPlaybook } = await loadPlaybookImport();
    return toAppliedStatus(await importConfigPresetPlaybook(context, user, item.configuration, { mode }), computed);
  },
};

export const playbooksFamily: ConfigPresetFamilyDefinition = {
  id: PLAYBOOKS_FAMILY_ID,
  label: 'Playbooks',
  description: 'Playbook definitions, imported stopped',
  group: automationRulesGroup,
  directory: 'automation_rules/playbooks',
  importer: playbooksImporter,
  importModes: [ConfigImportMode.Overwrite, ConfigImportMode.Copy],
  requiresEnterpriseEdition: true,
  listItems: async (context, user, args) => {
    const searched = args.search?.trim().toLowerCase();
    const items = (await playbookItems(context, user))
      .filter((item) => matchesListArgs(item, args) && (!searched || item.label.toLowerCase().includes(searched)));
    return pageConfigPresetItems(items, args);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    return (await playbookItems(context, user)).filter((item) => matchesListArgs(item, { ids, excludedIds }));
  },
};
