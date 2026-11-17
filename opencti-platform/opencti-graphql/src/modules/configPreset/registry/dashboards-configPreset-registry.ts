import { WorkspacesOrdering } from '../../../generated/graphql';
import { ConfigImportMode } from '../../configImport/configImport-types';
import { exportDashboard } from '../../workspace/workspace-export';
import { findAllWorkspaces, findWorkspacePaginated } from '../../workspace/workspace-domain';
import { importDashboard } from '../../workspace/workspace-import';
import type { BasicStoreEntityWorkspace } from '../../workspace/workspace-types';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetImporter, ConfigPresetImportPlan } from '../import/configPreset-import-types';
import { buildConfigPresetConnection, dashboardsGroup, standardIdListArgs, toAppliedItem, toComputedItem } from './common-configPreset-registry';

export const DASHBOARDS_FAMILY_ID = 'dashboards';

// Only the dashboards: an investigation is a workspace too
const dashboardsArgs = (ids?: string[] | null, excludedIds?: string[] | null) => ({
  orderBy: WorkspacesOrdering.Name,
  ...standardIdListArgs(ids, excludedIds, [{ key: ['type'], values: ['dashboard'] }]),
});

// The standard id of a dashboard is random: it is the same in the bundle and on the platform it comes from, not on another one
const toDashboardItem = (workspace: BasicStoreEntityWorkspace): ConfigPresetItemDefinition => ({
  id: workspace.standard_id,
  label: workspace.name,
  translatable: false,
  exporter: async (context, user) => exportDashboard(context, user, workspace),
});

// The names the earlier items of a dry run would take. Kept here, by plan, so that the plan of the engine does not have to know about dashboards
const plannedNames = new WeakMap<ConfigPresetImportPlan, Set<string>>();
const plannedNamesOf = (plan: ConfigPresetImportPlan) => {
  const names = plannedNames.get(plan) ?? new Set<string>();
  plannedNames.set(plan, names);
  return names;
};

const dashboardsImporter: ConfigPresetImporter = {
  // The bundle id cannot be checked against the content: the dashboard is matched by its name, not by its id
  compute: async (context, user, item, plan, mode) => {
    const { name } = item.configuration;
    const label = { label: typeof name === 'string' && name.trim() ? name.trim() : item.id, translatable: false };
    const result = await importDashboard(context, user, item.configuration, { mode, dryRun: true, reservedNames: plannedNamesOf(plan) });
    return toComputedItem(label, result);
  },
  apply: async (context, user, item, computed, mode) => toAppliedItem(await importDashboard(context, user, item.configuration, { mode }), computed),
};

// Dashboards, paged and searched through the workspace domain. An import matches a dashboard by its name:
// it overwrites it, or adds a copy of it under a free name.
export const dashboardsFamily: ConfigPresetFamilyDefinition = {
  importer: dashboardsImporter,
  importModes: [ConfigImportMode.Overwrite, ConfigImportMode.Copy],
  id: DASHBOARDS_FAMILY_ID,
  label: 'Dashboards',
  description: '',
  group: dashboardsGroup,
  directory: 'dashboards',
  listItems: async (context, user, args) => {
    const { first, after, search, ids, excludedIds } = args;
    // An empty list of ids is no dashboard: as a filter value it would match every dashboard
    if (ids?.length === 0) {
      return buildConfigPresetConnection(args, [], 0, false);
    }
    const page = await findWorkspacePaginated(context, user, { first, after, search, ...dashboardsArgs(ids, excludedIds) });
    const edges = page.edges.map(({ cursor, node }) => ({ cursor, node: toDashboardItem(node) }));
    return buildConfigPresetConnection(args, edges, page.pageInfo.globalCount, page.pageInfo.hasNextPage);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    if (ids?.length === 0) {
      return [];
    }
    const workspaces = await findAllWorkspaces(context, user, dashboardsArgs(ids, excludedIds)) as BasicStoreEntityWorkspace[];
    return workspaces.map(toDashboardItem);
  },
};
