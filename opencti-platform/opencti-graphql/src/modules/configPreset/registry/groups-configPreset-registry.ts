import { GroupsOrdering } from '../../../generated/graphql';
import { batchMarkingsForGroups, findAllGroups, findGroupPaginated } from '../../../domain/group';
import { BUILT_IN_MARKING_STANDARD_IDS } from '../../markingDefinition/marking-import';
import type { AuthContext, AuthUser } from '../../../types/user';
import { ConfigImportMode } from '../../configImport/configImport-types';
import { batchRolesForGroups } from '../../user/user-domain';
import { type BasicStoreEntityGroup, exportGroup } from '../../user/group-export';
import { groupStandardId, importGroup } from '../../user/group-import';
import type { BasicStoreEntityRole } from '../../user/role-export';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetComputedItem, ConfigPresetImporter } from '../import/configPreset-import-types';
import { configPresetPlanKey, configPresetTargets } from '../import/configPreset-import-types';
import {
  buildConfigPresetConnection,
  namedItemIdentity,
  MARKINGS_FAMILY_ID,
  ROLES_FAMILY_ID,
  securityAccessGroup,
  standardIdListArgs,
  toAppliedStatus,
  toComputedItem,
} from './common-configPreset-registry';

export const GROUPS_FAMILY_ID = 'groups';

const groupsArgs = (ids?: string[] | null, excludedIds?: string[] | null) => ({ orderBy: GroupsOrdering.Name, ...standardIdListArgs(ids, excludedIds) });

const toGroupItems = async (context: AuthContext, user: AuthUser, groups: BasicStoreEntityGroup[]): Promise<ConfigPresetItemDefinition[]> => {
  const [groupsRoles, groupsMarkings] = await Promise.all([
    batchRolesForGroups(context, user, groups.map(({ id }) => id)) as Promise<BasicStoreEntityRole[][]>,
    batchMarkingsForGroups(context, user, groups) as Promise<{ standard_id: string }[][]>,
  ]);
  return groups.map((group, index) => ({
    id: group.standard_id,
    label: group.name,
    translatable: false,
    dependsOn: [
      ...groupsRoles[index].map((role) => ({ type: ROLES_FAMILY_ID, id: role.standard_id })),
      // A built-in marking exists on every platform: a group never forces its color and order on the target
      ...groupsMarkings[index]
        .filter(({ standard_id }) => !BUILT_IN_MARKING_STANDARD_IDS.includes(standard_id))
        .map((marking) => ({ type: MARKINGS_FAMILY_ID, id: marking.standard_id })),
    ],
    exporter: async (ctx, usr) => exportGroup(ctx, usr, group, groupsRoles[index]),
  }));
};

const groupsImporter: ConfigPresetImporter = {
  compute: async (context, user, item, plan, mode): Promise<ConfigPresetComputedItem> => {
    const { label, failed } = namedItemIdentity(item, groupStandardId, 'The standard id of the group does not match its name');
    if (failed) {
      return failed;
    }
    const plannedRoles = new Map([...(plan.roleSensitiveRights ?? [])].map(([standardId, grantsSensitiveRights]) => [standardId, { grantsSensitiveRights }]));
    const roleTargets = configPresetTargets(plan, ROLES_FAMILY_ID);
    const options = { mode, dryRun: true, reservedIds: plan.groupIds, plannedRoles, roleTargets, plannedMarkings: plan.plannedMarkings };
    const result = await importGroup(context, user, item.configuration, options);
    if (result.status === 'created' && !result.exists) {
      plan.created.add(configPresetPlanKey(GROUPS_FAMILY_ID, item.id));
    }
    return toComputedItem(label, result);
  },
  apply: async (context, user, item, computed, mode, plan) => {
    return toAppliedStatus(await importGroup(context, user, item.configuration, { mode, roleTargets: configPresetTargets(plan, ROLES_FAMILY_ID) }), computed);
  },
};

export const groupsFamily: ConfigPresetFamilyDefinition = {
  importer: groupsImporter,
  importModes: [ConfigImportMode.Overwrite, ConfigImportMode.Copy],
  id: GROUPS_FAMILY_ID,
  label: 'Groups',
  description: 'Groups with their roles, markings and confidence level',
  group: securityAccessGroup,
  directory: 'security_access/groups',
  listItems: async (context, user, args) => {
    const { first, after, search, ids, excludedIds } = args;
    if (ids?.length === 0) {
      return buildConfigPresetConnection(args, [], 0, false);
    }
    const page = await findGroupPaginated(context, user, { first, after, search, ...groupsArgs(ids, excludedIds) });
    const items = await toGroupItems(context, user, page.edges.map(({ node }) => node as BasicStoreEntityGroup));
    const edges = page.edges.map(({ cursor }, index) => ({ cursor, node: items[index] }));
    return buildConfigPresetConnection(args, edges, page.pageInfo.globalCount, page.pageInfo.hasNextPage);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    if (ids?.length === 0) {
      return [];
    }
    return toGroupItems(context, user, await findAllGroups(context, user, groupsArgs(ids, excludedIds)) as BasicStoreEntityGroup[]);
  },
};
