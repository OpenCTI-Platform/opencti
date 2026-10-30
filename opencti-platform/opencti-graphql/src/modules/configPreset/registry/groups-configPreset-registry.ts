import { FilterMode, FilterOperator, OrderingMode } from '../../../generated/graphql';
import { FunctionalError } from '../../../config/errors';
import { fullEntitiesList, fullRelationsList, pageEntitiesConnection } from '../../../database/middleware-loader';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_ROLE } from '../../../schema/internalObject';
import { RELATION_HAS_ROLE } from '../../../schema/internalRelationship';
import type { AuthContext, AuthUser } from '../../../types/user';
import type { BasicStoreRelation } from '../../../types/store';
import { ConfigImportMode } from '../../configImport/configImport-types';
import { type BasicStoreEntityGroup, getGroupConfigPresetConfiguration } from '../../user/configPreset/group-export';
import { groupStandardId, importGroup } from '../../user/configPreset/group-import';
import type { BasicStoreEntityRole } from '../../user/configPreset/role-export';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetComputedItem, ConfigPresetImporter } from '../import/configPreset-import-types';
import { configPresetPlanKey } from '../import/configPreset-import-types';
import { buildConfigPresetConnection, securityAccessGroup } from './common-configPreset-registry';
import { ROLES_FAMILY_ID } from './roles-configPreset-registry';

export const GROUPS_FAMILY_ID = 'groups';

const groupsArgs = (ids?: string[] | null, excludedIds?: string[] | null) => {
  const filters = [
    ...(ids ? [{ key: ['standard_id'], values: ids }] : []),
    ...(excludedIds && excludedIds.length > 0 ? [{ key: ['standard_id'], values: excludedIds, operator: FilterOperator.NotEq }] : []),
  ];
  return {
    orderBy: 'name',
    orderMode: OrderingMode.Asc,
    filters: { mode: FilterMode.And, filters, filterGroups: [] },
  };
};

const toGroupItems = async (context: AuthContext, user: AuthUser, groups: BasicStoreEntityGroup[]): Promise<ConfigPresetItemDefinition[]> => {
  if (groups.length === 0) {
    return [];
  }
  const [relations, roles] = await Promise.all([
    fullRelationsList<BasicStoreRelation>(context, user, RELATION_HAS_ROLE, { fromId: groups.map(({ id }) => id), toTypes: [ENTITY_TYPE_ROLE] }),
    fullEntitiesList<BasicStoreEntityRole>(context, user, [ENTITY_TYPE_ROLE]),
  ]);
  const rolesById = new Map(roles.map((role) => [role.id, role]));
  return groups.map((group) => {
    const groupRoles = relations
      .filter(({ fromId }) => fromId === group.id)
      .map(({ toId }) => rolesById.get(toId))
      .filter((role): role is BasicStoreEntityRole => !!role);
    return {
      id: group.standard_id,
      label: group.name,
      translatable: false,
      dependsOn: groupRoles.map((role) => ({ type: ROLES_FAMILY_ID, id: role.standard_id })),
      exporter: async (ctx, usr) => getGroupConfigPresetConfiguration(ctx, usr, group, groupRoles),
    };
  });
};

const groupsImporter: ConfigPresetImporter = {
  compute: async (context, user, item, plan, mode): Promise<ConfigPresetComputedItem> => {
    const name = typeof item.configuration.name === 'string' ? item.configuration.name : item.id;
    const base = { label: name, translatable: false };
    if (groupStandardId(name) !== item.id) {
      return { ...base, exists: false, conflict: false, status: 'failed', reason: 'The standard id of the group does not match its name' };
    }
    const isRoleCreated = (standardId: string) => plan.created.has(configPresetPlanKey(ROLES_FAMILY_ID, standardId));
    const result = await importGroup(context, user, item.configuration, { mode, dryRun: true, reservedIds: plan.groupIds, isRoleCreated });
    if (result.status === 'created' && !result.exists) {
      plan.created.add(configPresetPlanKey(GROUPS_FAMILY_ID, item.id));
    }
    return { ...base, exists: result.exists, conflict: result.exists, status: result.status, reason: result.reason };
  },
  apply: async (context, user, item, computed, mode) => {
    const result = await importGroup(context, user, item.configuration, { mode });
    if (result.status !== 'created' && result.status !== 'overwritten') {
      throw FunctionalError(result.reason ?? 'Group cannot be imported');
    }
    return result.status === computed.status ? undefined : result.status;
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
    const page = await pageEntitiesConnection<BasicStoreEntityGroup>(context, user, [ENTITY_TYPE_GROUP], { first, after, search, ...groupsArgs(ids, excludedIds) });
    const items = await toGroupItems(context, user, page.edges.map(({ node }) => node));
    const edges = page.edges.map(({ cursor }, index) => ({ cursor, node: items[index] }));
    return buildConfigPresetConnection(args, edges, page.pageInfo.globalCount, page.pageInfo.hasNextPage);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    if (ids?.length === 0) {
      return [];
    }
    return toGroupItems(context, user, await fullEntitiesList<BasicStoreEntityGroup>(context, user, [ENTITY_TYPE_GROUP], groupsArgs(ids, excludedIds)));
  },
};
