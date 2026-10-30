import { FilterMode, FilterOperator, OrderingMode } from '../../../generated/graphql';
import { FunctionalError } from '../../../config/errors';
import { fullEntitiesList, pageEntitiesConnection } from '../../../database/middleware-loader';
import { ENTITY_TYPE_ROLE } from '../../../schema/internalObject';
import { ConfigImportMode } from '../../configImport/configImport-types';
import { type BasicStoreEntityRole, getRoleConfigPresetConfiguration } from '../../user/configPreset/role-export';
import { importRole, roleStandardId } from '../../user/configPreset/role-import';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetComputedItem, ConfigPresetImporter } from '../import/configPreset-import-types';
import { configPresetPlanKey } from '../import/configPreset-import-types';
import { buildConfigPresetConnection, securityAccessGroup } from './common-configPreset-registry';

export const ROLES_FAMILY_ID = 'roles';

const rolesArgs = (ids?: string[] | null, excludedIds?: string[] | null) => {
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

const toRoleItem = (role: BasicStoreEntityRole): ConfigPresetItemDefinition => ({
  id: role.standard_id,
  label: role.name,
  translatable: false,
  exporter: async (context, user) => getRoleConfigPresetConfiguration(context, user, role),
});

const rolesImporter: ConfigPresetImporter = {
  compute: async (context, user, item, plan, mode): Promise<ConfigPresetComputedItem> => {
    const name = typeof item.configuration.name === 'string' ? item.configuration.name : item.id;
    const base = { label: name, translatable: false };
    if (roleStandardId(name) !== item.id) {
      return { ...base, exists: false, conflict: false, status: 'failed', reason: 'The standard id of the role does not match its name' };
    }
    const result = await importRole(context, user, item.configuration, { mode, dryRun: true, reservedIds: plan.roleIds });
    if (result.status === 'created' && !result.exists) {
      plan.created.add(configPresetPlanKey(ROLES_FAMILY_ID, item.id));
    }
    return { ...base, exists: result.exists, conflict: result.exists, status: result.status, reason: result.reason };
  },
  apply: async (context, user, item, computed, mode) => {
    const result = await importRole(context, user, item.configuration, { mode });
    if (result.status !== 'created' && result.status !== 'overwritten') {
      throw FunctionalError(result.reason ?? 'Role cannot be imported');
    }
    return result.status === computed.status ? undefined : result.status;
  },
};

export const rolesFamily: ConfigPresetFamilyDefinition = {
  importer: rolesImporter,
  importModes: [ConfigImportMode.Overwrite, ConfigImportMode.Copy],
  id: ROLES_FAMILY_ID,
  label: 'Roles',
  description: 'Roles and their capabilities',
  group: securityAccessGroup,
  directory: 'security_access/roles',
  listItems: async (context, user, args) => {
    const { first, after, search, ids, excludedIds } = args;
    if (ids?.length === 0) {
      return buildConfigPresetConnection(args, [], 0, false);
    }
    const page = await pageEntitiesConnection<BasicStoreEntityRole>(context, user, [ENTITY_TYPE_ROLE], { first, after, search, ...rolesArgs(ids, excludedIds) });
    const edges = page.edges.map(({ cursor, node }) => ({ cursor, node: toRoleItem(node) }));
    return buildConfigPresetConnection(args, edges, page.pageInfo.globalCount, page.pageInfo.hasNextPage);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    if (ids?.length === 0) {
      return [];
    }
    const roles = await fullEntitiesList<BasicStoreEntityRole>(context, user, [ENTITY_TYPE_ROLE], rolesArgs(ids, excludedIds));
    return roles.map(toRoleItem);
  },
};
