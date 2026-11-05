import { RolesOrdering } from '../../../generated/graphql';
import { ConfigImportMode } from '../../configImport/configImport-types';
import { findAllRoles, findRoles } from '../../user/user-domain';
import { type BasicStoreEntityRole, exportRole } from '../../user/role-export';
import { importRole, roleStandardId } from '../../user/role-import';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetComputedItem, ConfigPresetImporter } from '../import/configPreset-import-types';
import { configPresetPlanKey, recordConfigPresetTarget } from '../import/configPreset-import-types';
import {
  buildConfigPresetConnection,
  namedItemIdentity,
  ROLES_FAMILY_ID,
  securityAccessGroup,
  standardIdListArgs,
  toAppliedStatus,
  toComputedItem,
} from './common-configPreset-registry';

const rolesArgs = (ids?: string[] | null, excludedIds?: string[] | null) => ({ orderBy: RolesOrdering.Name, ...standardIdListArgs(ids, excludedIds) });

const toRoleItem = (role: BasicStoreEntityRole): ConfigPresetItemDefinition => ({
  id: role.standard_id,
  label: role.name,
  translatable: false,
  exporter: async (context, user) => exportRole(context, user, role),
});

const rolesImporter: ConfigPresetImporter = {
  compute: async (context, user, item, plan, mode): Promise<ConfigPresetComputedItem> => {
    // Until the role is known to be written, the groups of the same import that depend on it fail, never get the local role of the same name
    recordConfigPresetTarget(plan, ROLES_FAMILY_ID, item.id, null);
    const { label, failed } = namedItemIdentity(item, roleStandardId, 'The standard id of the role does not match its name');
    if (failed) {
      return failed;
    }
    const result = await importRole(context, user, item.configuration, { mode, dryRun: true, reservedIds: plan.roleIds });
    if (result.status === 'created' && !result.exists) {
      plan.created.add(configPresetPlanKey(ROLES_FAMILY_ID, item.id));
    }
    if (result.targetId) {
      recordConfigPresetTarget(plan, ROLES_FAMILY_ID, item.id, result.targetId);
      plan.roleSensitiveRights?.set(result.targetId, !!result.grantsSensitiveRights);
    }
    return toComputedItem(label, result);
  },
  apply: async (context, user, item, computed, mode) => {
    return toAppliedStatus(await importRole(context, user, item.configuration, { mode }), computed);
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
    const page = await findRoles(context, user, { first, after, search, ...rolesArgs(ids, excludedIds) });
    const edges = page.edges.map(({ cursor, node }) => ({ cursor, node: toRoleItem(node as BasicStoreEntityRole) }));
    return buildConfigPresetConnection(args, edges, page.pageInfo.globalCount, page.pageInfo.hasNextPage);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    if (ids?.length === 0) {
      return [];
    }
    const roles = await findAllRoles(context, user, rolesArgs(ids, excludedIds));
    return (roles as BasicStoreEntityRole[]).map(toRoleItem);
  },
};
