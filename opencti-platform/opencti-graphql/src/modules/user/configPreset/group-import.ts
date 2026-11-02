import type { AuthContext, AuthUser } from '../../../types/user';
import type { BasicStoreEntity } from '../../../types/store';
import type { EditInput } from '../../../generated/graphql';
import { getEntitiesMapFromCache } from '../../../database/cache';
import { fullEntitiesThroughRelationsToList, storeLoadById } from '../../../database/middleware-loader';
import { addGroup } from '../../../domain/grant';
import { findById as findGroupById, groupAddRelation, groupAllowedMarkings, groupDeleteRelation, groupEditField } from '../../../domain/group';
import { generateStandardId } from '../../../schema/identifier';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_ROLE } from '../../../schema/internalObject';
import { RELATION_ACCESSES_TO, RELATION_HAS_ROLE } from '../../../schema/internalRelationship';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../schema/stixMetaObject';
import { BYPASS, ROLE_ADMINISTRATOR, SYSTEM_USER } from '../../../utils/access';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../../configImport/configImport-types';
import { configImportValidationReason, freeConfigImportName, joinConfigImportReasons } from '../../configImport/configImport-utils';
import { CONFIG_IMPORT_SENSITIVE_REASON, isConfigImportSensitiveChangeAllowed } from '../../configImport/configImport-sensitive';
import { ENTITY_TYPE_WORKSPACE } from '../../workspace/workspace-types';
import { findRoleById, roleCapabilities } from '../user-domain';
import type { BasicStoreEntityGroup } from './group-export';
import type { BasicStoreEntityRole } from './role-export';
import { roleStandardId, SENSITIVE_RIGHTS_REASON } from './role-import';
import { type GroupImportConfiguration, groupImportSchema, type GroupMarkingReference } from './group-import-schema';

export interface GroupImportOptions extends ConfigImportOptions {
  reservedIds?: Set<string>;
  isRoleCreated?: (standardId: string) => boolean;
  // In a dry run, whether a role the same import creates or overwrites will give sensitive rights; undefined when the import does not write it
  isRoleSensitive?: (standardId: string) => boolean | undefined;
}

export type GroupImportCode = 'invalid' | 'role_missing' | 'exists' | 'name_conflict' | 'sensitive_config';

export type GroupImportResult = ConfigImportResult<GroupImportConfiguration, GroupImportCode> & {
  group?: BasicStoreEntityGroup;
};

const refused = (code: GroupImportCode, reason: string, exists: boolean, configuration?: GroupImportConfiguration): GroupImportResult => {
  return { status: 'failed', code, reason, exists, configuration };
};

export const groupStandardId = (name: string): string => generateStandardId(ENTITY_TYPE_GROUP, { name });

const GROUP_FIELDS = [
  'description',
  'default_assignation',
  'auto_integration_assignation',
  'no_creators',
  'restrict_delete',
  'auto_new_marking',
  'group_confidence_level',
  'default_hidden_types',
] as const;

const NEW_USERS_REASON = 'New users join this group automatically';
const INTEGRATION_USERS_REASON = 'New integration users join this group automatically';
const ADMINISTRATOR_ROLE_KEPT_REASON = 'The Administrators group keeps the Administrator role';

const ADMINISTRATORS_GROUP = 'Administrators';

interface ResolvedGroup {
  fields: Record<string, unknown>;
  roleIds: string[];
  markingIds: string[];
  missingMarkings: string[];
  missingDashboard?: string;
}

const resolveGroup = async (context: AuthContext, user: AuthUser, configuration: GroupImportConfiguration, roles: BasicStoreEntity[]): Promise<ResolvedGroup> => {
  const markings = await getEntitiesMapFromCache<BasicStoreEntity>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  const missingMarkings = new Set<string>();
  const resolve = (reference: GroupMarkingReference) => {
    const marking = markings.get(reference.standard_id);
    if (!marking) {
      missingMarkings.add(reference.definition);
    }
    return marking?.id;
  };
  const resolveAll = (references: GroupMarkingReference[]) => references.map(resolve).filter((id): id is string => !!id);
  const { default_dashboard: dashboardReference } = configuration;
  const dashboard = dashboardReference ? await storeLoadById<BasicStoreEntity>(context, user, dashboardReference.standard_id, ENTITY_TYPE_WORKSPACE) : undefined;
  const fields: Record<string, unknown> = Object.fromEntries(GROUP_FIELDS.map((key) => [key, configuration[key]]));
  fields.default_dashboard = dashboard?.id;
  fields.default_marking = configuration.default_marking.map(({ entity_type, values }) => ({ entity_type, values: resolveAll(values) }));
  fields.max_shareable_markings = configuration.max_shareable_markings.map(({ type, value }) => ({ type, value: (value === 'none' ? undefined : resolve(value)) ?? 'none' }));
  return {
    fields,
    roleIds: roles.map(({ id }) => id),
    markingIds: resolveAll(configuration.allowed_markings),
    missingMarkings: [...missingMarkings],
    missingDashboard: dashboardReference && !dashboard ? dashboardReference.name : undefined,
  };
};

const freeGroupName = (context: AuthContext, user: AuthUser, name: string, { reservedIds }: GroupImportOptions) => {
  return freeConfigImportName(name, async (candidate) => {
    const standardId = groupStandardId(candidate);
    return !!reservedIds?.has(standardId) || !!(await findGroupById(context, user, standardId));
  });
};

const definedFields = (fields: Record<string, unknown>) => Object.entries(fields).filter(([, value]) => value !== null && value !== undefined);

const replaceRelations = async (context: AuthContext, user: AuthUser, groupId: string, currentIds: string[], ids: string[], relationshipType: string) => {
  const added = ids.filter((id) => !currentIds.includes(id));
  const removed = currentIds.filter((id) => !ids.includes(id));
  for (let i = 0; i < added.length; i += 1) {
    await groupAddRelation(context, user, groupId, { toId: added[i], relationship_type: relationshipType });
  }
  for (let i = 0; i < removed.length; i += 1) {
    await groupDeleteRelation(context, user, groupId, undefined, removed[i], relationshipType);
  }
};

const currentRoleIds = async (context: AuthContext, user: AuthUser, groupId: string) => {
  return (await fullEntitiesThroughRelationsToList(context, user, groupId, RELATION_HAS_ROLE, ENTITY_TYPE_ROLE)).map(({ id }) => id);
};

const currentMarkingIds = async (context: AuthContext, user: AuthUser, groupId: string) => {
  return ((await groupAllowedMarkings(context, user, groupId)) as BasicStoreEntity[]).map(({ id }) => id);
};

const createGroup = async (context: AuthContext, user: AuthUser, name: string, resolved: ResolvedGroup): Promise<BasicStoreEntityGroup> => {
  const group = await addGroup(context, user, { name, ...Object.fromEntries(definedFields(resolved.fields)) });
  await replaceRelations(context, user, group.id, [], resolved.roleIds, RELATION_HAS_ROLE);
  await replaceRelations(context, user, group.id, [], resolved.markingIds, RELATION_ACCESSES_TO);
  return group;
};

const overwriteGroup = async (context: AuthContext, user: AuthUser, existing: BasicStoreEntityGroup, resolved: ResolvedGroup) => {
  const input: EditInput[] = definedFields(resolved.fields)
    .filter(([key, value]) => JSON.stringify(existing[key as keyof BasicStoreEntityGroup] ?? null) !== JSON.stringify(value))
    .map(([key, value]) => ({ key, value: Array.isArray(value) ? value : [value] }));
  if (input.length > 0) {
    await groupEditField(context, user, existing.id, input);
  }
  await replaceRelations(context, user, existing.id, await currentRoleIds(context, user, existing.id), resolved.roleIds, RELATION_HAS_ROLE);
  await replaceRelations(context, user, existing.id, await currentMarkingIds(context, user, existing.id), resolved.markingIds, RELATION_ACCESSES_TO);
  return (await findGroupById(context, user, existing.id)) as BasicStoreEntityGroup;
};

// The Administrator role is never removed from the Administrators group: an import must not take the bypass away from the administrators
const withAdministratorRole = async (context: AuthContext, user: AuthUser, groupId: string, roles: BasicStoreEntityRole[]) => {
  if (groupId !== groupStandardId(ADMINISTRATORS_GROUP)) {
    return { roles, administratorRoleKept: false };
  }
  const administratorRole = await findRoleById(context, user, roleStandardId(ROLE_ADMINISTRATOR)) as BasicStoreEntityRole | undefined;
  if (!administratorRole || roles.some(({ id }) => id === administratorRole.id)) {
    return { roles, administratorRoleKept: false };
  }
  return { roles: [...roles, administratorRole], administratorRoleKept: true };
};

const grantsSensitiveRights = async (
  context: AuthContext,
  user: AuthUser,
  references: string[],
  roles: BasicStoreEntityRole[],
  currentIds: string[],
  isRoleSensitive: (standardId: string) => boolean | undefined,
) => {
  for (let i = 0; i < references.length; i += 1) {
    const role = roles.find(({ standard_id }) => standard_id === references[i]);
    if (!role || !currentIds.includes(role.id)) {
      // The rights the same import gives the role first, then the ones it has on the platform
      const planned = isRoleSensitive(references[i]);
      const sensitive = planned ?? (!!role && (!!role.can_manage_sensitive_config || (await roleCapabilities(context, user, role.id)).some(({ name }) => name === BYPASS)));
      if (sensitive) {
        return true;
      }
    }
  }
  return false;
};

// The automatic assignments are imported as they are, and shown in the preview when the group does not have them yet
const assignmentReasons = (configuration: GroupImportConfiguration, existing?: BasicStoreEntityGroup) => [
  configuration.default_assignation && !existing?.default_assignation ? NEW_USERS_REASON : undefined,
  (configuration.auto_integration_assignation ?? []).some((value) => !(existing?.auto_integration_assignation ?? []).includes(value))
    ? INTEGRATION_USERS_REASON
    : undefined,
];

export const importGroup = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  options: GroupImportOptions,
): Promise<GroupImportResult> => {
  const { mode, dryRun = false, reservedIds, isRoleCreated = () => false, isRoleSensitive = () => undefined } = options;
  const parsed = groupImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return refused('invalid', configImportValidationReason(parsed.error), false);
  }
  const roles = await Promise.all(parsed.data.roles.map(({ standard_id }) => findRoleById(context, user, standard_id)));
  const missingRoles = parsed.data.roles.filter(({ standard_id }, index) => !roles[index] && !(dryRun && isRoleCreated(standard_id)));
  if (missingRoles.length > 0) {
    return refused('role_missing', `Roles could not be imported: ${missingRoles.map(({ name }) => name).join(', ')}`, false, parsed.data);
  }
  const existing = await findGroupById(context, user, groupStandardId(parsed.data.name)) as BasicStoreEntityGroup | undefined;
  if (existing && mode === ConfigImportMode.Add) {
    return refused('exists', 'Group already exists', true, parsed.data);
  }
  const isCopy = mode === ConfigImportMode.Copy;
  const name = isCopy ? await freeGroupName(context, user, parsed.data.name, options) : parsed.data.name;
  if (!name) {
    return refused('name_conflict', 'Group name already exists', !!existing, parsed.data);
  }
  const target = isCopy ? undefined : existing;
  const targetId = groupStandardId(name);
  if (!(await isConfigImportSensitiveChangeAllowed(context, user, 'groups', targetId))) {
    return refused('sensitive_config', CONFIG_IMPORT_SENSITIVE_REASON, !!existing, parsed.data);
  }
  const found = roles.filter((role): role is BasicStoreEntityRole => !!role);
  const { roles: groupRoles, administratorRoleKept } = await withAdministratorRole(context, user, targetId, found);
  const resolved = await resolveGroup(context, user, parsed.data, groupRoles);
  const currentIds = target ? await currentRoleIds(context, user, target.id) : [];
  // The roles of the bundle, the ones the same import creates included, and the Administrator role the Administrators group keeps
  const references = [...new Set([...parsed.data.roles.map(({ standard_id }) => standard_id), ...groupRoles.map(({ standard_id }) => standard_id)])];
  const reason = joinConfigImportReasons([
    name !== parsed.data.name ? `Added as "${name}"` : undefined,
    administratorRoleKept ? ADMINISTRATOR_ROLE_KEPT_REASON : undefined,
    (await grantsSensitiveRights(context, user, references, groupRoles, currentIds, isRoleSensitive)) ? SENSITIVE_RIGHTS_REASON : undefined,
    resolved.missingMarkings.length > 0 ? `Markings not found: ${resolved.missingMarkings.join(', ')}` : undefined,
    resolved.missingDashboard ? `Default dashboard not found: ${resolved.missingDashboard}` : undefined,
    ...assignmentReasons(parsed.data, target),
  ]);
  const result: GroupImportResult = { status: target ? 'overwritten' : 'created', exists: !!existing, configuration: parsed.data, reason };
  if (dryRun) {
    reservedIds?.add(targetId);
    return result;
  }
  return { ...result, group: target ? await overwriteGroup(context, user, target, resolved) : await createGroup(context, user, name, resolved) };
};
