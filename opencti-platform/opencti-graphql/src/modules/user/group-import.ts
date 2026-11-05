import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import type { EditInput } from '../../generated/graphql';
import { getEntitiesMapFromCache } from '../../database/cache';
import { fullEntitiesThroughRelationsToList, storeLoadById } from '../../database/middleware-loader';
import { addGroup } from '../../domain/grant';
import { findById as findGroupById, groupAddRelation, groupAllowedMarkings, groupDeleteRelation, groupEditField } from '../../domain/group';
import { generateStandardId } from '../../schema/identifier';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_ROLE } from '../../schema/internalObject';
import { RELATION_ACCESSES_TO, RELATION_HAS_ROLE } from '../../schema/internalRelationship';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import { ROLE_ADMINISTRATOR, SYSTEM_USER } from '../../utils/access';
import { cleanMarkings } from '../../utils/markingDefinition-utils';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import {
  CONFIG_IMPORT_UNCHANGED_REASON,
  configImportReasonValue,
  configImportValidationReason,
  freeConfigImportName,
  joinConfigImportReasons,
} from '../configImport/configImport-utils';
import { CONFIG_IMPORT_SENSITIVE_REASON, isConfigImportSensitiveChangeAllowed } from './sensitive-config-import';
import { ENTITY_TYPE_WORKSPACE } from '../workspace/workspace-types';
import { findRoleById, roleCapabilities } from './user-domain';
import type { BasicStoreEntityGroup } from './group-export';
import type { BasicStoreEntityRole } from './role-export';
import { isSensitiveRole, REMOVES_SENSITIVE_RIGHTS_REASON, roleStandardId, SENSITIVE_RIGHTS_REASON } from './role-import';
import { type GroupImportConfiguration, groupImportSchema, type GroupMarkingReference } from './group-import-schema';

export interface GroupImportOptions extends ConfigImportOptions {
  reservedIds?: Set<string>;
  // In a dry run, the roles the same import creates or overwrites under their own standard id, and whether they will give sensitive rights
  plannedRoles?: Map<string, { grantsSensitiveRights: boolean }>;
  // The standard id each role of the bundle is written under by the same import, by its bundle id (the copy of a role imported as COPY)
  roleTargets?: Map<string, string | null>;
  // In a dry run, the markings the same import creates or overwrites, as they will be once written, by standard id
  plannedMarkings?: Map<string, PlannedMarking>;
}

export interface PlannedMarking {
  definition_type: string;
  definition: string;
  x_opencti_order: number;
}

export type GroupImportCode = 'invalid' | 'role_missing' | 'exists' | 'name_conflict' | 'sensitive_config' | 'unchanged';

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

type BasicStoreMarking = BasicStoreEntity & { definition: string; definition_type: string; x_opencti_order: number };

type ResolvedMarking = PlannedMarking & { id?: string; standard_id: string };

interface ResolvedGroup {
  fields: Record<string, unknown>;
  roleIds: string[];
  markingIds: string[];
  missingMarkings: string[];
  // Maximum shareable markings above the allowed markings of the group: never written, as the settings screen never offers them
  notAllowedShareableMarkings: string[];
  missingDashboard?: string;
  getsPlannedMarkings: boolean;
}

const loadMarkings = async (context: AuthContext, user: AuthUser, references: GroupMarkingReference[]) => {
  const cached = await getEntitiesMapFromCache<BasicStoreMarking>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  const uncached = [...new Set(references.map(({ standard_id }) => standard_id).filter((standardId) => !cached.get(standardId)))];
  const loaded = await Promise.all(uncached.map((standardId) => storeLoadById<BasicStoreMarking>(context, user, standardId, ENTITY_TYPE_MARKING_DEFINITION)));
  return (standardId: string) => cached.get(standardId) ?? loaded[uncached.indexOf(standardId)];
};

const resolveGroup = async (
  context: AuthContext,
  user: AuthUser,
  configuration: GroupImportConfiguration,
  roles: BasicStoreEntity[],
  plannedMarkings: Map<string, PlannedMarking>,
): Promise<ResolvedGroup> => {
  const shareable = configuration.max_shareable_markings.flatMap(({ value }) => (value === 'none' ? [] : [value]));
  const findMarking = await loadMarkings(context, user, [...configuration.allowed_markings, ...configuration.default_marking.flatMap(({ values }) => values), ...shareable]);
  const missingMarkings = new Set<string>();
  let getsPlannedMarkings = false;
  const resolveMarking = (reference: GroupMarkingReference): ResolvedMarking | undefined => {
    const marking = findMarking(reference.standard_id);
    const planned = plannedMarkings.get(reference.standard_id);
    if (planned) {
      getsPlannedMarkings ||= !marking;
      return { ...planned, id: marking?.id, standard_id: reference.standard_id };
    }
    if (!marking) {
      missingMarkings.add(reference.definition);
    }
    return marking;
  };
  const resolve = (reference: GroupMarkingReference) => resolveMarking(reference)?.id;
  const resolveAll = (references: GroupMarkingReference[]) => references.map(resolve).filter((id): id is string => !!id);
  const { default_dashboard: dashboardReference } = configuration;
  const dashboard = dashboardReference ? await storeLoadById<BasicStoreEntity>(context, user, dashboardReference.standard_id, ENTITY_TYPE_WORKSPACE) : undefined;
  const fields: Record<string, unknown> = Object.fromEntries(GROUP_FIELDS.map((key) => [key, configuration[key]]));
  fields.default_dashboard = dashboard?.id;
  fields.default_marking = await Promise.all(configuration.default_marking.map(async ({ entity_type, values }) => ({
    entity_type,
    values: (await cleanMarkings(context, values.map(resolveMarking).filter((marking) => !!marking)) as ResolvedMarking[])
      .flatMap(({ id }) => (id ? [id] : [])),
  })));
  // Same rule as the settings screen: a marking is shareable when an allowed marking of its type is at least as high
  const allowed = configuration.allowed_markings.map(resolveMarking).filter((marking): marking is ResolvedMarking => !!marking);
  const isAllowed = (marking: ResolvedMarking) => allowed.some(({ definition_type, x_opencti_order }) => definition_type === marking.definition_type
    && x_opencti_order >= marking.x_opencti_order);
  const notAllowedShareableMarkings: string[] = [];
  fields.max_shareable_markings = configuration.max_shareable_markings.map(({ type, value }) => {
    const marking = value === 'none' ? undefined : resolveMarking(value);
    if (marking && !isAllowed(marking)) {
      notAllowedShareableMarkings.push(marking.definition);
      return { type, value: 'none' };
    }
    return { type, value: marking?.id ?? 'none' };
  });
  return {
    notAllowedShareableMarkings,
    fields,
    roleIds: roles.map(({ id }) => id),
    markingIds: resolveAll(configuration.allowed_markings),
    missingMarkings: [...missingMarkings],
    missingDashboard: dashboardReference && !dashboard ? dashboardReference.name : undefined,
    getsPlannedMarkings,
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

interface CurrentGroupRelations {
  roles: BasicStoreEntityRole[];
  markings: BasicStoreMarking[];
}

const currentRelations = async (context: AuthContext, user: AuthUser, groupId: string): Promise<CurrentGroupRelations> => {
  const [roles, markings] = await Promise.all([
    fullEntitiesThroughRelationsToList<BasicStoreEntityRole>(context, user, groupId, RELATION_HAS_ROLE, ENTITY_TYPE_ROLE),
    groupAllowedMarkings(context, user, groupId) as Promise<BasicStoreMarking[]>,
  ]);
  return { roles, markings };
};

const idsOf = (entities: BasicStoreEntity[]) => entities.map(({ id }) => id);

const createGroup = async (context: AuthContext, user: AuthUser, name: string, resolved: ResolvedGroup): Promise<BasicStoreEntityGroup> => {
  const group = await addGroup(context, user, { name, ...Object.fromEntries(definedFields(resolved.fields)) });
  await replaceRelations(context, user, group.id, [], resolved.roleIds, RELATION_HAS_ROLE);
  await replaceRelations(context, user, group.id, [], resolved.markingIds, RELATION_ACCESSES_TO);
  return group;
};

const GROUP_FIELD_DEFAULTS: Record<string, unknown> = {
  description: '',
  default_assignation: false,
  auto_integration_assignation: [],
  no_creators: false,
  restrict_delete: false,
  auto_new_marking: false,
  default_hidden_types: [],
  default_marking: [],
  max_shareable_markings: [],
};
const GROUP_SET_FIELDS = ['auto_integration_assignation', 'default_hidden_types'];

const sortedKeys = (_key: string, value: unknown) => (value && typeof value === 'object' && !Array.isArray(value)
  ? Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)))
  : value);

const comparableField = (key: string, value: unknown) => {
  const field = value ?? GROUP_FIELD_DEFAULTS[key] ?? null;
  return JSON.stringify(GROUP_SET_FIELDS.includes(key) && Array.isArray(field) ? [...field].sort() : field, sortedKeys);
};

const groupEditInput = (existing: BasicStoreEntityGroup, resolved: ResolvedGroup): EditInput[] => {
  return definedFields(resolved.fields)
    .filter(([key, value]) => comparableField(key, existing[key as keyof BasicStoreEntityGroup]) !== comparableField(key, value))
    .map(([key, value]) => ({ key, value: Array.isArray(value) ? value : [value] }));
};

const sameIds = (currentIds: string[], ids: string[]) => currentIds.length === ids.length && ids.every((id) => currentIds.includes(id));

const overwriteGroup = async (context: AuthContext, user: AuthUser, existing: BasicStoreEntityGroup, resolved: ResolvedGroup, current: CurrentGroupRelations) => {
  const input = groupEditInput(existing, resolved);
  if (input.length > 0) {
    await groupEditField(context, user, existing.id, input);
  }
  await replaceRelations(context, user, existing.id, idsOf(current.roles), resolved.roleIds, RELATION_HAS_ROLE);
  await replaceRelations(context, user, existing.id, idsOf(current.markings), resolved.markingIds, RELATION_ACCESSES_TO);
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

const givesSensitiveRights = async (context: AuthContext, user: AuthUser, role: BasicStoreEntityRole, plannedRoles: Map<string, { grantsSensitiveRights: boolean }>) => {
  const planned = plannedRoles.get(role.standard_id)?.grantsSensitiveRights;
  return planned ?? isSensitiveRole({ ...role, capabilities: (await roleCapabilities(context, user, role.id)).map(({ name }) => name) });
};

const anyGivesSensitiveRights = async (
  context: AuthContext,
  user: AuthUser,
  roles: BasicStoreEntityRole[],
  plannedRoles: Map<string, { grantsSensitiveRights: boolean }>,
) => {
  return (await Promise.all(roles.map((role) => givesSensitiveRights(context, user, role, plannedRoles)))).some((sensitive) => sensitive);
};

const grantsSensitiveRights = async (
  context: AuthContext,
  user: AuthUser,
  references: string[],
  roles: BasicStoreEntityRole[],
  currentIds: string[],
  plannedRoles: Map<string, { grantsSensitiveRights: boolean }>,
) => {
  const found = references.map((reference) => roles.find(({ standard_id }) => standard_id === reference));
  // A role the same import creates is not on the platform yet: only the plan knows its rights
  if (references.some((reference, index) => !found[index] && plannedRoles.get(reference)?.grantsSensitiveRights)) {
    return true;
  }
  const gained = found.filter((role): role is BasicStoreEntityRole => !!role && !currentIds.includes(role.id));
  return anyGivesSensitiveRights(context, user, gained, plannedRoles);
};

// What the bundle refers to and the platform does not have: left out of the group
const missingReasons = (resolved: ResolvedGroup) => [
  resolved.missingMarkings.length > 0 ? `Markings not found: ${configImportReasonValue(resolved.missingMarkings.join(', '))}` : undefined,
  resolved.missingDashboard ? `Default dashboard not found: ${configImportReasonValue(resolved.missingDashboard)}` : undefined,
  resolved.notAllowedShareableMarkings.length > 0
    ? `Shareable markings not allowed by the group: ${configImportReasonValue(resolved.notAllowedShareableMarkings.join(', '))}`
    : undefined,
];

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
  const { mode, dryRun = false, reservedIds, plannedRoles = new Map(), roleTargets = new Map(), plannedMarkings = new Map() } = options;
  const parsed = groupImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return refused('invalid', configImportValidationReason(parsed.error), false);
  }
  // null: the copy of the role is not written, the local role with its standard id is another role
  const targetOf = (standardId: string) => (roleTargets.has(standardId) ? roleTargets.get(standardId) ?? null : standardId);
  const roles = await Promise.all(parsed.data.roles.map(({ standard_id }) => {
    const target = targetOf(standard_id);
    return target ? findRoleById(context, user, target) : undefined;
  }));
  const missingRoles = parsed.data.roles.filter(({ standard_id }, index) => {
    const target = targetOf(standard_id);
    return !roles[index] && !(dryRun && target && plannedRoles.has(target));
  });
  if (missingRoles.length > 0) {
    return refused('role_missing', `Roles could not be imported: ${configImportReasonValue(missingRoles.map(({ name }) => name).join(', '))}`, false, parsed.data);
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
  const resolved = await resolveGroup(context, user, parsed.data, groupRoles, dryRun ? plannedMarkings : new Map());
  const current = target ? await currentRelations(context, user, target.id) : { roles: [], markings: [] };
  const currentIds = idsOf(current.roles);
  const removedRoles = current.roles.filter(({ id }) => !resolved.roleIds.includes(id));
  const removedMarkings = current.markings.filter(({ id }) => !resolved.markingIds.includes(id)).map(({ definition }) => definition);
  const references = [...new Set([...parsed.data.roles.map(({ standard_id }) => targetOf(standard_id) ?? standard_id), ...groupRoles.map(({ standard_id }) => standard_id)])];
  const reason = joinConfigImportReasons([
    name !== parsed.data.name ? `Added as "${configImportReasonValue(name)}"` : undefined,
    administratorRoleKept ? ADMINISTRATOR_ROLE_KEPT_REASON : undefined,
    (await grantsSensitiveRights(context, user, references, groupRoles, currentIds, plannedRoles)) ? SENSITIVE_RIGHTS_REASON : undefined,
    (await anyGivesSensitiveRights(context, user, removedRoles, plannedRoles)) ? REMOVES_SENSITIVE_RIGHTS_REASON : undefined,
    ...missingReasons(resolved),
    removedRoles.length > 0 ? `Roles removed: ${configImportReasonValue(removedRoles.map(({ name }) => name).join(', '))}` : undefined,
    removedMarkings.length > 0 ? `Markings removed: ${configImportReasonValue(removedMarkings.join(', '))}` : undefined,
    ...assignmentReasons(parsed.data, target),
  ]);
  // A role or a marking the same import creates is not on the platform yet, but the group will get it
  const getsPlanned = roles.some((role) => !role) || resolved.getsPlannedMarkings;
  const unchanged = !!target && !getsPlanned && groupEditInput(target, resolved).length === 0
    && sameIds(currentIds, resolved.roleIds) && sameIds(idsOf(current.markings), resolved.markingIds);
  if (unchanged) {
    const upToDate = joinConfigImportReasons([CONFIG_IMPORT_UNCHANGED_REASON, administratorRoleKept ? ADMINISTRATOR_ROLE_KEPT_REASON : undefined, ...missingReasons(resolved)]);
    return { status: 'skipped', code: 'unchanged', exists: true, configuration: parsed.data, reason: upToDate };
  }
  const result: GroupImportResult = { status: target ? 'overwritten' : 'created', exists: !!existing, configuration: parsed.data, reason };
  if (dryRun) {
    reservedIds?.add(targetId);
    return result;
  }
  return { ...result, group: target ? await overwriteGroup(context, user, target, resolved, current) : await createGroup(context, user, name, resolved) };
};
