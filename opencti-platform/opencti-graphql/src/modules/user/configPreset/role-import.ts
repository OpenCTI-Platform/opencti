import type { AuthContext, AuthUser } from '../../../types/user';
import type { BasicStoreEntity } from '../../../types/store';
import type { EditInput } from '../../../generated/graphql';
import { fullEntitiesList } from '../../../database/middleware-loader';
import { addRole } from '../../../domain/grant';
import { generateStandardId } from '../../../schema/identifier';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_ROLE } from '../../../schema/internalObject';
import { RELATION_HAS_CAPABILITY, RELATION_HAS_CAPABILITY_IN_DRAFT } from '../../../schema/internalRelationship';
import { BYPASS, CAPABILITIES_IN_DRAFT_NAMES, ROLE_ADMINISTRATOR } from '../../../utils/access';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../../configImport/configImport-types';
import { configImportValidationReason, freeConfigImportName, joinConfigImportReasons } from '../../configImport/configImport-utils';
import { findRoleById, roleAddRelation, roleCapabilities, roleDeleteRelation, roleEditField } from '../user-domain';
import type { BasicStoreEntityRole } from './role-export';
import { type RoleImportConfiguration, roleImportSchema } from './role-import-schema';

// A dry run writes nothing: the standard ids the earlier items of the same dry run would take are reserved for the next ones
export interface RoleImportOptions extends ConfigImportOptions {
  reservedIds?: Set<string>;
}

export type RoleImportCode = 'invalid' | 'unknown_capability' | 'exists' | 'name_conflict';

export type RoleImportResult = ConfigImportResult<RoleImportConfiguration, RoleImportCode> & {
  role?: BasicStoreEntityRole;
};

const refused = (code: RoleImportCode, reason: string, exists: boolean, configuration?: RoleImportConfiguration): RoleImportResult => {
  return { status: 'failed', code, reason, exists, configuration };
};

export const roleStandardId = (name: string): string => generateStandardId(ENTITY_TYPE_ROLE, { name });
const capabilityStandardId = (name: string): string => generateStandardId(ENTITY_TYPE_CAPABILITY, { name });

const freeRoleName = (context: AuthContext, user: AuthUser, name: string, { reservedIds }: RoleImportOptions) => {
  return freeConfigImportName(name, async (candidate) => {
    const standardId = roleStandardId(candidate);
    return !!reservedIds?.has(standardId) || !!(await findRoleById(context, user, standardId));
  });
};

const capabilitiesReason = async (context: AuthContext, user: AuthUser, { capabilities, capabilities_in_draft: inDraft }: RoleImportConfiguration) => {
  const known = new Set((await fullEntitiesList<BasicStoreEntity>(context, user, [ENTITY_TYPE_CAPABILITY])).map(({ name }) => name));
  const unknown = capabilities.filter((name) => !known.has(name));
  if (unknown.length > 0) {
    return `Unknown capabilities: ${unknown.join(', ')}`;
  }
  const notInDraft = inDraft.filter((name) => !CAPABILITIES_IN_DRAFT_NAMES.includes(name));
  if (notInDraft.length > 0) {
    return `Capabilities not available in draft: ${notInDraft.join(', ')}`;
  }
  return undefined;
};

const BYPASS_KEPT_REASON = 'The Administrator role keeps the bypass capability';
const SENSITIVE_RIGHTS_REASON = 'Grants sensitive rights';

const withAdministratorBypass = (standardId: string, configuration: RoleImportConfiguration) => {
  if (standardId !== roleStandardId(ROLE_ADMINISTRATOR) || configuration.capabilities.includes(BYPASS)) {
    return { configuration, bypassKept: false };
  }
  return { configuration: { ...configuration, capabilities: [...configuration.capabilities, BYPASS] }, bypassKept: true };
};

const grantsSensitiveRights = (configuration: RoleImportConfiguration, existing?: { role: BasicStoreEntityRole; capabilities: string[] }) => {
  const grantsBypass = configuration.capabilities.includes(BYPASS) && !existing?.capabilities.includes(BYPASS);
  const grantsSensitiveConfig = !!configuration.can_manage_sensitive_config && !existing?.role.can_manage_sensitive_config;
  return grantsBypass || grantsSensitiveConfig;
};

const capabilityNames = async (context: AuthContext, user: AuthUser, roleId: string, relationshipType: string) => {
  return (await roleCapabilities(context, user, roleId, relationshipType)).map(({ name }) => name);
};

const createRole = async (context: AuthContext, user: AuthUser, configuration: RoleImportConfiguration): Promise<BasicStoreEntityRole> => {
  const { capabilities_in_draft: capabilitiesInDraft, ...role } = configuration;
  return addRole(context, user, { ...role, capabilitiesInDraft });
};

const replaceCapabilities = async (context: AuthContext, user: AuthUser, roleId: string, names: string[], relationshipType: string) => {
  const current = await roleCapabilities(context, user, roleId, relationshipType);
  const added = names.filter((name) => !current.some((capability) => capability.name === name));
  const removed = current.filter((capability) => !names.includes(capability.name));
  for (let i = 0; i < added.length; i += 1) {
    await roleAddRelation(context, user, roleId, { toId: capabilityStandardId(added[i]), relationship_type: relationshipType });
  }
  for (let i = 0; i < removed.length; i += 1) {
    await roleDeleteRelation(context, user, roleId, removed[i].id, relationshipType);
  }
};

// A value that is null or absent is left untouched, the capabilities are always replaced
const overwriteRole = async (context: AuthContext, user: AuthUser, existing: BasicStoreEntityRole, configuration: RoleImportConfiguration) => {
  const input: EditInput[] = (['description', 'can_manage_sensitive_config'] as const)
    .filter((key) => configuration[key] !== null && configuration[key] !== undefined && configuration[key] !== existing[key])
    .map((key) => ({ key, value: [configuration[key]] }));
  if (input.length > 0) {
    await roleEditField(context, user, existing.id, input);
  }
  await replaceCapabilities(context, user, existing.id, configuration.capabilities, RELATION_HAS_CAPABILITY);
  await replaceCapabilities(context, user, existing.id, configuration.capabilities_in_draft, RELATION_HAS_CAPABILITY_IN_DRAFT);
  return (await findRoleById(context, user, existing.id)) as BasicStoreEntityRole;
};

export const importRole = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  options: RoleImportOptions,
): Promise<RoleImportResult> => {
  const { mode, dryRun = false, reservedIds } = options;
  const parsed = roleImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return refused('invalid', configImportValidationReason(parsed.error), false);
  }
  const unknownReason = await capabilitiesReason(context, user, parsed.data);
  if (unknownReason) {
    return refused('unknown_capability', unknownReason, false, parsed.data);
  }
  const standardId = roleStandardId(parsed.data.name);
  const existing = await findRoleById(context, user, standardId) as BasicStoreEntityRole | undefined;
  if (existing && mode === ConfigImportMode.Add) {
    return refused('exists', 'Role already exists', true, parsed.data);
  }
  const isCopy = mode === ConfigImportMode.Copy;
  const name = isCopy ? await freeRoleName(context, user, parsed.data.name, options) : parsed.data.name;
  if (!name) {
    return refused('name_conflict', 'Role name already exists', !!existing, parsed.data);
  }
  const target = isCopy ? undefined : existing;
  const targetId = roleStandardId(name);
  const { configuration: role, bypassKept } = withAdministratorBypass(targetId, { ...parsed.data, name });
  const current = target ? { role: target, capabilities: await capabilityNames(context, user, target.id, RELATION_HAS_CAPABILITY) } : undefined;
  const reason = joinConfigImportReasons([
    name !== parsed.data.name ? `Added as "${name}"` : undefined,
    bypassKept ? BYPASS_KEPT_REASON : undefined,
    grantsSensitiveRights(role, current) ? SENSITIVE_RIGHTS_REASON : undefined,
  ]);
  const result: RoleImportResult = { status: target ? 'overwritten' : 'created', exists: !!existing, configuration: parsed.data, reason };
  if (dryRun) {
    reservedIds?.add(targetId);
    return result;
  }
  return { ...result, role: target ? await overwriteRole(context, user, target, role) : await createRole(context, user, role) };
};
