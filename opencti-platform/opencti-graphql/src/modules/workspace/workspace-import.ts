import * as R from 'ramda';
import type { FileHandle } from 'fs/promises';
import { GraphQLError } from 'graphql';
import { FUNCTIONAL_ERROR } from '../../config/errors';
import { FilterMode, type EditInput, type ImportWidgetInput, type MemberAccessInput } from '../../generated/graphql';
import { BUS_TOPICS } from '../../config/conf';
import { createEntity, updateAttribute } from '../../database/middleware';
import { notify } from '../../database/redis';
import { publishUserAction } from '../../listener/UserActionListener';
import type { AuthContext, AuthUser } from '../../types/user';
import { fromB64, toB64 } from '../../utils/base64';
import { extractContentFrom } from '../../utils/fileToContent';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import {
  CONFIG_IMPORT_UNCHANGED_REASON,
  configImportReasonValue,
  configImportRefusal,
  configImportValidationReason,
  freeConfigImportName,
} from '../configImport/configImport-utils';
import { checkDashboardConfigurationImport, convertDashboardManifestIds, importDashboardWidgetConfiguration } from '../dashboard/dashboard-utils';
import { findAllWorkspaces, findById, initializeAuthorizedMembers, sanitizeElementForPublishAction } from './workspace-domain';
import { DASHBOARD_NAME_MAX_LENGTH, type DashboardImportConfiguration, dashboardImportSchema } from './workspace-import-schema';
import { type BasicStoreEntityWorkspace, ENTITY_TYPE_WORKSPACE, type StoreEntityWorkspace } from './workspace-types';
import { withWorkspaceManifestLock } from './workspace-variables-domain';
import { type StoreDashboardPreset, type StoreDashboardVariable } from './workspace-variables-types';
import { pruneInvalidPresetValues, removeVariableFromPresets } from './workspace-presets-validation';
import { preserveServerOwnedManifestKeys, validateManifestVariables } from './workspace-variables-utils';

// The names the earlier items of the same dry run take, written or not: the dashboard of a name is imported once per import.
// An overwrite reserves the name it targets, a copy the name it takes
export interface DashboardImportOptions extends ConfigImportOptions {
  reservedNames?: Set<string>;
}

export type DashboardImportCode = 'invalid' | 'exists' | 'unchanged' | 'ambiguous' | 'duplicate' | 'name_conflict';

export type DashboardImportResult = ConfigImportResult<DashboardImportConfiguration, DashboardImportCode>;

const refused = configImportRefusal<DashboardImportConfiguration, DashboardImportCode>;

export const findDashboardsByName = async (context: AuthContext, user: AuthUser, name: string) => {
  const workspaces = await findAllWorkspaces(context, user, {
    filters: { mode: FilterMode.And, filters: [{ key: ['type'], values: ['dashboard'] }, { key: ['name'], values: [name] }], filterGroups: [] },
  }) as BasicStoreEntityWorkspace[];
  // The filter on the name does not tell the case apart
  return workspaces.filter((workspace) => workspace.name === name);
};

// region manifest
// The manifest with the ids of this platform. A reference it does not have is kept as it is, as the file import does.
// The variables are validated as the typed API does, before any id is resolved, then converted as the ids of the widgets. The presets are never taken
const prepareManifest = async (context: AuthContext, user: AuthUser, manifest: string | null | undefined) => {
  if (!manifest) {
    return undefined;
  }
  const taken = toB64(R.omit(['presets'], fromB64(manifest))) as string;
  const validated = validateManifestVariables(taken);
  return convertDashboardManifestIds(context, user, validated, 'stix') as Promise<string>;
};

// What a bundle does not hold, so what it neither compares nor replaces on a dashboard: the presets, and the variables when the bundle has none
// (no `variables` key: it comes from a platform before the dashboard variables, or from a dashboard that never had any).
// A bundle writes `variables` as soon as the dashboard had some, an empty list included, so it can still clear them
const bundleLeftOutKeys = (imported: string) => {
  return 'variables' in fromB64<Record<string, unknown>>(imported) ? ['presets'] : ['presets', 'variables'];
};
const withoutLeftOutKeys = (encoded: string | undefined, leftOutKeys: string[]) => R.omit(leftOutKeys, fromB64(encoded));
const isSameManifest = (stored: string | undefined, imported: string) => {
  const leftOutKeys = bundleLeftOutKeys(imported);
  return R.equals(withoutLeftOutKeys(stored, leftOutKeys), withoutLeftOutKeys(imported, leftOutKeys));
};
// The presets of the dashboard once the variables of the bundle replace its own, kept consistent with them as the other paths do (the deletion
// and the update of a variable, the file import): the value of a variable the bundle no longer has is removed, and so is one that the variable,
// as the bundle defines it, no longer accepts (its type, its selection). The presets are otherwise kept
const reconcilePresets = (presets: StoreDashboardPreset[], variables: StoreDashboardVariable[]) => {
  const variableIds = new Set(variables.map(({ id }) => id));
  const droppedIds = new Set(presets.flatMap(({ values }) => Object.keys(values)).filter((id) => !variableIds.has(id)));
  const withoutDropped = [...droppedIds].reduce((kept, id) => removeVariableFromPresets(kept, id), presets);
  return variables.reduce((kept, variable) => pruneInvalidPresetValues(kept, variable), withoutDropped);
};
// The dashboard keeps what the bundle does not hold: an overwrite does not erase its presets (nor its variables when the bundle has none)
const keepStoredLeftOutKeys = (stored: string | undefined, imported: string) => {
  const leftOutKeys = bundleLeftOutKeys(imported);
  const kept = stored ? R.pick(leftOutKeys, fromB64<Record<string, unknown>>(stored)) : {};
  if (Array.isArray(kept.presets) && !leftOutKeys.includes('variables')) {
    // The variables of the bundle replace the stored ones: they were validated by prepareManifest
    const { variables } = fromB64<{ variables: StoreDashboardVariable[] }>(imported);
    kept.presets = reconcilePresets(kept.presets as StoreDashboardPreset[], variables);
  }
  return Object.keys(kept).length === 0 ? imported : toB64({ ...fromB64<Record<string, unknown>>(imported), ...kept }) as string;
};
// endregion

// region writes
const createDashboard = (context: AuthContext, user: AuthUser, data: DashboardImportConfiguration, manifest: string | undefined, name: string) => {
  return createImportedWorkspace(context, user, {
    ...R.reject(R.isNil, { description: data.description, tags: data.tags, refresh_interval: data.refresh_interval, manifest }),
    name,
    // As the file import: the importing user is its admin, nobody else
    restricted_members: initializeAuthorizedMembers([], user),
  });
};

// The fields an import writes on an existing dashboard: what the bundle sets and the dashboard does not have. A value that is null or absent leaves
// the one of the dashboard untouched. The members of the dashboard are never touched
const buildPatch = (existing: BasicStoreEntityWorkspace, data: DashboardImportConfiguration, manifest: string | undefined) => {
  const patch: EditInput[] = [];
  if (data.description != null && data.description !== (existing.description ?? '')) patch.push({ key: 'description', value: [data.description] });
  if (data.tags != null && !R.equals([...data.tags].sort(), [...(existing.tags ?? [])].sort())) patch.push({ key: 'tags', value: data.tags });
  if (data.refresh_interval != null && data.refresh_interval !== (existing.refresh_interval ?? 0)) patch.push({ key: 'refresh_interval', value: [data.refresh_interval] });
  if (manifest && !isSameManifest(existing.manifest, manifest)) {
    patch.push({ key: 'manifest', value: [keepStoredLeftOutKeys(existing.manifest, manifest)] });
  }
  return patch;
};

// Written with updateAttribute, not workspaceEditField: that one keeps the variables of the stored manifest, the import replaces them.
// The patch is built from the dashboard as stored under the lock, so that what was written since it was found (a preset saved meanwhile) is kept.
// Returns 'gone' when the dashboard was deleted since it was found: nothing is written, the caller decides
const patchDashboard = async (
  context: AuthContext,
  user: AuthUser,
  existing: BasicStoreEntityWorkspace,
  data: DashboardImportConfiguration,
  manifest: string | undefined,
): Promise<'gone' | 'done'> => {
  const result = await withWorkspaceManifestLock(existing.id, async () => {
    const stored = await findById(context, user, existing.id) as BasicStoreEntityWorkspace | undefined;
    if (!stored) {
      return 'gone' as const;
    }
    const patch = buildPatch(stored, data, manifest);
    if (patch.length === 0) {
      return undefined;
    }
    const { element: updated } = await updateAttribute<StoreEntityWorkspace>(context, user, existing.id, ENTITY_TYPE_WORKSPACE, patch);
    return updated;
  });
  if (result === 'gone') {
    return 'gone';
  }
  const element = result;
  if (!element) {
    return 'done';
  }
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'extended',
    message: `import ${element.name} workspace`,
    context_data: { id: existing.id, entity_type: ENTITY_TYPE_WORKSPACE, input: sanitizeElementForPublishAction(element) },
  });
  await notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, element, user);
  return 'done';
};

// endregion

// The one place where a dashboard is imported from a configuration bundle: validates, finds the dashboard by its name and writes it.
// A refusal is a result, not an error. A dry run decides the same result and writes nothing.
// The standard id of a dashboard is random, so its name is its identity: add refuses an existing name, overwrite patches the dashboard that has it
// (its manifest, variables included, is replaced; its members are kept), else creates it. A name that several dashboards have is refused.
// Copy creates the dashboard under a free name (`name (1)`, ...), whether the name is taken or not.
// A name that an earlier item of the same import already took is a duplicate: refused, as the later item would overwrite the dashboard of the earlier one.
// The ids of the filters are converted to this platform's: a reference it does not have is kept as it is, as the file import does.
// The variables are converted the same way and replace the ones of an overwritten dashboard.
export const importDashboard = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  { mode, dryRun = false, reservedNames }: DashboardImportOptions,
): Promise<DashboardImportResult> => {
  const parsed = dashboardImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return refused('failed', 'invalid', configImportValidationReason(parsed.error), false);
  }
  const { data } = parsed;
  let manifest: string | undefined;
  try {
    manifest = await prepareManifest(context, user, data.manifest);
  } catch (error) {
    // Only what the manifest breaks is a refusal of the item: a failure of the platform (a lookup of the ids that times out) stays an error
    if (!(error instanceof GraphQLError && error.extensions.code === FUNCTIONAL_ERROR)) {
      throw error;
    }
    return refused('failed', 'invalid', configImportReasonValue(error.message), false, data);
  }
  if (mode === ConfigImportMode.Copy) {
    const sameName = await findDashboardsByName(context, user, data.name);
    // The name of the configuration is read once: the first candidate of a copy is that name
    const isTaken = async (candidate: string) => {
      if (reservedNames?.has(candidate)) {
        return true;
      }
      return (candidate === data.name ? sameName : await findDashboardsByName(context, user, candidate)).length > 0;
    };
    const name = await freeConfigImportName(data.name, isTaken, { maxLength: DASHBOARD_NAME_MAX_LENGTH });
    if (!name) {
      return refused('failed', 'name_conflict', 'Dashboard name already exists', sameName.length > 0, data);
    }
    if (dryRun) {
      reservedNames?.add(name);
    } else {
      await createDashboard(context, user, data, manifest, name);
    }
    const reason = name === data.name ? undefined : `Added as "${configImportReasonValue(name)}"`;
    return { status: 'created', exists: sameName.length > 0, configuration: data, reason };
  }
  if (reservedNames?.has(data.name)) {
    // exists is false: the clash is with an earlier item of the bundle, not with a dashboard of the platform, so the preview offers no choice
    return refused('failed', 'duplicate', 'Another dashboard of the import has this name', false, data);
  }
  if (dryRun) {
    reservedNames?.add(data.name);
  }
  const sameName = await findDashboardsByName(context, user, data.name);
  if (sameName.length > 1) {
    return refused('failed', 'ambiguous', 'Several dashboards have this name', true, data);
  }
  const [existing] = sameName;
  if (!existing) {
    if (!dryRun) {
      await createDashboard(context, user, data, manifest, data.name);
    }
    return { status: 'created', exists: false, configuration: data };
  }
  if (mode === ConfigImportMode.Add) {
    return refused('failed', 'exists', 'Dashboard already exists', true, data);
  }
  const patch = buildPatch(existing, data, manifest);
  if (patch.length === 0) {
    return refused('skipped', 'unchanged', CONFIG_IMPORT_UNCHANGED_REASON, true, data);
  }
  if (!dryRun && await patchDashboard(context, user, existing, data, manifest) === 'gone') {
    // Deleted since it was found: the name is free, as when the overwrite finds none
    await createDashboard(context, user, data, manifest, data.name);
    return { status: 'created', exists: false, configuration: data };
  }
  return { status: 'overwritten', exists: true, configuration: data };
};

// A dashboard written by an import (the file import, the configuration bundle): the same audit event and notification
export const createImportedWorkspace = async (
  context: AuthContext,
  user: AuthUser,
  input: { name: string; openCTI_version?: string; manifest?: string; description?: string; tags?: string[]; refresh_interval?: number; restricted_members: MemberAccessInput[] },
) => {
  const importWorkspaceCreation = await createEntity(context, user, { type: 'dashboard', ...input }, ENTITY_TYPE_WORKSPACE);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `import ${importWorkspaceCreation.name} workspace`,
    context_data: {
      id: importWorkspaceCreation.id,
      entity_type: ENTITY_TYPE_WORKSPACE,
      input: sanitizeElementForPublishAction(importWorkspaceCreation),
    },
  });
  await notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].ADDED_TOPIC, importWorkspaceCreation, user);
  return importWorkspaceCreation;
};

export const workspaceImportConfiguration = async (context: AuthContext, user: AuthUser, file: Promise<FileHandle>) => {
  const parsedData = await extractContentFrom(file);
  checkDashboardConfigurationImport('dashboard', parsedData);
  const authorizedMembers = initializeAuthorizedMembers([], user);
  const { manifest } = parsedData.configuration;
  // Dashboard variables of an imported file go through the same validation as the typed API, before any id
  // is resolved: a malformed variable never reaches the conversion.
  const validatedManifest = validateManifestVariables(manifest);
  // Manifest ids must be rewritten for filters and variables
  const generatedManifest = await convertDashboardManifestIds(context, user, validatedManifest, 'stix');
  const created = await createImportedWorkspace(context, user, {
    openCTI_version: parsedData.openCTI_version,
    name: parsedData.configuration.name,
    manifest: generatedManifest as string,
    restricted_members: authorizedMembers,
  });
  return created.id;
};

export const workspaceImportWidgetConfiguration = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
  input: ImportWidgetInput,
) => {
  const { updatedManifest, importedWidgetId } = await importDashboardWidgetConfiguration(
    context,
    user,
    input.file,
    input.dashboardManifest,
  );
  // The manifest comes from the client: same protection as workspaceFieldPatch.
  const element = await withWorkspaceManifestLock(workspaceId, async () => {
    const workspace = await findById(context, user, workspaceId);
    const safeInputs = preserveServerOwnedManifestKeys([{ key: 'manifest', value: [updatedManifest] }], workspace?.manifest);
    const { element: updated } = await updateAttribute<StoreEntityWorkspace>(context, user, workspaceId, ENTITY_TYPE_WORKSPACE, safeInputs);
    return updated;
  });

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `import widget (id : ${importedWidgetId}) in workspace (id : ${workspaceId})`,
    context_data: {
      id: workspaceId,
      entity_type: ENTITY_TYPE_WORKSPACE,
      input: sanitizeElementForPublishAction(element),
    },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, element, user);
};
