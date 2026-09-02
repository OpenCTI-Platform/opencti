import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import type { FileHandle } from 'fs/promises';
import pjson from '../../../package.json';
import { createEntity, deleteElementById, fullEntitiesOrRelationsConnection, pageEntitiesOrRelationsConnection, updateAttribute } from '../../database/middleware';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { BUS_TOPICS } from '../../config/conf';
import { delEditContext, notify, setEditContext } from '../../database/redis';
import { type BasicStoreEntityWorkspace, type DashboardManifest, type DashboardPreset, type DashboardVariable, ENTITY_TYPE_WORKSPACE, type StoreEntityWorkspace } from './workspace-types';
import { DatabaseError, ForbiddenAccess, FunctionalError } from '../../config/errors';
import type { AuthContext, AuthUser } from '../../types/user';
import type {
  EditContext,
  EditInput,
  ImportWidgetInput,
  InputMaybe,
  MemberAccessInput,
  QueryWorkspacesArgs,
  WorkspaceAddInput,
  WorkspaceDuplicateInput,
  WorkspaceObjectsArgs,
} from '../../generated/graphql';
import { EXPLORE_EXUPDATE, getUserAccessRight, isUserHasCapability, MEMBER_ACCESS_RIGHT_ADMIN, MEMBER_ACCESS_RIGHT_VIEW, SYSTEM_USER } from '../../utils/access';
import { publishUserAction } from '../../listener/UserActionListener';
import { editAuthorizedMembers } from '../../utils/authorizedMembers';
import { elFindByIds, elRawDeleteByQuery } from '../../database/engine';
import type { BasicConnection, BasicStoreBase, BasicStoreEntity } from '../../types/store';
import { buildPagination, isEmptyField, fromBase64, toBase64, READ_DATA_INDICES_WITHOUT_INTERNAL, READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { extractContentFrom } from '../../utils/fileToContent';
import { getEntitiesListFromCache } from '../../database/cache';
import { ENTITY_TYPE_PUBLIC_DASHBOARD, type PublicDashboardCached } from '../publicDashboard/publicDashboard-types';
import { createInternalObject, editInternalObject } from '../../domain/internalObject';
import { checkDashboardConfigurationImport, convertDashboardManifestIds, exportDashboardWidget, importDashboardWidgetConfiguration } from '../dashboard/dashboard-utils';

// Local input types until graphql codegen is run against the new schema
interface DashboardVariableInput {
  name: string;
  filterKey: string;
  filterKeyType: string;
  defaultValue?: string | null;
  restrictionMode?: string | null;
  restrictionValues?: string[] | null;
  restrictionFilters?: string | null;
}

interface DashboardPresetInput {
  name: string;
  variable_values: string;
}

export const PLATFORM_DASHBOARD = 'cf093b57-713f-404b-a210-a1c5c8cb3791';

export const sanitizeElementForPublishAction = (element: BasicStoreEntityWorkspace) => {
  // Because manifest can be huge we remove this data from activity logs.
  return { ...element, manifest: undefined };
};

export const findById = (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
) => {
  if (workspaceId === PLATFORM_DASHBOARD) {
    return {
      id: PLATFORM_DASHBOARD,
    } as BasicStoreEntityWorkspace;
  }
  return storeLoadById<BasicStoreEntityWorkspace>(
    context,
    user,
    workspaceId,
    ENTITY_TYPE_WORKSPACE,
  );
};

export const findAllWorkspaces = (context: AuthContext, user: AuthUser, args: QueryWorkspacesArgs) => {
  return fullEntitiesList(context, user, [ENTITY_TYPE_WORKSPACE], args);
};

export const findWorkspacePaginated = (context: AuthContext, user: AuthUser, args: QueryWorkspacesArgs) => {
  return pageEntitiesConnection<BasicStoreEntityWorkspace>(context, user, [ENTITY_TYPE_WORKSPACE], args);
};

export const workspaceEditAuthorizedMembers = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
  input: MemberAccessInput[],
) => {
  const args = {
    entityId: workspaceId,
    input,
    requiredCapabilities: ['EXPLORE_EXUPDATE_EXDELETE'],
    entityType: ENTITY_TYPE_WORKSPACE,
    busTopicKey: ENTITY_TYPE_WORKSPACE,
  };
  // @ts-expect-error TODO improve busTopicKey types to avoid this
  return editAuthorizedMembers(context, user, args);
};

export const getCurrentUserAccessRight = async (
  user: AuthUser,
  workspace: BasicStoreEntityWorkspace,
) => {
  return getUserAccessRight(user, workspace);
};

export const getOwnerId = (workspace: BasicStoreEntityWorkspace) => {
  if (Array.isArray(workspace.creator_id)) {
    return workspace.creator_id.length > 0
      ? workspace.creator_id[0]
      : undefined;
  }
  return workspace.creator_id;
};

export const objects = async (
  context: AuthContext,
  user: AuthUser,
  { investigated_entities_ids }: BasicStoreEntityWorkspace,
  args: WorkspaceObjectsArgs,
) => {
  if (isEmptyField(investigated_entities_ids)) {
    return buildPagination<BasicStoreBase>(1, null, [], 0);
  }
  const filters = addFilter(args.filters, 'internal_id', investigated_entities_ids);
  const finalArgs = { ...args, filters };
  const finalTypes = args.types?.filter((t) => t) as string[] | undefined;
  if (args.all) {
    return fullEntitiesOrRelationsConnection(context, user, finalTypes, finalArgs);
  }
  return await pageEntitiesOrRelationsConnection(context, user, finalTypes, finalArgs) as BasicConnection<BasicStoreBase>;
};

const checkInvestigatedEntitiesInputs = async (
  context: AuthContext,
  user: AuthUser,
  inputs: EditInput[],
): Promise<void> => {
  const addedOrReplacedInvestigatedEntitiesIds = inputs
    .filter(
      ({ key, operation }) => key === 'investigated_entities_ids'
        && (operation === 'add' || operation === 'replace'),
    )
    .flatMap(({ value }) => value) as string[];
  const opts = { indices: READ_DATA_INDICES_WITHOUT_INTERNAL };
  const entities = (await elFindByIds(
    context,
    user,
    addedOrReplacedInvestigatedEntitiesIds,
    opts,
  )) as Array<BasicStoreEntity>;
  const missingEntitiesIds = R.difference(
    addedOrReplacedInvestigatedEntitiesIds,
    entities.map((entity) => entity.id),
  );
  if (missingEntitiesIds.length > 0) {
    throw FunctionalError('Invalid ids specified', { ids: missingEntitiesIds });
  }
};

export const initializeAuthorizedMembers = (
  authorizedMembers: InputMaybe<MemberAccessInput[]> | undefined,
  user: AuthUser,
) => {
  const initializedAuthorizedMembers = authorizedMembers ?? [];
  if (!authorizedMembers?.some((e) => e.id === user.id)) {
    // add creator to authorized_members on creation
    initializedAuthorizedMembers.push({
      id: user.id,
      access_right: MEMBER_ACCESS_RIGHT_ADMIN,
    });
  }
  return initializedAuthorizedMembers;
};
export const addWorkspace = async (
  context: AuthContext,
  user: AuthUser,
  input: WorkspaceAddInput,
) => {
  // check capabilities according to workspace type
  let hasCapa;
  if (input.type === 'investigation') {
    hasCapa = isUserHasCapability(user, 'INVESTIGATION_INUPDATE');
  } else if (input.type === 'dashboard') {
    hasCapa = isUserHasCapability(user, 'EXPLORE_EXUPDATE');
  }
  if (!hasCapa) {
    throw ForbiddenAccess();
  }
  // construct final creation input
  const authorizedMembers = initializeAuthorizedMembers(
    input.authorized_members,
    user,
  );
  const workspaceToCreate = { ...input, restricted_members: authorizedMembers };
  return createInternalObject<StoreEntityWorkspace>(context, user, workspaceToCreate, ENTITY_TYPE_WORKSPACE);
};

export const workspaceDelete = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
) => {
  const deleted = await deleteElementById<StoreEntityWorkspace>(
    context,
    user,
    workspaceId,
    ENTITY_TYPE_WORKSPACE,
  );

  // region cascade delete associated public dashboards
  const publicDashboards = await getEntitiesListFromCache<PublicDashboardCached>(
    context,
    SYSTEM_USER,
    ENTITY_TYPE_PUBLIC_DASHBOARD,
  );
  const publicDashboardsToDelete = publicDashboards
    .filter((dashboard) => dashboard.dashboard_id === workspaceId)
    .map((dashboard) => dashboard.id);
  if (publicDashboardsToDelete.length > 0) {
    await elRawDeleteByQuery({
      index: READ_INDEX_INTERNAL_OBJECTS,
      refresh: true,
      body: {
        query: {
          bool: {
            must: [
              { term: { 'entity_type.keyword': { value: 'PublicDashboard' } } },
              { terms: { 'internal_id.keyword': publicDashboardsToDelete } },
            ],
          },
        },
      },
    }).catch((err: Error) => {
      throw DatabaseError(
        '[DELETE] Error deleting public dashboard for workspace ',
        { cause: err, workspace_id: workspaceId },
      );
    });
  }
  // endregion

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes ${deleted.type} workspace \`${deleted.name}\``,
    context_data: {
      id: workspaceId,
      entity_type: ENTITY_TYPE_WORKSPACE,
      input: sanitizeElementForPublishAction(deleted),
    },
  });
  return workspaceId;
};

export const workspaceEditField = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
  inputs: EditInput[],
) => {
  await checkInvestigatedEntitiesInputs(context, user, inputs);
  return editInternalObject<StoreEntityWorkspace>(context, user, workspaceId, ENTITY_TYPE_WORKSPACE, inputs);
};

export const workspaceCleanContext = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
) => {
  await delEditContext(user, workspaceId);
  return storeLoadById(context, user, workspaceId, ENTITY_TYPE_WORKSPACE).then(
    (userToReturn) => {
      return notify(
        BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC,
        userToReturn,
        user,
      );
    },
  );
};

export const workspaceEditContext = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
  input: EditContext,
) => {
  await setEditContext(user, workspaceId, input);
  return storeLoadById(context, user, workspaceId, ENTITY_TYPE_WORKSPACE).then(
    (workspaceToReturn) => notify(
      BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC,
      workspaceToReturn,
      user,
    ),
  );
};

export const generateWorkspaceExportConfiguration = async (context: AuthContext, user: AuthUser, workspace: BasicStoreEntityWorkspace) => {
  if (workspace.type !== 'dashboard') {
    throw FunctionalError('WORKSPACE_EXPORT_INCOMPATIBLE_TYPE', { type: workspace.type });
  }
  const generatedManifest = await convertDashboardManifestIds(context, user, workspace.manifest, 'internal');
  const exportConfigration = {
    openCTI_version: pjson.version,
    type: 'dashboard',
    configuration: {
      name: workspace.name,
      manifest: generatedManifest,
    },
  };
  return JSON.stringify(exportConfigration);
};

export const generateWidgetExportConfiguration = async (context: AuthContext, user: AuthUser, workspace: BasicStoreEntityWorkspace, widgetId: string) => {
  if (workspace.type !== 'dashboard') {
    throw FunctionalError('WORKSPACE_EXPORT_INCOMPATIBLE_TYPE', { type: workspace.type });
  }
  const result = await exportDashboardWidget(context, user, workspace.manifest, widgetId);
  if (!result.success) {
    throw FunctionalError('WIDGET_EXPORT_NOT_FOUND', { workspace: workspace.id, widget: widgetId });
  }
  return result.data;
};

export const workspaceImportConfiguration = async (context: AuthContext, user: AuthUser, file: Promise<FileHandle>) => {
  const parsedData = await extractContentFrom(file);
  checkDashboardConfigurationImport('dashboard', parsedData);
  const authorizedMembers = initializeAuthorizedMembers([], user);
  const { manifest } = parsedData.configuration;
  // Manifest ids must be rewritten for filters
  const generatedManifest = await convertDashboardManifestIds(context, user, manifest, 'stix');
  const mappedData = {
    type: parsedData.type,
    openCTI_version: parsedData.openCTI_version,
    name: parsedData.configuration.name,
    manifest: generatedManifest,
    restricted_members: authorizedMembers,
  };
  const importWorkspaceCreation = await createEntity(context, user, mappedData, ENTITY_TYPE_WORKSPACE);
  const workspaceId = importWorkspaceCreation.id;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `import ${importWorkspaceCreation.name} workspace`,
    context_data: {
      id: workspaceId,
      entity_type: ENTITY_TYPE_WORKSPACE,
      input: sanitizeElementForPublishAction(importWorkspaceCreation),
    },
  });
  await notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].ADDED_TOPIC, importWorkspaceCreation, user);
  return workspaceId;
};

export const duplicateWorkspace = async (context: AuthContext, user: AuthUser, input: WorkspaceDuplicateInput) => {
  const authorizedMembers = initializeAuthorizedMembers([], user);
  const workspaceToCreate = { ...input, restricted_members: authorizedMembers };
  const created = await createEntity(context, user, workspaceToCreate, ENTITY_TYPE_WORKSPACE);
  const sanitizeElement = { ...input, manifest: undefined };
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `creates ${created.type} workspace \`${created.name}\` from custom-named duplication`,
    context_data: { id: created.id, entity_type: ENTITY_TYPE_WORKSPACE, input: sanitizeElement },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].ADDED_TOPIC, created, user);
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
  const { element } = await updateAttribute<StoreEntityWorkspace>(
    context,
    user,
    workspaceId,
    ENTITY_TYPE_WORKSPACE,
    [{ key: 'manifest', value: [updatedManifest] }],
  );

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

export const isDashboardShared = async (context: AuthContext, workspace: BasicStoreEntityWorkspace) => {
  if (workspace.type !== 'dashboard') return false;
  const publicDashboards = await getEntitiesListFromCache<PublicDashboardCached>(
    context,
    SYSTEM_USER,
    ENTITY_TYPE_PUBLIC_DASHBOARD,
  );
  return publicDashboards.some((publicDashboard) => (
    publicDashboard.dashboard_id === workspace.id && publicDashboard.enabled
  ));
};

// region Dashboard variable management

const parseManifest = (manifest: string | undefined | null): DashboardManifest => {
  if (!manifest) return {};
  try {
    // Manifest is stored as base64(json) by the frontend.
    const decoded = fromBase64(manifest);
    if (!decoded) return {};
    return JSON.parse(decoded) as DashboardManifest;
  } catch {
    // Fallback: try raw JSON (legacy / migration path)
    try {
      return JSON.parse(manifest) as DashboardManifest;
    } catch {
      return {};
    }
  }
};

/** Re-encode a parsed manifest as base64(json), matching the frontend's serializeDashboardManifestForBackend. */
const serializeManifest = (manifest: DashboardManifest): string => toBase64(JSON.stringify(manifest)) as string;

/**
 * Guard for dashboard variable / preset structural changes.
 *
 * requireStructural = true  → needs EXPLORE_EXUPDATE capability AND AM role edit|admin
 * requireStructural = false → needs only AM role edit|admin (no platform capability)
 */
export const checkDashboardEditRights = async (
  context: AuthContext,
  user: AuthUser,
  workspace: BasicStoreEntityWorkspace,
  { requireStructural }: { requireStructural: boolean },
): Promise<void> => {
  const accessRight = await getUserAccessRight(user, workspace);
  if (accessRight === MEMBER_ACCESS_RIGHT_VIEW || accessRight === null) {
    throw ForbiddenAccess('You need at least edit access to this dashboard');
  }
  if (requireStructural && !isUserHasCapability(user, EXPLORE_EXUPDATE)) {
    throw ForbiddenAccess('You need the EXPLORE_EXUPDATE capability to modify dashboard structure');
  }
};

export const getWorkspaceVariables = (workspace: BasicStoreEntityWorkspace): DashboardVariable[] => {
  return parseManifest(workspace.manifest).variables ?? [];
};

export const workspaceVariableAdd = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
  input: DashboardVariableInput,
): Promise<BasicStoreEntityWorkspace> => {
  const workspace = await findById(context, user, workspaceId);
  if (!workspace) throw FunctionalError('Workspace not found', { id: workspaceId });
  await checkDashboardEditRights(context, user, workspace, { requireStructural: true });

  const manifest = parseManifest(workspace.manifest);
  const newVariable: DashboardVariable = {
    id: uuidv4(),
    name: input.name,
    filterKey: input.filterKey,
    filterKeyType: input.filterKeyType as DashboardVariable['filterKeyType'],
    defaultValue: input.defaultValue ?? null,
    restrictionMode: input.restrictionMode ?? null,
    restrictionValues: input.restrictionValues ?? null,
    restrictionFilters: input.restrictionFilters ?? null,
  };
  const updatedManifest: DashboardManifest = {
    ...manifest,
    variables: [...(manifest.variables ?? []), newVariable],
  };
  return editInternalObject<StoreEntityWorkspace>(
    context,
    user,
    workspaceId,
    ENTITY_TYPE_WORKSPACE,
    [{ key: 'manifest', value: [serializeManifest(updatedManifest)] }],
  );
};

export const workspaceVariableFieldPatch = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
  variableId: string,
  inputs: EditInput[],
): Promise<BasicStoreEntityWorkspace> => {
  const workspace = await findById(context, user, workspaceId);
  if (!workspace) throw FunctionalError('Workspace not found', { id: workspaceId });
  await checkDashboardEditRights(context, user, workspace, { requireStructural: true });

  const manifest = parseManifest(workspace.manifest);
  const variables = manifest.variables ?? [];
  const idx = variables.findIndex((v) => v.id === variableId);
  if (idx === -1) throw FunctionalError('Variable not found', { variableId });

  const updated = { ...variables[idx] };
  for (const { key, value } of inputs) {
    (updated as Record<string, unknown>)[key] = value?.[0] ?? null;
  }
  const updatedVariables = [...variables];
  updatedVariables[idx] = updated;
  const updatedManifest: DashboardManifest = { ...manifest, variables: updatedVariables };
  return editInternalObject<StoreEntityWorkspace>(
    context,
    user,
    workspaceId,
    ENTITY_TYPE_WORKSPACE,
    [{ key: 'manifest', value: [serializeManifest(updatedManifest)] }],
  );
};

export const workspaceVariableDelete = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
  variableId: string,
): Promise<string> => {
  const workspace = await findById(context, user, workspaceId);
  if (!workspace) throw FunctionalError('Workspace not found', { id: workspaceId });
  await checkDashboardEditRights(context, user, workspace, { requireStructural: true });

  const manifest = parseManifest(workspace.manifest);
  const variables = (manifest.variables ?? []).filter((v) => v.id !== variableId);
  const updatedManifest: DashboardManifest = { ...manifest, variables };
  await editInternalObject<StoreEntityWorkspace>(
    context,
    user,
    workspaceId,
    ENTITY_TYPE_WORKSPACE,
    [{ key: 'manifest', value: [serializeManifest(updatedManifest)] }],
  );
  return variableId;
};

// region Dashboard preset management

export const getWorkspacePresets = (workspace: BasicStoreEntityWorkspace): DashboardPreset[] => {
  return parseManifest(workspace.manifest).presets ?? [];
};

export const workspacePresetAdd = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
  input: DashboardPresetInput,
): Promise<BasicStoreEntityWorkspace> => {
  const workspace = await findById(context, user, workspaceId);
  if (!workspace) throw FunctionalError('Workspace not found', { id: workspaceId });
  await checkDashboardEditRights(context, user, workspace, { requireStructural: true });

  const manifest = parseManifest(workspace.manifest);
  const newPreset: DashboardPreset = {
    id: uuidv4(),
    name: input.name,
    variable_values: input.variable_values,
  };
  const updatedManifest: DashboardManifest = {
    ...manifest,
    presets: [...(manifest.presets ?? []), newPreset],
  };
  return editInternalObject<StoreEntityWorkspace>(
    context,
    user,
    workspaceId,
    ENTITY_TYPE_WORKSPACE,
    [{ key: 'manifest', value: [serializeManifest(updatedManifest)] }],
  );
};

export const workspacePresetFieldPatch = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
  presetId: string,
  inputs: EditInput[],
): Promise<BasicStoreEntityWorkspace> => {
  const workspace = await findById(context, user, workspaceId);
  if (!workspace) throw FunctionalError('Workspace not found', { id: workspaceId });
  await checkDashboardEditRights(context, user, workspace, { requireStructural: true });

  const manifest = parseManifest(workspace.manifest);
  const presets = manifest.presets ?? [];
  const idx = presets.findIndex((p) => p.id === presetId);
  if (idx === -1) throw FunctionalError('Preset not found', { presetId });

  const updated = { ...presets[idx] };
  for (const { key, value } of inputs) {
    (updated as Record<string, unknown>)[key] = value?.[0] ?? null;
  }
  const updatedPresets = [...presets];
  updatedPresets[idx] = updated;
  const updatedManifest: DashboardManifest = { ...manifest, presets: updatedPresets };
  return editInternalObject<StoreEntityWorkspace>(
    context,
    user,
    workspaceId,
    ENTITY_TYPE_WORKSPACE,
    [{ key: 'manifest', value: [serializeManifest(updatedManifest)] }],
  );
};

export const workspacePresetDelete = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
  presetId: string,
): Promise<string> => {
  const workspace = await findById(context, user, workspaceId);
  if (!workspace) throw FunctionalError('Workspace not found', { id: workspaceId });
  await checkDashboardEditRights(context, user, workspace, { requireStructural: true });

  const manifest = parseManifest(workspace.manifest);
  const presets = (manifest.presets ?? []).filter((p) => p.id !== presetId);
  const updatedManifest: DashboardManifest = { ...manifest, presets };
  await editInternalObject<StoreEntityWorkspace>(
    context,
    user,
    workspaceId,
    ENTITY_TYPE_WORKSPACE,
    [{ key: 'manifest', value: [serializeManifest(updatedManifest)] }],
  );
  return presetId;
};

// endregion
