import * as R from 'ramda';
import type { FileHandle } from 'fs/promises';
import { v4 as uuidv4 } from 'uuid';
import pjson from '../../../package.json';
import { createEntity, deleteElementById, listThings, paginateAllThings, updateAttribute } from '../../database/middleware';
import { listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { BUS_TOPICS } from '../../config/conf';
import { delEditContext, notify, setEditContext } from '../../database/redis';
import { ENTITY_TYPE_WORKSPACE, type BasicStoreEntityWorkspace } from './workspace-types';
import { DatabaseError, FunctionalError } from '../../config/errors';
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
  WorkspaceObjectsArgs
} from '../../generated/graphql';
import { getUserAccessRight, MEMBER_ACCESS_RIGHT_ADMIN, SYSTEM_USER } from '../../utils/access';
import { publishUserAction } from '../../listener/UserActionListener';
import { editAuthorizedMembers } from '../../utils/authorizedMembers';
import { elFindByIds, elRawDeleteByQuery } from '../../database/engine';
import type { BasicStoreEntity } from '../../types/store';
import { buildPagination, fromBase64, isEmptyField, isNotEmptyField, READ_DATA_INDICES_WITHOUT_INTERNAL, READ_INDEX_INTERNAL_OBJECTS, toBase64 } from '../../database/utils';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { extractContentFrom } from '../../utils/fileToContent';
import { isCompatibleVersionWithMinimal } from '../../utils/version';
import { getEntitiesListFromCache } from '../../database/cache';
import { ENTITY_TYPE_PUBLIC_DASHBOARD, type PublicDashboardCached } from '../publicDashboard/publicDashboard-types';
import { convertWidgetsIds } from './workspace-utils';

export const PLATFORM_DASHBOARD = 'cf093b57-713f-404b-a210-a1c5c8cb3791';

export const findById = (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
) => {
  if (workspaceId === PLATFORM_DASHBOARD) {
    return {
      id: PLATFORM_DASHBOARD
    } as BasicStoreEntityWorkspace;
  }
  return storeLoadById<BasicStoreEntityWorkspace>(
    context,
    user,
    workspaceId,
    ENTITY_TYPE_WORKSPACE,
  );
};

export const findAll = (
  context: AuthContext,
  user: AuthUser,
  args: QueryWorkspacesArgs,
) => {
  return listEntitiesPaginated<BasicStoreEntityWorkspace>(
    context,
    user,
    [ENTITY_TYPE_WORKSPACE],
    args,
  );
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
  context: AuthContext,
  user: AuthUser,
  workspace: BasicStoreEntityWorkspace,
) => {
  return getUserAccessRight(user, workspace);
};

export const getOwnerId = (workspace: BasicStoreEntityWorkspace) => {
  return Array.isArray(workspace.creator_id) && workspace.creator_id.length > 0
    ? workspace.creator_id.at(0)
    : workspace.creator_id;
};

export const objects = async (
  context: AuthContext,
  user: AuthUser,
  { investigated_entities_ids }: BasicStoreEntityWorkspace,
  args: WorkspaceObjectsArgs,
) => {
  if (isEmptyField(investigated_entities_ids)) {
    return buildPagination(0, null, [], 0);
  }
  const filters = addFilter(
    args.filters,
    'internal_id',
    investigated_entities_ids,
  );
  const finalArgs = { ...args, filters };
  if (args.all) {
    return paginateAllThings(context, user, args.types, finalArgs);
  }
  return listThings(context, user, args.types, finalArgs);
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
  const authorizedMembers = initializeAuthorizedMembers(
    input.authorized_members,
    user,
  );
  const workspaceToCreate = { ...input, authorized_members: authorizedMembers };
  const created = await createEntity(
    context,
    user,
    workspaceToCreate,
    ENTITY_TYPE_WORKSPACE,
  );
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `creates ${created.type} workspace \`${created.name}\``,
    context_data: { id: created.id, entity_type: ENTITY_TYPE_WORKSPACE, input },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].ADDED_TOPIC, created, user);
};

export const workspaceDelete = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
) => {
  const deleted = await deleteElementById(
    context,
    user,
    workspaceId,
    ENTITY_TYPE_WORKSPACE,
  );

  // region cascade delete associated public dashboards
  const publicDashboards = await getEntitiesListFromCache<PublicDashboardCached>(
    context,
    SYSTEM_USER,
    ENTITY_TYPE_PUBLIC_DASHBOARD
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
              { terms: { 'internal_id.keyword': publicDashboardsToDelete } }
            ]
          }
        }
      }
    }).catch((err: Error) => {
      throw DatabaseError(
        '[DELETE] Error deleting public dashboard for workspace ',
        { cause: err, workspace_id: workspaceId, }
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
      input: deleted,
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
  const { element } = await updateAttribute(
    context,
    user,
    workspaceId,
    ENTITY_TYPE_WORKSPACE,
    inputs,
  );
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, element, user);
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

const MINIMAL_COMPATIBLE_VERSION = '5.12.16';
const configurationImportTypeValidation = new Map<string, string>();
configurationImportTypeValidation.set(
  'dashboard',
  'Invalid type. Please import OpenCTI dashboard-type only',
);
configurationImportTypeValidation.set(
  'widget',
  'Invalid type. Please import OpenCTI widget-type only',
);

export const checkConfigurationImport = (type: string, parsedData: any) => {
  if (configurationImportTypeValidation.has(type) && parsedData.type !== type) {
    throw FunctionalError(configurationImportTypeValidation.get(type), {
      reason: parsedData.type,
    });
  }

  if (!isCompatibleVersionWithMinimal(parsedData.openCTI_version, MINIMAL_COMPATIBLE_VERSION)) {
    throw FunctionalError(
      `Invalid version of the platform. Please upgrade your OpenCTI. Minimal version required: ${MINIMAL_COMPATIBLE_VERSION}`,
      { reason: parsedData.openCTI_version },
    );
  }
};

// region workspace ids converter_2_1
// Export => Dashboard filter ids must be converted to standard id
// Import => Dashboards filter ids must be converted back to internal id
const convertWorkspaceManifestIds = async (context: AuthContext, user: AuthUser, manifest: string, from: 'internal' | 'stix'): Promise<string> => {
  const parsedManifest = JSON.parse(fromBase64(manifest) ?? '{}');
  // Regeneration for dashboards
  if (parsedManifest && isNotEmptyField(parsedManifest.widgets)) {
    const { widgets } = parsedManifest;
    const widgetDefinitions = Object.values(widgets);
    await convertWidgetsIds(context, user, widgetDefinitions, from);
    return toBase64(JSON.stringify(parsedManifest)) as string;
  }
  return manifest;
};
// endregion

export const generateWorkspaceExportConfiguration = async (context: AuthContext, user: AuthUser, workspace: BasicStoreEntityWorkspace) => {
  if (workspace.type !== 'dashboard') {
    throw FunctionalError('WORKSPACE_EXPORT_INCOMPATIBLE_TYPE', { type: workspace.type });
  }
  const generatedManifest = await convertWorkspaceManifestIds(context, user, workspace.manifest, 'internal');
  const exportConfigration = {
    openCTI_version: pjson.version,
    type: 'dashboard',
    configuration: {
      name: workspace.name,
      manifest: generatedManifest
    },
  };
  return JSON.stringify(exportConfigration);
};

export const generateWidgetExportConfiguration = async (context: AuthContext, user: AuthUser, workspace: BasicStoreEntityWorkspace, widgetId: string) => {
  if (workspace.type !== 'dashboard') {
    throw FunctionalError('WORKSPACE_EXPORT_INCOMPATIBLE_TYPE', { type: workspace.type });
  }
  const parsedManifest = JSON.parse(fromBase64(workspace.manifest) ?? '{}');
  if (parsedManifest && isNotEmptyField(parsedManifest.widgets) && parsedManifest.widgets[widgetId]) {
    const widgetDefinition = parsedManifest.widgets[widgetId];
    delete widgetDefinition.id; // Remove current widget id
    await convertWidgetsIds(context, user, [widgetDefinition], 'internal');
    const exportConfigration = {
      openCTI_version: pjson.version,
      type: 'widget',
      configuration: toBase64(JSON.stringify(widgetDefinition)) as string
    };
    return JSON.stringify(exportConfigration);
  }
  throw FunctionalError('WIDGET_EXPORT_NOT_FOUND', { workspace: workspace.id, widget: widgetId });
};

export const workspaceImportConfiguration = async (context: AuthContext, user: AuthUser, file: Promise<FileHandle>) => {
  const parsedData = await extractContentFrom(file);
  checkConfigurationImport('dashboard', parsedData);
  const authorizedMembers = initializeAuthorizedMembers([], user);
  const { manifest } = parsedData.configuration;
  // Manifest ids must be rewritten for filters
  const generatedManifest = await convertWorkspaceManifestIds(context, user, manifest, 'stix');
  const mappedData = {
    type: parsedData.type,
    openCTI_version: parsedData.openCTI_version,
    name: parsedData.configuration.name,
    manifest: generatedManifest,
    authorized_members: authorizedMembers,
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
      input: importWorkspaceCreation,
    },
  });
  await notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].ADDED_TOPIC, importWorkspaceCreation, user);
  return workspaceId;
};

export const duplicateWorkspace = async (context: AuthContext, user: AuthUser, input: WorkspaceDuplicateInput) => {
  const authorizedMembers = initializeAuthorizedMembers([], user);
  const workspaceToCreate = { ...input, authorized_members: authorizedMembers };
  const created = await createEntity(context, user, workspaceToCreate, ENTITY_TYPE_WORKSPACE);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `creates ${created.type} workspace \`${created.name}\` from custom-named duplication`,
    context_data: { id: created.id, entity_type: ENTITY_TYPE_WORKSPACE, input },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].ADDED_TOPIC, created, user);
};

export const workspaceImportWidgetConfiguration = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
  input: ImportWidgetInput,
) => {
  const parsedData = await extractContentFrom(input.file);
  checkConfigurationImport('widget', parsedData);
  const widgetDefinition = JSON.parse(fromBase64(parsedData.configuration) || '{}');
  await convertWidgetsIds(context, user, [widgetDefinition], 'stix');
  const mappedData = {
    type: parsedData.type,
    openCTI_version: parsedData.openCTI_version,
    widget: widgetDefinition,
  };
  const importedWidgetId = uuidv4();
  const dashboardManifestObjects = JSON.parse(fromBase64(input.dashboardManifest) || '{}');
  const updatedObjects = {
    ...dashboardManifestObjects,
    widgets: {
      ...dashboardManifestObjects.widgets,
      [`${importedWidgetId}`]: { id: importedWidgetId, ...mappedData.widget },
    },
  };
  const updatedManifest = toBase64(JSON.stringify(updatedObjects));
  const { element } = await updateAttribute(
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
      input: element,
    },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, element, user);
};

export const isDashboardShared = async (context: AuthContext, workspace: BasicStoreEntityWorkspace) => {
  if (workspace.type !== 'dashboard') return false;
  const publicDashboards = await getEntitiesListFromCache<PublicDashboardCached>(
    context,
    SYSTEM_USER,
    ENTITY_TYPE_PUBLIC_DASHBOARD
  );
  return publicDashboards.some((publicDashboard) => (
    publicDashboard.dashboard_id === workspace.id && publicDashboard.enabled
  ));
};
