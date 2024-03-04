import * as R from 'ramda';
import type { FileHandle } from 'fs/promises';
import { v4 as uuidv4 } from 'uuid';
import pjson from '../../../package.json';
import { createEntity, deleteElementById, listThings, paginateAllThings, patchAttribute, updateAttribute } from '../../database/middleware';
import { internalFindByIds, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { BUS_TOPICS } from '../../config/conf';
import { delEditContext, notify, setEditContext } from '../../database/redis';
import { ENTITY_TYPE_WORKSPACE, type BasicStoreEntityWorkspace } from './workspace-types';
import { DatabaseError, FunctionalError } from '../../config/errors';
import type { AuthContext, AuthUser } from '../../types/user';
import type {
  EditContext,
  EditInput,
  Filter,
  FilterGroup,
  ImportWidgetInput,
  InputMaybe,
  MemberAccessInput,
  QueryWorkspacesArgs,
  WorkspaceAddInput,
  WorkspaceDuplicateInput,
  WorkspaceObjectsArgs
} from '../../generated/graphql';
import { getUserAccessRight, isValidMemberAccessRight, MEMBER_ACCESS_RIGHT_ADMIN, SYSTEM_USER } from '../../utils/access';
import { publishUserAction } from '../../listener/UserActionListener';
import { containsValidAdmin } from '../../utils/authorizedMembers';
import { elFindByIds, elRawDeleteByQuery } from '../../database/engine';
import type { BasicStoreEntity, BasicStoreObject } from '../../types/store';
import { buildPagination, fromBase64, isEmptyField, isNotEmptyField, READ_DATA_INDICES_WITHOUT_INTERNAL, READ_INDEX_INTERNAL_OBJECTS, toBase64 } from '../../database/utils';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { extractContentFrom } from '../../utils/fileToContent';
import { isInternalId, isStixId } from '../../schema/schemaUtils';
import { INSTANCE_REGARDING_OF } from '../../utils/filtering/filtering-constants';
import { isCompatibleVersionWithMinimal } from '../../utils/version';
import { getEntitiesListFromCache } from '../../database/cache';
import { ENTITY_TYPE_PUBLIC_DASHBOARD, type PublicDashboardCached } from '../publicDashboard/publicDashboard-types';

export const findById = (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
) => {
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

export const editAuthorizedMembers = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
  input: MemberAccessInput[],
) => {
  // validate input (validate access right) and remove duplicates
  const filteredInput = input.filter((value, index, array) => {
    return (
      isValidMemberAccessRight(value.access_right)
      && array.findIndex((e) => e.id === value.id) === index
    );
  });
  const hasValidAdmin = await containsValidAdmin(context, filteredInput, ['EXPLORE_EXUPDATE_EXDELETE']);
  if (!hasValidAdmin) {
    throw FunctionalError('Workspace should have at least one admin');
  }
  const authorizedMembersInput = filteredInput.map((e) => {
    return { id: e.id, access_right: e.access_right };
  });
  const patch = { authorized_members: authorizedMembersInput };
  const { element } = await patchAttribute(
    context,
    user,
    workspaceId,
    ENTITY_TYPE_WORKSPACE,
    patch,
  );
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, element, user);
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
    }).catch((err) => {
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

// region workspace ids converter
// Export => Dashboard filter ids must be converted to standard id
// Import => Dashboards filter ids must be converted back to internal id
const toKeys = (k: string | string[]) => (Array.isArray(k) ? k : [k]);
const extractFiltersIds = (filter: FilterGroup, from: 'internal' | 'stix') => {
  const internalIds: string[] = [];
  filter.filters.forEach((f) => {
    let innerValues = f.values;
    if (toKeys(f.key).includes(INSTANCE_REGARDING_OF)) {
      innerValues = innerValues.find((v) => toKeys(v.key).includes('id'))?.values ?? [];
    }
    const ids = innerValues.filter((value) => {
      if (from === 'internal') return isInternalId(value);
      return isStixId(value);
    });
    internalIds.push(...ids);
  });
  filter.filterGroups.forEach((group) => {
    const groupIds = extractFiltersIds(group, from);
    internalIds.push(...groupIds);
  });
  return R.uniq(internalIds);
};

const filterValuesRemap = (filter: Filter, resolvedMap: { [k: string]: BasicStoreObject }, from: 'internal' | 'stix') => {
  return filter.values.map((value) => {
    if (from === 'internal' && isInternalId(value)) {
      return resolvedMap[value]?.standard_id ?? value;
    }
    if (from === 'stix' && isStixId(value)) {
      return resolvedMap[value]?.internal_id ?? value;
    }
    return value;
  });
};
const replaceFiltersIds = (filter: FilterGroup, resolvedMap: { [k: string]: BasicStoreObject }, from: 'internal' | 'stix') => {
  filter.filters.forEach((f) => {
    // Explicit reassign working by references
    if (toKeys(f.key).includes(INSTANCE_REGARDING_OF)) {
      const regardingOfValues = [];
      const idInnerFilter = f.values.find((v) => toKeys(v.key).includes('id'));
      if (idInnerFilter) { // Id is not mandatory
        idInnerFilter.values = filterValuesRemap(idInnerFilter, resolvedMap, from);
        regardingOfValues.push(idInnerFilter);
      }
      const typeInnerFilter = f.values.find((v) => toKeys(v.key).includes('type'));
      if (typeInnerFilter) { // Type is not mandatory
        regardingOfValues.push(typeInnerFilter);
      }
      // eslint-disable-next-line no-param-reassign
      f.values = regardingOfValues;
    } else {
      // eslint-disable-next-line no-param-reassign
      f.values = filterValuesRemap(f, resolvedMap, from);
    }
  });
  filter.filterGroups.forEach((group) => {
    replaceFiltersIds(group, resolvedMap, from);
  });
};
// For now, this function is only useful for workspace dashboards
const convertWidgetsIds = async (context: AuthContext, user: AuthUser, widgetDefinitions: any[], from: 'internal' | 'stix') => {
  // First iteration to resolve all ids to translate
  const resolvingIds: string[] = [];
  widgetDefinitions.forEach((widgetDefinition: any) => {
    widgetDefinition.dataSelection.forEach((selection: any) => {
      if (isNotEmptyField(selection.filters)) {
        const filterIds = extractFiltersIds(selection.filters as FilterGroup, from);
        resolvingIds.push(...filterIds);
      }
      if (isNotEmptyField(selection.dynamicFrom)) {
        const dynamicFromIds = extractFiltersIds(selection.dynamicFrom as FilterGroup, from);
        resolvingIds.push(...dynamicFromIds);
      }
      if (isNotEmptyField(selection.dynamicTo)) {
        const dynamicToIds = extractFiltersIds(selection.dynamicTo as FilterGroup, from);
        resolvingIds.push(...dynamicToIds);
      }
    });
  });
  // Resolve then second iteration to replace the ids
  const resolveOpts = { baseData: true, toMap: true, mapWithAllIds: true };
  const resolvedMap = await internalFindByIds(context, user, resolvingIds, resolveOpts);
  const idsMap = resolvedMap as unknown as { [k: string]: BasicStoreObject };
  widgetDefinitions.forEach((widgetDefinition: any) => {
    widgetDefinition.dataSelection.forEach((selection: any) => {
      if (isNotEmptyField(selection.filters)) {
        replaceFiltersIds(selection.filters as FilterGroup, idsMap, from);
      }
      if (isNotEmptyField(selection.dynamicFrom)) {
        replaceFiltersIds(selection.dynamicFrom as FilterGroup, idsMap, from);
      }
      if (isNotEmptyField(selection.dynamicTo)) {
        replaceFiltersIds(selection.dynamicTo as FilterGroup, idsMap, from);
      }
    });
  });
};
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
