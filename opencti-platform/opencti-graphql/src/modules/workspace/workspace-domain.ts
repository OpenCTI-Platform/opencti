import * as R from "ramda";
import type {FileHandle} from "fs/promises";
import { v4 as uuidv4 } from "uuid";
import {v4 as uuidv4} from 'uuid';
import {
  createEntity,
  deleteElementById,
  listThings,
  paginateAllThings,
  patchAttribute,
  updateAttribute,
} from "../../database/middleware";
import {listEntitiesPaginated, storeLoadById,
} from "../../database/middleware-loader";
import {BUS_TOPICS} from "../../config/conf";
import {delEditContext, notify, setEditContext} from "../../database/redis";
import {type BasicStoreEntityWorkspace, ENTITY_TYPE_WORKSPACE,
} from "./workspace-types";
import {FunctionalError} from "../../config/errors";
import type {AuthContext, AuthUser} from "../../types/user";
import type {
  EditContext,
  EditInput,
  ImportConfigurationInput,
  ImportWidgetInput,
  InputMaybe,
  MemberAccessInput,
  QueryWorkspacesArgs,
  WorkspaceAddInput,
  WorkspaceDuplicateInput,
  WorkspaceObjectsArgs,
} from "../../generated/graphql";
import {
  getUserAccessRight,
  isValidMemberAccessRight,
  MEMBER_ACCESS_RIGHT_ADMIN
} from '../../utils/access';
import { publishUserAction } from '../../listener/UserActionListener';
import { containsValidAdmin } from '../../utils/authorizedMembers';
import { elFindByIds } from '../../database/engine';
import type { BasicStoreEntity } from '../../types/store';
import { buildPagination, isEmptyField, READ_DATA_INDICES_WITHOUT_INTERNAL } from '../../database/utils';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { streamToString } from '../../database/file-storage';

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
      isValidMemberAccessRight(value.access_right) &&
      array.findIndex((e) => e.id === value.id) === index
    );
  });
  const hasValidAdmin = await containsValidAdmin(context, filteredInput, ['EXPLORE_EXUPDATE_EXDELETE', 'EXPLORE_EXUPDATE']);
  if (!hasValidAdmin) {
    throw FunctionalError("Workspace should have at least one admin");
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
  const filters = addFilter(args.filters, 'internal_id', investigated_entities_ids);
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
      ({ key, operation }) =>
        key === "investigated_entities_ids" &&
        (operation === "add" || operation === "replace"),
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
    throw FunctionalError("Invalid ids specified", { ids: missingEntitiesIds });
  }
};

const initializeAuthorizedMembers = (
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
    event_type: "mutation",
    event_scope: "create",
    event_access: "extended",
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
  await publishUserAction({
    user,
    event_type: "mutation",
    event_scope: "delete",
    event_access: "administration",
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
    (workspaceToReturn) =>
      notify(
        BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC,
        workspaceToReturn,
        user,
      ),
  );
};

const configurationImportTypeValidation = new Map<string, string>();
configurationImportTypeValidation.set(
  "dashboard",
  "Invalid type. Please import OpenCTI dashboard-type only",
);
configurationImportTypeValidation.set(
  "widget",
  "Invalid type. Please import OpenCTI widget-type only",
);

export const checkConfigurationImport = (type: string, parsedData: any) => {
  if (configurationImportTypeValidation.has(type) && parsedData.type !== type) {
    throw FunctionalError(configurationImportTypeValidation.get(type), {
      reason: parsedData.type,
    });
  }

  const MINIMAL_COMPATIBLE_VERSION = "5.12.0";
  const isCompatibleOpenCtiVersion = (openCtiVersion: string) => {
    const [major, minor, patch] = openCtiVersion.split('.').map((number) => parseInt(number, 10));
    const [openCtiMajor, openCtiMinor, openCtiPatch] = MINIMAL_COMPATIBLE_VERSION.split('.').map((number) => parseInt(number, 10));
    return major >= openCtiMajor && minor >= openCtiMinor && patch >= openCtiPatch;
  };

  if (!isCompatibleOpenCtiVersion(parsedData.openCTI_version)) {
    throw FunctionalError(`Invalid version of the platform. Please upgrade your OpenCTI. Minimal version required: ${MINIMAL_COMPATIBLE_VERSION}`, { reason: parsedData.openCTI_version });
  }
};

export const checkWidgetConfigurationImport = (parsedData: any) => {
  if (parsedData.type !== 'widget') {
    throw FunctionalError('Invalid type. Please import OpenCTI widget-type only', { reason: parsedData.type });
  }

  const MINIMAL_COMPATIBLE_VERSION = '5.12.0';
  const isCompatibleOpenCtiVersion = (openCtiVersion: string) => {
    const [major, minor, patch] = openCtiVersion
      .split(".")
      .map((number) => parseInt(number, 10));
    const [openCtiMajor, openCtiMinor, openCtiPatch] =
      MINIMAL_COMPATIBLE_VERSION.split(".").map((number) =>
        parseInt(number, 10),
      );
    return (
      major >= openCtiMajor && minor >= openCtiMinor && patch >= openCtiPatch
    );
  };

  if (!isCompatibleOpenCtiVersion(parsedData.openCTI_version)) {
    throw FunctionalError(
      `Invalid version of the platform. Please upgrade your OpenCTI. Minimal version required: ${MINIMAL_COMPATIBLE_VERSION}`,
      { reason: parsedData.openCTI_version },
    );
  }
};
/*
// Refactor to mappedData as below
async function importDashboardConfiguration(context: AuthContext, user: AuthUser, mappedData: { authorized_members: MemberAccessInput[]; manifest: any; name: any; openCTI_version: any; type: any }) {
  const importWorkspaceCreation = await createEntity(
      context,
      user,
      mappedData,
      ENTITY_TYPE_WORKSPACE,
  );
  const workspaceId = importWorkspaceCreation.id;
  await publishUserAction({
    user,
    event_type: "mutation",
    event_scope: "create",
    event_access: "extended",
    message: `import ${importWorkspaceCreation.name} workspace`,
    context_data: {
      id: workspaceId,
      entity_type: ENTITY_TYPE_WORKSPACE,
      input: importWorkspaceCreation,
    },
  });
  await notify(
      BUS_TOPICS[ENTITY_TYPE_WORKSPACE].ADDED_TOPIC,
      importWorkspaceCreation,
      user,
  );
  return workspaceId;
}
*/
export const workspaceConfigurationImport = async (
  context: AuthContext,
  user: AuthUser,
  file: Promise<FileHandle>,
) => {
  const authorizedMembers = initializeAuthorizedMembers([], user);
  const parsedData = await extractContentFrom(file);

  const mappedData = {
    type: parsedData.type,
    openCTI_version: parsedData.openCTI_version,
    name: parsedData.configuration.name,
    manifest: parsedData.configuration.manifest,
    authorized_members: authorizedMembers,
  };
  checkConfigurationImport("dashboard", mappedData);
  const importWorkspaceCreation = await createEntity(context, user, mappedData, ENTITY_TYPE_WORKSPACE);
  const workspaceId = importWorkspaceCreation.id;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `import ${importWorkspaceCreation.name} workspace`,
    context_data: { id: workspaceId, entity_type: ENTITY_TYPE_WORKSPACE, input: importWorkspaceCreation }
  });
  await notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].ADDED_TOPIC, importWorkspaceCreation, user);
  return workspaceId;
};

export const duplicateWorkspace = async (
  context: AuthContext,
  user: AuthUser,
  input: WorkspaceDuplicateInput,
) => {
  const authorizedMembers = initializeAuthorizedMembers([], user);
  const workspaceToCreate = { ...input, authorized_members: authorizedMembers };
  const created = await createEntity(
    context,
    user,
    workspaceToCreate,
    ENTITY_TYPE_WORKSPACE,
  );
  await publishUserAction({
    user,
    event_type: "mutation",
    event_scope: "create",
    event_access: "extended",
    message: `creates ${created.type} workspace \`${created.name}\` from custom-named duplication`,
    context_data: { id: created.id, entity_type: ENTITY_TYPE_WORKSPACE, input },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].ADDED_TOPIC, created, user);
};

interface DashboardConfiguration {
  name: string;
  manifest: string;
}
interface WidgetConfiguration {
  type: string;
  perspective: string;
  dataSelection: [
    {
      label: string;
      attribute: string;
      date_attribute: string;
      perspective: string;
      isTo: boolean;
      filters: {};
      dynamicFrom: {};
      dynamicTo: {};
    },
  ];
  parameters: {};
  layout: {
    w: number;
    h: number;
    x: number;
    y: number;
    i: string;
    moved: boolean;
    static: boolean;
  };
}

const mapFromType: (
  type: string,
  parsedData: {
    openCTI_version: string;
    type: string;
    configuration: WidgetConfiguration;
  },
) => {
  type: string;
  openCTI_version: string;
  configuration: Configuration;
} = (
  type: string,
  parsedData: {
    openCTI_version: string;
    type: string;
    configuration: Configuration;
  },
) => {
  return {
    type: parsedData.type,
    openCTI_version: parsedData.openCTI_version,
    configuration: parsedData.configuration,
  };
};

type Configuration = WidgetConfiguration | DashboardConfiguration;

async function importWidgetConfiguration(
  input: ImportConfigurationInput,
  mappedData:
    {
      type: string;
      openCTI_version: string;
      configuration: Configuration;
    },
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
) {
  const importedWidgetId = uuidv4();
  const dashboardManifestObjects = JSON.parse(
    fromBase64(input.dashboardManifest) || "",
  );
  const updatedObjects = {
    ...dashboardManifestObjects,
    widgets: {
      ...dashboardManifestObjects.widgets,
      [`${importedWidgetId}`]: {
        id: importedWidgetId,
        ...mappedData?.configuration,
      },
    },
  };
  const updatedManifest = toBase64(JSON.stringify(updatedObjects));
  const { element } = await updateAttribute(
    context,
    user,
    workspaceId,
    ENTITY_TYPE_WORKSPACE,
    [{ key: "manifest", value: [updatedManifest] }],
  );
  await publishUserAction({
    user,
    event_type: "mutation",
    event_scope: "create",
    event_access: "extended",
    message: `import widget (id : ${importedWidgetId}) in workspace (id : ${workspaceId})`,
    context_data: {
      id: workspaceId,
      entity_type: ENTITY_TYPE_WORKSPACE,
      input: element,
    },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, element, user);
}

export const importConfiguration = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
  input: ImportConfigurationInput,
) => {
  const parsedData = await extractContentFrom(input.file);

  const mappedData = mapFromType(input.importType, parsedData);
  checkConfigurationImport(input.importType, mappedData);

  if(input.importType === 'widget') {
    return await importWidgetConfiguration(
        input,
        mappedData,
        context,
        user,
        workspaceId,
    );
  }

  /* Check widget import before refactoring
  if(input.importType === 'dashboard') {
    return await importDashboardConfiguration(context, user, mappedData);
  }
  */
};
export const importWidget = async (
  context: AuthContext,
  user: AuthUser,
  workspaceId: string,
  input: ImportWidgetInput,
) => {
  const parsedData = await extractContentFrom(input.file);

  const mappedData = {
    type: parsedData.type,
    openCTI_version: parsedData.openCTI_version,
    widget: parsedData.configuration,
  };
  checkConfigurationImport("widget", mappedData);

  const importedWidgetId = uuidv4();
  const dashboardManifestObjects = JSON.parse(
    fromBase64(input.dashboardManifest) || "",
  );
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
    [{ key: "manifest", value: [updatedManifest] }],
  );
  await publishUserAction({
    user,
    event_type: "mutation",
    event_scope: "create",
    event_access: "extended",
    message: `import widget (id : ${importedWidgetId}) in workspace (id : ${workspaceId})`,
    context_data: {
      id: workspaceId,
      entity_type: ENTITY_TYPE_WORKSPACE,
      input: element,
    },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, element, user);
};
