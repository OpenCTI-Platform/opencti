import { v5 as uuidv5 } from 'uuid';
import { createEntity, deleteElementById, patchAttribute, updateAttribute } from '../database/middleware';
import { type GetHttpClient, getHttpClient } from '../utils/http-client';
import { connector, connectors } from '../modules/connector/connector-domain';
import { registerConnectorQueues, unregisterConnector, unregisterExchanges } from '../modules/connector/connector-rabbitmq';
import { ENTITY_TYPE_SYNC, ENTITY_TYPE_WORK } from '../schema/internalObject';
import { FunctionalError, ValidationError } from '../config/errors';
import { elLoadById } from '../database/engine';
import { isEmptyField, READ_INDEX_HISTORY } from '../database/utils';
import { OPENCTI_NAMESPACE } from '../schema/general';
import { SYSTEM_USER } from '../utils/access';
import { delEditContext, notify, redisGetWork, setEditContext } from '../database/redis';
import { internalLoadById, pageEntitiesConnection, storeLoadById } from '../database/middleware-loader';
import { completeContextDataForEntity, publishUserAction, type UserImportActionContextData } from '../listener/UserActionListener';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreEntitySynchronizer } from '../types/connector';
import type { BasicStoreEntityConnector } from '../modules/connector/connector-types';
import { connectorDelete, registerConnector } from '../modules/connector/connector-domain';
import {
  ConnectorType,
  ConnectorPriorityGroup,
  type DraftWorkspaceAddInput,
  type EditContext,
  type EditInput,
  type SynchronizerAddAutoUserInput,
  type SynchronizerAddInput,
  type SynchronizerFetchInput,
  ValidationMode,
} from '../generated/graphql';
import { BUS_TOPICS, logApp, PLATFORM_VERSION } from '../config/conf';
import { defaultValidationMode, loadFile, uploadJobImport } from '../database/file-storage';
import { controlUserConfidenceAgainstElement } from '../utils/confidence-level';
import { isCompatibleVersionWithMinimal } from '../utils/version';
import { extractEntityRepresentativeName } from '../database/entity-representative';
import type { BasicStoreCommon, StoreEntity } from '../types/store';
import { addWorkbenchDraftConvertionCount, addWorkbenchValidationCount } from '../manager/telemetryManager';
import { createOnTheFlyUser } from '../modules/user/user-domain';
import { addDraftWorkspace } from '../modules/draftWorkspace/draftWorkspace-domain';
import type { Work } from '../types/work';
import { AxiosError } from 'axios';
import { URL } from 'node:url';
import { extractContentFrom } from '../utils/fileToContent';
import type { FileHandle } from 'fs/promises';
import { encryptSynchronizerCredential } from './connector-sync-crypto';
import { testSync as testSyncUtils } from './connector-utils';
import { verifyIngestionUri } from '../modules/ingestion/ingestion-common';

const MINIMAL_SYNCHRONIZER_COMPATIBLE_VERSION = '6.9.6';

// region works
export const connectorForWork = async (context: AuthContext, user: AuthUser, id: string) => {
  const work = await elLoadById<Work>(context, user, id, { type: ENTITY_TYPE_WORK, indices: READ_INDEX_HISTORY });
  if (work) return connector(context, user, work.connector_id);
  return null;
};

export const computeWorkStatus = async (work: Work) => {
  if (work.status === 'complete') {
    return { import_processed_number: work.completed_number, import_expected_number: work.import_expected_number };
  }
  // If running, information in redis.
  const redisData = await redisGetWork(work.id);
  // If data in redis not exist, just send default values
  return redisData ?? { import_processed_number: null, import_expected_number: null };
};
// endregion

// region syncs
interface ConnectorIngestionInput {
  id: string;
  type: 'RSS' | 'CSV' | 'TAXII' | 'TAXII-PUSH' | 'JSON' | 'FORM';
  name: string;
  connector_user_id?: string | null;
  is_running: boolean;
  connector_priority_group?: ConnectorPriorityGroup;
}
export const connectorIdFromIngestId = (id: string) => uuidv5(id, OPENCTI_NAMESPACE);
export const registerConnectorForIngestion = async (context: AuthContext, input: ConnectorIngestionInput) => {
  // Create the representing connector
  await registerConnector(context, SYSTEM_USER, {
    id: connectorIdFromIngestId(input.id),
    name: `[FEED - ${input.type}] ${input.name}`,
    type: ConnectorType.ExternalImport,
    auto: true,
    auto_update: false,
    scope: ['application/stix+json;version=2.1'],
    only_contextual: false,
    playbook_compatible: false,
  }, {
    built_in: true,
    active: input.is_running,
    connector_user_id: input.connector_user_id,
  });
};

export const unregisterConnectorForIngestion = async (context: AuthContext, id: string) => {
  const connectorId = connectorIdFromIngestId(id);
  await connectorDelete(context, SYSTEM_USER, connectorId);
};

type SynchronizerPatch = {
  running?: boolean;
  current_state_date?: Date | string;
  last_execution_date?: Date | string;
  last_execution_status?: string;
};

export const patchSync = async (context: AuthContext, user: AuthUser, id: string, patch: SynchronizerPatch) => {
  const patched = await patchAttribute(context, user, id, ENTITY_TYPE_SYNC, patch);
  return patched.element;
};
export const findSyncById = async (context: AuthContext, user: AuthUser, syncId: string) => {
  return storeLoadById<BasicStoreEntitySynchronizer>(context, user, syncId, ENTITY_TYPE_SYNC);
};
export const findSyncPaginated = async (context: AuthContext, user: AuthUser, opts = {}) => {
  return pageEntitiesConnection(context, SYSTEM_USER, [ENTITY_TYPE_SYNC], opts);
};

export const testSync = async (context: AuthContext, user: AuthUser, sync: SynchronizerAddInput) => {
  verifyIngestionUri(sync.uri);
  return testSyncUtils(context, user, sync);
};

export const computeStreamRemoteUrl = (inputUri: string) => {
  const inputAsURL = new URL(inputUri);
  if (inputAsURL.protocol !== 'http:' && inputAsURL.protocol !== 'https:') {
    throw FunctionalError('Stream URL format is not correct');
  }
  const sanitizeUri = `${inputAsURL.origin}${inputAsURL.pathname}`;
  return `${sanitizeUri.endsWith('/') ? sanitizeUri.slice(0, -1) : sanitizeUri}/graphql`;
};

export const fetchRemoteStreams = async (context: AuthContext, user: AuthUser, input: SynchronizerFetchInput) => {
  const { token, uri, ssl_verify } = input;
  verifyIngestionUri(uri);
  try {
    const query = `
    query SyncCreationStreamCollectionQuery {
      streamCollections(first: 1000) {
        edges {
          node {
            id
            name
            description
            filters
          }
        }
      }
    }
  `;

    const headers = !isEmptyField(token) ? { authorization: `Bearer ${token}` } : undefined;
    const httpClientOptions: GetHttpClient = { headers, rejectUnauthorized: ssl_verify ?? false, responseType: 'json' };
    const httpClient = getHttpClient(httpClientOptions);
    const remoteUri = computeStreamRemoteUrl(uri);
    const { data } = await httpClient.post(remoteUri, { query });
    return data.data.streamCollections.edges.map((e: any) => e.node);
  } catch (e) {
    let errorMessage = '';
    if (e instanceof AxiosError) {
      logApp.error('[OPENCTI-MODULE] Issue when trying to call OpenCTI remote stream', { httpStatus: e.status, message: e.message, streamURI: uri });
      errorMessage = e.message;
    }
    throw ValidationError('Error getting the streams from remote OpenCTI', 'uri', { cause: errorMessage });
  }
};
export const registerSync = async (
  context: AuthContext,
  user: AuthUser,
  syncData: SynchronizerAddInput,
) => {
  verifyIngestionUri(syncData.uri);

  let finalSyncData = { ...syncData, running: false };

  if (finalSyncData.automatic_user) {
    const onTheFlyCreatedUser = await createOnTheFlyUser(
      context,
      user,
      {
        userName: finalSyncData.user_id,
        serviceAccount: true,
        confidenceLevel: finalSyncData.confidence_level,
      },
    );

    finalSyncData = {
      ...finalSyncData,
      user_id: onTheFlyCreatedUser.id,
    };
  }

  const {
    automatic_user: _automatic_user,
    confidence_level: _confidence_level,
    ...synchronizerToCreate
  } = finalSyncData;

  await testSyncUtils(context, user, synchronizerToCreate);

  if (synchronizerToCreate.token) {
    synchronizerToCreate.token = await encryptSynchronizerCredential(synchronizerToCreate.token);
  }

  const { element, isCreation } = await createEntity(
    context,
    user,
    synchronizerToCreate,
    ENTITY_TYPE_SYNC,
    { complete: true },
  );

  if (isCreation) {
    const syncId = element.internal_id;

    await registerConnectorQueues(
      syncId,
      `Sync ${syncId} queue`,
      'internal',
      'sync',
    );

    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'administration',
      message: `creates synchronizer \`${finalSyncData.name}\``,
      context_data: {
        id: element.id,
        entity_type: ENTITY_TYPE_SYNC,
        input: synchronizerToCreate,
      },
    });
  }

  return element;
};

export const syncAddInputFromImport = async (file: Promise<FileHandle>) => {
  const parsedData = await extractContentFrom(file);

  // check platform version compatibility
  if (!isCompatibleVersionWithMinimal(parsedData.openCTI_version, MINIMAL_SYNCHRONIZER_COMPATIBLE_VERSION)) {
    throw FunctionalError(
      `Invalid version of the platform. Please upgrade your OpenCTI. Minimal version required: ${MINIMAL_SYNCHRONIZER_COMPATIBLE_VERSION}`,
      { reason: parsedData.openCTI_version },
    );
  }

  return parsedData.configuration;
};

export const synchronizerAddAutoUser = async (context: AuthContext, user: AuthUser, synchronizerId: string, input: SynchronizerAddAutoUserInput) => {
  const onTheFlyCreatedUser = await createOnTheFlyUser(context, user,
    { userName: input.user_name, confidenceLevel: input.confidence_level, serviceAccount: true });

  return syncEditField(context, user, synchronizerId, [{ key: 'user_id', value: [onTheFlyCreatedUser.id] }]);
};

export const syncEditField = async (context: AuthContext, user: AuthUser, syncId: string, input: EditInput[]) => {
  const uriInput = input.find((i) => i.key === 'uri');
  if (uriInput && uriInput.value[0]) {
    verifyIngestionUri(uriInput.value[0]);
  }

  const tokenInput = input.find((i) => i.key === 'token');
  if (tokenInput && tokenInput.value[0]) {
    tokenInput.value[0] = await encryptSynchronizerCredential(tokenInput.value[0]);
  }
  const { element } = await updateAttribute<StoreEntity>(context, user, syncId, ENTITY_TYPE_SYNC, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for synchronizer \`${element.name}\``,
    context_data: { id: syncId, entity_type: ENTITY_TYPE_SYNC, input },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_SYNC].EDIT_TOPIC, element, user);
};
export const syncDelete = async (context: AuthContext, user: AuthUser, syncId: string) => {
  const deleted = await deleteElementById<StoreEntity>(context, user, syncId, ENTITY_TYPE_SYNC);
  await unregisterConnector(syncId);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes synchronizer \`${deleted.name}\``,
    context_data: { id: syncId, entity_type: ENTITY_TYPE_SYNC, input: deleted },
  });
  return syncId;
};
export const synchronizerExport = async (synchronizer: BasicStoreEntitySynchronizer) => {
  const { name, uri, stream_id, current_state_date, listen_deletion, ssl_verify, no_dependencies, synchronized } = synchronizer;
  return JSON.stringify({
    openCTI_version: PLATFORM_VERSION,
    type: 'openCTI_stream',
    configuration: {
      name,
      uri,
      stream_id,
      current_state_date,
      listen_deletion,
      ssl_verify,
      no_dependencies,
      synchronized,
    },
  });
};
export const syncCleanContext = async (context: AuthContext, user: AuthUser, syncId: string) => {
  await delEditContext(user, syncId);
  return storeLoadById(context, user, syncId, ENTITY_TYPE_SYNC)
    .then((syncToReturn) => notify(BUS_TOPICS[ENTITY_TYPE_SYNC].EDIT_TOPIC, syncToReturn, user));
};
export const syncEditContext = async (context: AuthContext, user: AuthUser, syncId: string, input: EditContext) => {
  await setEditContext(user, syncId, input);
  return storeLoadById(context, user, syncId, ENTITY_TYPE_SYNC)
    .then((syncToReturn) => notify(BUS_TOPICS[ENTITY_TYPE_SYNC].EDIT_TOPIC, syncToReturn, user));
};
// endregion

// region testing
export const deleteQueues = async (context: AuthContext, user: AuthUser) => {
  const platformConnectors = await connectors(context, user);
  for (let index = 0; index < platformConnectors.length; index += 1) {
    const conn = platformConnectors[index];
    await unregisterConnector(conn.id);
  }
  try {
    await unregisterExchanges();
  } catch (_e) { /* nothing */ }
};
// endregion

export const askJobImport = async (
  context: AuthContext,
  user: AuthUser,
  args: {
    fileName: string;
    connectorId?: string;
    configuration?: string;
    bypassEntityId?: string;
    bypassValidation?: boolean;
    validationMode?: ValidationMode;
    forceValidation?: boolean;
  },
) => {
  const {
    fileName,
    connectorId = null,
    configuration = null,
    bypassEntityId = null,
    bypassValidation = false,
    validationMode = defaultValidationMode,
    forceValidation = false,
  } = args;
  if (!fileName) {
    logApp.error('[JOBS] ask import, fileName is required');
    return null;
  }
  logApp.info(`[JOBS] ask import for file ${fileName} by ${user.user_email}`);
  const file = await loadFile(context, user, fileName);
  if (!file) {
    logApp.error('[JOBS] ask import, file not found:', fileName);
    return null;
  }
  logApp.info('[JOBS] ask import, file found:', file);
  const entityId = bypassEntityId || file?.metaData.entity_id || null;
  const opts: {
    manual: boolean;
    connectorId?: string | null;
    configuration?: string | null;
    bypassValidation: boolean;
    validationMode: ValidationMode;
    forceValidation: boolean;
  } = {
    manual: true,
    connectorId,
    configuration,
    bypassValidation,
    validationMode,
    forceValidation,
  };
  const entity = await internalLoadById(context, user, entityId ?? undefined) as BasicStoreCommon;
  // This is a manual request for import, we have to check confidence and throw on error
  if (entity) {
    controlUserConfidenceAgainstElement(user, entity);
  }
  const connectorsForFile = await uploadJobImport(context, user, file, entityId ?? undefined, opts);
  if (file.id.startsWith('import/pending')) {
    if (args.forceValidation && args.validationMode === 'draft') {
      await addWorkbenchDraftConvertionCount();
    } else if (args.bypassValidation) {
      await addWorkbenchValidationCount();
    }
  }
  const entityName = entityId ? extractEntityRepresentativeName(entity) : 'global';
  const entityType = entityId ? entity.entity_type : 'global';
  const baseData: UserImportActionContextData = {
    id: entityId || file.id,
    file_id: file.id,
    file_name: file.name,
    file_mime: file.metaData.mimetype ?? 'application/octet-stream',
    connectors: connectorsForFile.map((c: BasicStoreEntityConnector) => c.name),
    entity_name: entityName,
    entity_type: entityType,
  };
  const contextData = completeContextDataForEntity(baseData, entity);
  await publishUserAction({
    user,
    event_access: 'extended',
    event_type: 'command',
    event_scope: 'import',
    context_data: contextData,
  });
  return file;
};

export const createDraftAndAskJobImport = async (
  context: AuthContext,
  user: AuthUser,
  args: {
    authorized_members?: DraftWorkspaceAddInput['authorized_members'];
    description?: DraftWorkspaceAddInput['description'];
    objectAssignee?: DraftWorkspaceAddInput['objectAssignee'];
    objectParticipant?: DraftWorkspaceAddInput['objectParticipant'];
    createdBy?: DraftWorkspaceAddInput['createdBy'];
    entity_id?: string;
    fileName: string;
    connectorId?: string;
    configuration?: string;
    bypassEntityId?: string;
    bypassValidation?: boolean;
    validationMode?: ValidationMode;
    forceValidation?: boolean;
  },
) => {
  const {
    authorized_members,
    description,
    objectAssignee,
    objectParticipant,
    createdBy,
    fileName,
    connectorId,
    configuration,
    validationMode = defaultValidationMode,
    entity_id,
    bypassEntityId,
  } = args;
  const { id } = await addDraftWorkspace(context, user, {
    name: fileName,
    authorized_members,
    description,
    objectAssignee,
    objectParticipant,
    createdBy,
    entity_id,
  });

  return askJobImport(
    { ...context, draft_context: id },
    user,
    {
      fileName,
      connectorId,
      configuration,
      bypassEntityId,
      validationMode,
      bypassValidation: true,
      forceValidation: false,
    },
  );
};
