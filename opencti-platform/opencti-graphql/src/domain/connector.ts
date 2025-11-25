import { v5 as uuidv5 } from 'uuid';
import { createEntity, deleteElementById, internalDeleteElementById, patchAttribute, updateAttribute } from '../database/middleware';
import { type GetHttpClient, getHttpClient } from '../utils/http-client';
import { completeConnector, connector, connectors, connectorsFor } from '../database/repository';
import { getConnectorQueueDetails, purgeConnectorQueues, registerConnectorQueues, unregisterConnector, unregisterExchanges } from '../database/rabbitmq';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_CONNECTOR_MANAGER, ENTITY_TYPE_SYNC, ENTITY_TYPE_USER, ENTITY_TYPE_WORK } from '../schema/internalObject';
import { FunctionalError, UnsupportedError, ValidationError } from '../config/errors';
import { validateFilterGroupForStixMatch } from '../utils/filtering/filtering-stix/stix-filtering';
import { isFilterGroupNotEmpty } from '../utils/filtering/filtering-utils';
import { now } from '../utils/format';
import { elLoadById } from '../database/engine';
import { isEmptyField, READ_INDEX_HISTORY } from '../database/utils';
import { ABSTRACT_INTERNAL_OBJECT, CONNECTOR_INTERNAL_EXPORT_FILE, OPENCTI_NAMESPACE } from '../schema/general';
import { isUserHasCapability, SETTINGS_SET_ACCESSES, SYSTEM_USER } from '../utils/access';
import {
  type ConnectorHealthMetrics,
  delEditContext,
  notify,
  redisGetConnectorHealthMetrics,
  redisGetWork,
  redisSetConnectorHealthMetrics,
  redisSetConnectorLogs,
  setEditContext
} from '../database/redis';
import { fullEntitiesList, internalLoadById, pageEntitiesConnection, storeLoadById } from '../database/middleware-loader';
import { completeContextDataForEntity, publishUserAction, type UserImportActionContextData } from '../listener/UserActionListener';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreEntityConnector, BasicStoreEntityConnectorManager, BasicStoreEntitySynchronizer, ConnectorInfo } from '../types/connector';
import {
  type AddManagedConnectorInput,
  ConnectorPriorityGroup,
  ConnectorType,
  type CurrentConnectorStatusInput,
  type DraftWorkspaceAddInput,
  type EditContext,
  type EditInput,
  type EditManagedConnectorInput,
  type HealthConnectorStatusInput,
  IngestionAuthType,
  type LogsConnectorStatusInput,
  type MutationSynchronizerTestArgs,
  type RegisterConnectorInput,
  type RegisterConnectorsManagerInput,
  type RequestConnectorStatusInput,
  type SynchronizerAddInput,
  type SynchronizerFetchInput,
  type UpdateConnectorManagerStatusInput,
  ValidationMode
} from '../generated/graphql';
import { BUS_TOPICS, logApp } from '../config/conf';
import { deleteWorkForConnector } from './work';
import { testSync as testSyncUtils } from './connector-utils';
import { defaultValidationMode, loadFile, uploadJobImport } from '../database/file-storage';
import { controlUserConfidenceAgainstElement } from '../utils/confidence-level';
import { extractEntityRepresentativeName } from '../database/entity-representative';
import type { BasicStoreCommon } from '../types/store';
import { addConnectorDeployedCount, addWorkbenchDraftConvertionCount, addWorkbenchValidationCount } from '../manager/telemetryManager';
import { computeConnectorTargetContract, getSupportedContractsByImage } from '../modules/catalog/catalog-domain';
import { getEntitiesMapFromCache } from '../database/cache';
import { removeAuthenticationCredentials } from '../modules/ingestion/ingestion-common';
import { createOnTheFlyUser } from '../modules/user/user-domain';
import { addDraftWorkspace } from '../modules/draftWorkspace/draftWorkspace-domain';

// Sanitize name for K8s/Docker
const sanitizeContainerName = (label: string): string => {
  const withHyphens = label.replace(/([a-z])([A-Z])/g, '$1-$2');
  let sanitized = withHyphens
    .replace(/[^a-zA-Z0-9]+/g, '-')
    .toLowerCase()
    .replace(/^-+/, '')
    .replace(/-+$/, '');

  if (sanitized.length > 63) {
    sanitized = sanitized.substring(0, 63);
    sanitized = sanitized.replace(/-+$/, '');
  }

  if (sanitized.length === 0) {
    return `a-${Math.floor(Math.random() * 10)}`;
  }

  return sanitized;
};

// region connectors
export const connectorForWork = async (context: AuthContext, user: AuthUser, id: string) => {
  const work = await elLoadById(context, user, id, { type: ENTITY_TYPE_WORK, indices: READ_INDEX_HISTORY }) as unknown as Work;
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
export const connectorsForExport = async (context: AuthContext, user: AuthUser, scope = null, onlyAlive = false) => {
  return connectorsFor(context, user, CONNECTOR_INTERNAL_EXPORT_FILE, scope, onlyAlive);
};

export const updateConnectorWithConnectorInfo = async (
  context: AuthContext,
  user: AuthUser,
  connectorEntity: BasicStoreEntityConnector,
  state: string,
  connectorInfo: ConnectorInfo
) => {
  // Patch the updated_at and the state if needed
  let connectorPatch;

  if (connectorEntity.connector_state_reset) {
    connectorPatch = { connector_state_reset: false };
  } else {
    connectorPatch = { updated_at: now(), connector_state: state };
  }

  if (connectorInfo) {
    const connectorInfoData: ConnectorInfo = {
      run_and_terminate: connectorInfo.run_and_terminate,
      buffering: connectorInfo.buffering,
      queue_threshold: connectorInfo.queue_threshold,
      queue_messages_size: connectorInfo.queue_messages_size,
      next_run_datetime: connectorInfo.next_run_datetime,
      last_run_datetime: connectorInfo.last_run_datetime,
    };

    connectorPatch = { ...connectorPatch, connector_info: connectorInfoData };
  }
  await patchAttribute(context, user, connectorEntity.id, ENTITY_TYPE_CONNECTOR, connectorPatch);
};

export const pingConnector = async (context: AuthContext, user: AuthUser, id: string, state: string, connectorInfo: ConnectorInfo) => {
  const connectorEntity = await storeLoadById(context, user, id, ENTITY_TYPE_CONNECTOR) as unknown as BasicStoreEntityConnector;
  if (!connectorEntity) {
    throw FunctionalError('No connector found with the specified ID', { id });
  }
  // Ensure queue are correctly setup
  const scopes = connectorEntity.connector_scope ? connectorEntity.connector_scope.split(',') : [];
  await registerConnectorQueues(connectorEntity.id, connectorEntity.name, connectorEntity.connector_type, scopes);

  await updateConnectorWithConnectorInfo(context, user, connectorEntity, state, connectorInfo);
  return storeLoadById(context, user, id, 'Connector').then((data) => completeConnector(data));
};
export const resetStateConnector = async (context: AuthContext, user: AuthUser, id: string) => {
  const patch = { connector_state: '', connector_state_reset: true, connector_state_timestamp: now() };
  const { element } = await patchAttribute(context, user, id, ENTITY_TYPE_CONNECTOR, patch);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `resets \`state\` and purge queues for ${ENTITY_TYPE_CONNECTOR} \`${element.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_CONNECTOR, input: patch }
  });
  await purgeConnectorQueues(element);
  return storeLoadById(context, user, id, ENTITY_TYPE_CONNECTOR).then((data) => completeConnector(data));
};
interface RegisterOptions {
  built_in?: boolean
  active?: boolean
  connector_user_id?: string | null,
  connector_priority_group?: ConnectorPriorityGroup,
}

export const registerConnectorsManager = async (context: AuthContext, user: AuthUser, input: RegisterConnectorsManagerInput) => {
  const manager = await storeLoadById(context, user, input.id, ENTITY_TYPE_CONNECTOR_MANAGER);
  const patch = { name: input.name, last_sync_execution: now(), public_key: input.public_key };
  if (manager) {
    const { element } = await patchAttribute(context, user, input.id, ENTITY_TYPE_CONNECTOR_MANAGER, patch);
    return element;
  }
  const managerToCreate = { internal_id: input.id, ...patch };
  return createEntity(context, user, managerToCreate, ENTITY_TYPE_CONNECTOR_MANAGER);
};

export const updateConnectorManagerStatus = async (context: AuthContext, user:AuthUser, input: UpdateConnectorManagerStatusInput) => {
  const patch: any = { last_sync_execution: now() };
  const { element } = await patchAttribute(context, user, input.id, ENTITY_TYPE_CONNECTOR_MANAGER, patch);
  return element;
};

export const managedConnectorEdit = async (
  context: AuthContext,
  user:AuthUser,
  input: EditManagedConnectorInput
) => {
  const conn: any = await storeLoadById(context, user, input.id, ENTITY_TYPE_CONNECTOR);
  if (isEmptyField(conn)) {
    throw UnsupportedError('Connector not found', { id: input.id });
  }
  const contractsMap = getSupportedContractsByImage();
  const targetContract: any = contractsMap.get(conn.manager_contract_image);
  if (isEmptyField(targetContract)) {
    throw UnsupportedError('Target contract not found');
  }
  const connectorManagers = await fullEntitiesList<BasicStoreEntityConnectorManager>(context, user, [ENTITY_TYPE_CONNECTOR_MANAGER]);
  if (connectorManagers?.length < 1) {
    throw FunctionalError('There is no connector manager configured');
  }
  const currentManager = connectorManagers[0];
  const contractConfigurations = computeConnectorTargetContract(
    input.manager_contract_configuration,
    targetContract,
    currentManager.public_key,
    conn.manager_contract_configuration
  );
  const patch: any = {
    name: input.name,
    connector_type: targetContract.container_type,
    connector_user_id: input.connector_user_id,
    manager_contract_configuration: contractConfigurations,
  };
  const { element } = await patchAttribute(context, user, input.id, ENTITY_TYPE_CONNECTOR, patch);
  return element;
};

export const managedConnectorAdd = async (
  context: AuthContext,
  user:AuthUser,
  input: AddManagedConnectorInput
) => {
  // Get contract
  const contractsMap = getSupportedContractsByImage();
  const targetContract: any = contractsMap.get(input.manager_contract_image);
  if (isEmptyField(targetContract)) {
    throw UnsupportedError('Target contract not found');
  }
  if (!targetContract.manager_supported) {
    throw FunctionalError('You have not chosen a connector supported by the manager');
  }
  const connectorManagers = await fullEntitiesList<BasicStoreEntityConnectorManager>(context, user, [ENTITY_TYPE_CONNECTOR_MANAGER]);
  if (connectorManagers?.length < 1) {
    throw FunctionalError('There is no connector manager configured');
  }
  const currentManager = connectorManagers[0];
  const contractConfigurations = computeConnectorTargetContract(input.manager_contract_configuration, targetContract, currentManager.public_key);
  // Get user
  if (input.user_id.length < 2) {
    throw FunctionalError('You have not chosen a user responsible for data creation', {});
  }
  let finalUserId = input.user_id;
  if (input.automatic_user) {
    const onTheFlyCreatedUser = await createOnTheFlyUser(
      context,
      user,
      { userName: input.user_id, serviceAccount: true, confidenceLevel: input.confidence_level ? parseInt(input.confidence_level, 10) : null }
    );
    finalUserId = onTheFlyCreatedUser.id;
  }
  const connectorUser = await storeLoadById(context, user, finalUserId, ENTITY_TYPE_USER);
  if (isEmptyField(connectorUser)) {
    throw UnsupportedError('Connector user not found', { id: finalUserId });
  }
  // Sanitize name
  const sanitizedName = sanitizeContainerName(input.name);
  if (!sanitizedName || sanitizedName.length < 2) {
    throw FunctionalError('Invalid connector name');
  }
  // Check for name collision
  const existingConnectors = await connectors(context, user);
  const nameCollision = existingConnectors.find((c) => c.name === sanitizedName);
  if (nameCollision) {
    logApp.info(`[CONNECTOR] Name collision detected: connector with name '${sanitizedName}' already exists`);
    throw FunctionalError('CONNECTOR_NAME_ALREADY_EXISTS');
  }

  // Create connector
  const connectorToCreate: any = {
    title: input.name,
    name: sanitizedName,
    connector_type: targetContract.container_type,
    catalog_id: input.catalog_id,
    connector_user_id: connectorUser.id,
    manager_contract_image: input.manager_contract_image,
    manager_contract_configuration: contractConfigurations,
    manager_requested_status: 'stopped',
    connector_state_timestamp: now(),
    built_in: false
  };

  const createdConnector: any = await createEntity(context, user, connectorToCreate, ENTITY_TYPE_CONNECTOR);
  // Increment telemetry for connector deployed via composer
  await addConnectorDeployedCount();
  // Publish
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates ${ENTITY_TYPE_CONNECTOR} \`${createdConnector.name}\``,
    context_data: { id: createdConnector.internal_id, entity_type: ENTITY_TYPE_CONNECTOR, input }
  });
  // Notify configuration change for caching system
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC, createdConnector, user);
  // Return the connector

  return completeConnector(createdConnector);
};

export const registerConnector = async (
  context: AuthContext,
  user:AuthUser,
  connectorData: RegisterConnectorInput,
  opts: RegisterOptions = {}
) => {
  // eslint-disable-next-line camelcase
  const { id, name, type, scope, only_contextual = null, playbook_compatible = false, listen_callback_uri } = connectorData;
  const { auto = null, auto_update = null, enrichment_resolution = null } = connectorData;
  const conn = await storeLoadById(context, user, id, ENTITY_TYPE_CONNECTOR);
  // Register queues
  await registerConnectorQueues(id, name, type, scope);
  if (conn) {
    // Simple connector update
    const patch: any = {
      name,
      updated_at: now(),
      connector_type: type,
      connector_scope: scope && scope.length > 0 ? scope.join(',') : null,
      auto,
      auto_update,
      enrichment_resolution,
      only_contextual,
      playbook_compatible,
      listen_callback_uri,
      connector_user_id: opts.connector_user_id ?? user.id,
      built_in: opts.built_in ?? false,
    };
    if (opts.active !== undefined) {
      patch.active = opts.active;
    }
    const { element } = await patchAttribute(context, user, id, ENTITY_TYPE_CONNECTOR, patch);
    // Notify configuration change for caching system
    await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
    return storeLoadById(context, user, id, ENTITY_TYPE_CONNECTOR).then((data) => completeConnector(data));
  }
  // Need to create the connector
  const connectorToCreate: any = {
    internal_id: id,
    name,
    connector_type: type,
    connector_scope: scope && scope.length > 0 ? scope.join(',') : null,
    auto,
    auto_update,
    enrichment_resolution,
    only_contextual,
    playbook_compatible,
    listen_callback_uri,
    connector_user_id: opts.connector_user_id ?? user.id,
    connector_state_timestamp: now(),
    built_in: opts.built_in ?? false,
    connector_priority_group: opts.connector_priority_group ?? ConnectorPriorityGroup.Default,
  };
  if (opts.active !== undefined) {
    connectorToCreate.active = opts.active;
  }
  const createdConnector = await createEntity(context, user, connectorToCreate, ENTITY_TYPE_CONNECTOR);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates ${ENTITY_TYPE_CONNECTOR} \`${createdConnector.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_CONNECTOR, input: connectorData }
  });
  // Notify configuration change for caching system
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC, createdConnector, user);
  // Return the connector
  return completeConnector(createdConnector);
};

export const connectorDelete = async (context: AuthContext, user:AuthUser, connectorId: string) => {
  await deleteWorkForConnector(context, user, connectorId);
  await unregisterConnector(connectorId);
  const { element } = await internalDeleteElementById(context, user, connectorId, ENTITY_TYPE_CONNECTOR);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes ${ENTITY_TYPE_CONNECTOR} \`${element.name}\``,
    context_data: { id: connectorId, entity_type: ENTITY_TYPE_CONNECTOR, input: element }
  });
  // Notify configuration change for caching system
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, element, user);
  return element.internal_id;
};

const updateConnector = async (context: AuthContext, user: AuthUser, connectorId: string, input: EditInput[]) => {
  const { element } = await updateAttribute(context, user, connectorId, ENTITY_TYPE_CONNECTOR, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for connector \`${element.name}\``,
    context_data: { id: connectorId, entity_type: ENTITY_TYPE_CONNECTOR, input }
  });
  // Notify configuration change for caching system
  return notify(BUS_TOPICS[ENTITY_TYPE_CONNECTOR].EDIT_TOPIC, element, user);
};

export const connectorUpdateLogs = async (_context: AuthContext, _user: AuthUser, input: LogsConnectorStatusInput) => {
  await redisSetConnectorLogs(input.id, input.logs);
  return input.id;
};

// Health metrics update function
export const connectorUpdateHealth = async (_context: AuthContext, _user: AuthUser, input: HealthConnectorStatusInput) => {
  const metrics: ConnectorHealthMetrics = {
    restart_count: input.restart_count,
    started_at: input.started_at,
    is_in_reboot_loop: input.is_in_reboot_loop,
    last_update: new Date().toISOString()
  };
  await redisSetConnectorHealthMetrics(input.id, metrics);
  return input.id;
};

// Get health metrics function
export const connectorGetHealth = async (_context: AuthContext, _user: AuthUser, connectorId: string): Promise<ConnectorHealthMetrics | null> => {
  return redisGetConnectorHealthMetrics(connectorId);
};

// Get connector uptime in seconds
export const connectorGetUptime = async (context: AuthContext, user: AuthUser, connectorId: string): Promise<number | null> => {
  const healthMetrics = await connectorGetHealth(context, user, connectorId);
  if (!healthMetrics?.started_at) {
    return null;
  }
  // Parse ISO8601 format from xtm-composer
  const startDate = new Date(healthMetrics.started_at);
  if (Number.isNaN(startDate.getTime())) {
    return null;
  }
  const uptimeInSeconds = Math.floor((Date.now() - startDate.getTime()) / 1000);
  // Return uptime if positive, null otherwise
  return uptimeInSeconds >= 0 ? uptimeInSeconds : null;
};

export const updateConnectorRequestedStatus = async (context: AuthContext, user: AuthUser, input: RequestConnectorStatusInput) => {
  const ediInput: EditInput[] = [{ key: 'manager_requested_status', value: [input.status] }];
  return updateConnector(context, user, input.id, ediInput);
};

export const updateConnectorCurrentStatus = async (context: AuthContext, user: AuthUser, input: CurrentConnectorStatusInput) => {
  const ediInput: EditInput[] = [{ key: 'manager_current_status', value: [input.status] }];
  return updateConnector(context, user, input.id, ediInput);
};

export const connectorTriggerUpdate = async (context: AuthContext, user: AuthUser, connectorId: string, input: EditInput[]) => {
  const conn = await storeLoadById(context, user, connectorId, ENTITY_TYPE_CONNECTOR) as unknown as BasicStoreEntityConnector;
  if (!conn) {
    throw FunctionalError('Cant find element to update', { id: connectorId, type: ENTITY_TYPE_CONNECTOR });
  }
  if (!['INTERNAL_ENRICHMENT', 'INTERNAL_IMPORT_FILE'].includes(conn.connector_type)) {
    throw FunctionalError('Update is only possible on internal enrichment or import file connectors types', { connectorId });
  }
  const supportedInputKeys = ['connector_trigger_filters'];
  if (input.some((item) => !supportedInputKeys.includes(item.key))) {
    throw FunctionalError(`Update is only possible on these input keys: ${supportedInputKeys.join(', ')}`, { connectorId });
  }
  const filtersItem: EditInput | undefined = input.find((item: EditInput) => item.key === 'connector_trigger_filters');
  if (filtersItem && filtersItem.value.length > 0) {
    const jsonFilters = JSON.parse(filtersItem.value[0]);
    if (isFilterGroupNotEmpty(jsonFilters)) {
      // our stix matching is currently limited, we need to validate the input filters
      validateFilterGroupForStixMatch(jsonFilters);
    } else {
      filtersItem.value[0] = ''; // empty filter
    }
  }
  return updateConnector(context, user, connectorId, input);
};
// endregion

// region syncs
interface ConnectorIngestionInput {
  id: string,
  type: 'RSS' | 'CSV' | 'TAXII' | 'TAXII-PUSH' | 'JSON' | 'FORM',
  name: string,
  connector_user_id?: string | null,
  is_running: boolean,
  connector_priority_group?: ConnectorPriorityGroup,
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
    playbook_compatible: false
  }, {
    built_in: true,
    active: input.is_running,
    connector_user_id: input.connector_user_id
  });
};

export const unregisterConnectorForIngestion = async (context: AuthContext, id: string) => {
  const connectorId = connectorIdFromIngestId(id);
  await connectorDelete(context, SYSTEM_USER, connectorId);
};

export const patchSync = async (context: AuthContext, user: AuthUser, id: string, patch: { running: boolean }) => {
  const patched = await patchAttribute(context, user, id, ENTITY_TYPE_SYNC, patch);
  return patched.element;
};
export const findSyncById = async (context: AuthContext, user: AuthUser, syncId: string, removeCredentials = false) => {
  const basicIngestion = await storeLoadById<BasicStoreEntitySynchronizer>(context, user, syncId, ENTITY_TYPE_SYNC);
  if (removeCredentials) {
    basicIngestion.token = removeAuthenticationCredentials(IngestionAuthType.Bearer, basicIngestion.token) ?? null;
  }
  return basicIngestion;
};
export const findSyncPaginated = async (context: AuthContext, user: AuthUser, opts = {}) => {
  return pageEntitiesConnection(context, SYSTEM_USER, [ENTITY_TYPE_SYNC], opts);
};

export const testSync = async (context: AuthContext, user: AuthUser, sync: MutationSynchronizerTestArgs) => {
  return testSyncUtils(context, user, sync);
};

export const fetchRemoteStreams = async (context: AuthContext, user: AuthUser, input:SynchronizerFetchInput) => {
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
    const { token, uri, ssl_verify } = input;
    const headers = !isEmptyField(token) ? { authorization: `Bearer ${token}` } : undefined;
    const httpClientOptions: GetHttpClient = { headers, rejectUnauthorized: ssl_verify ?? false, responseType: 'json' };
    const httpClient = getHttpClient(httpClientOptions);
    const remoteUri = `${uri.endsWith('/') ? uri.slice(0, -1) : uri}/graphql`;
    const { data } = await httpClient.post(remoteUri, { query });
    return data.data.streamCollections.edges.map((e: any) => e.node);
  } catch (e) {
    throw ValidationError('Error getting the streams from remote OpenCTI', 'uri', { cause: e });
  }
};
export const registerSync = async (context: AuthContext, user: AuthUser, syncData: SynchronizerAddInput) => {
  const data = { ...syncData, running: false };
  await testSyncUtils(context, user, data);
  const { element, isCreation } = await createEntity(context, user, data, ENTITY_TYPE_SYNC, { complete: true });
  if (isCreation) {
    const syncId = element.internal_id;
    await registerConnectorQueues(syncId, `Sync ${syncId} queue`, 'internal', 'sync');
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'administration',
      message: `creates synchronizer \`${syncData.name}\``,
      context_data: { id: element.id, entity_type: ENTITY_TYPE_SYNC, input: data }
    });
  }
  return element;
};
export const syncEditField = async (context: AuthContext, user: AuthUser, syncId: string, input: EditInput[]) => {
  const { element } = await updateAttribute(context, user, syncId, ENTITY_TYPE_SYNC, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for synchronizer \`${element.name}\``,
    context_data: { id: syncId, entity_type: ENTITY_TYPE_SYNC, input }
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_SYNC].EDIT_TOPIC, element, user);
};
export const syncDelete = async (context: AuthContext, user: AuthUser, syncId: string) => {
  const deleted = await deleteElementById(context, user, syncId, ENTITY_TYPE_SYNC);
  await unregisterConnector(syncId);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes synchronizer \`${deleted.name}\``,
    context_data: { id: syncId, entity_type: ENTITY_TYPE_SYNC, input: deleted }
  });
  return syncId;
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
  try { await unregisterExchanges(); } catch (_e) { /* nothing */ }
};
// endregion

export const queueDetails = async (connectorId: string) => {
  return getConnectorQueueDetails(connectorId);
};

export const connectorUser = async (context: AuthContext, user: AuthUser, userId: string) => {
  if (isUserHasCapability(user, SETTINGS_SET_ACCESSES)) {
    const platformUsers = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_USER);
    return platformUsers.get(userId);
  }
  return null;
};

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
    forceValidation
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
    entity_type: entityType
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
    fileName,
    connectorId,
    configuration,
    validationMode = defaultValidationMode,
    entity_id,
    bypassEntityId,
  } = args;
  const { id } = await addDraftWorkspace(context, user, { name: fileName, authorized_members, entity_id });

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
    }
  );
};
