import { v5 as uuidv5 } from 'uuid';
import { createEntity, deleteElementById, internalDeleteElementById, patchAttribute, updateAttribute } from '../database/middleware';
import { type GetHttpClient, getHttpClient } from '../utils/http-client';
import { completeConnector, connector, connectors, connectorsFor } from '../database/repository';
import { getConnectorQueueDetails, purgeConnectorQueues, registerConnectorQueues, unregisterConnector, unregisterExchanges } from '../database/rabbitmq';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_SYNC, ENTITY_TYPE_WORK } from '../schema/internalObject';
import { FunctionalError, ValidationError } from '../config/errors';
import { validateFilterGroupForStixMatch } from '../utils/filtering/filtering-stix/stix-filtering';
import { isFilterGroupNotEmpty } from '../utils/filtering/filtering-utils';
import { now } from '../utils/format';
import { elLoadById } from '../database/engine';
import { isEmptyField, READ_INDEX_HISTORY } from '../database/utils';
import { ABSTRACT_INTERNAL_OBJECT, CONNECTOR_INTERNAL_EXPORT_FILE, OPENCTI_NAMESPACE } from '../schema/general';
import { isUserHasCapability, SETTINGS_SET_ACCESSES, SYSTEM_USER } from '../utils/access';
import { delEditContext, notify, redisGetWork, setEditContext } from '../database/redis';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { publishUserAction } from '../listener/UserActionListener';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreEntityConnector, ConnectorInfo } from '../types/connector';
import {
  ConnectorListenProtocol,
  ConnectorType,
  type EditContext,
  type EditInput,
  type MutationSynchronizerTestArgs,
  type RegisterConnectorInput,
  type SynchronizerAddInput,
  type SynchronizerFetchInput
} from '../generated/graphql';
import { BUS_TOPICS } from '../config/conf';
import { deleteWorkForConnector } from './work';
import { testSync as testSyncUtils } from './connector-utils';
import { findById } from './user';

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
  const patch = { connector_state: '', connector_state_reset: true };
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
  connector_user_id?: string | null
}
export const registerConnector = async (context: AuthContext, user:AuthUser, connectorData:RegisterConnectorInput, opts: RegisterOptions = {}) => {
  // eslint-disable-next-line camelcase
  const { id, name, type, scope, auto = null, only_contextual = null, playbook_compatible = false, listen_callback_uri } = connectorData;
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
      only_contextual,
      playbook_compatible,
      listen_callback_uri,
      connector_user_id: opts.connector_user_id ?? user.id,
      built_in: opts.built_in ?? false
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
    only_contextual,
    playbook_compatible,
    listen_callback_uri,
    connector_user_id: opts.connector_user_id ?? user.id,
    built_in: opts.built_in ?? false,
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
  const { element } = await internalDeleteElementById(context, user, connectorId);
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

export const connectorTriggerUpdate = async (context: AuthContext, user: AuthUser, connectorId: string, input: EditInput[]) => {
  const conn = await storeLoadById(context, user, connectorId, ENTITY_TYPE_CONNECTOR) as unknown as BasicStoreEntityConnector;
  if (!conn) {
    throw FunctionalError('Cant find element to update', { id: connectorId, type: ENTITY_TYPE_CONNECTOR });
  }
  if (!['INTERNAL_ENRICHMENT', 'INTERNAL_IMPORT_FILE'].includes(conn.connector_type)) {
    throw FunctionalError('Update is only possible on internal enrichment or import file connectors types');
  }
  const supportedInputKeys = ['connector_trigger_filters'];
  if (input.some((item) => !supportedInputKeys.includes(item.key))) {
    throw FunctionalError(`Update is only possible on these input keys: ${supportedInputKeys.join(', ')}`);
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
// endregion

// region syncs
interface ConnectorIngestionInput {
  id: string,
  type: 'RSS' | 'CSV' | 'TAXII' | 'TAXII-PUSH',
  name: string,
  connector_user_id?: string | null,
  is_running: boolean
}
export const connectorIdFromIngestId = (id: string) => uuidv5(id, OPENCTI_NAMESPACE);
export const registerConnectorForIngestion = async (context: AuthContext, input: ConnectorIngestionInput) => {
  // Create the representing connector
  await registerConnector(context, SYSTEM_USER, {
    id: connectorIdFromIngestId(input.id),
    name: `[FEED - ${input.type}] ${input.name}`,
    type: ConnectorType.ExternalImport,
    auto: true,
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
export const findSyncById = (context: AuthContext, user: AuthUser, syncId: string) => {
  return storeLoadById(context, user, syncId, ENTITY_TYPE_SYNC);
};
export const findAllSync = async (context: AuthContext, user: AuthUser, opts = {}) => {
  return listEntities(context, SYSTEM_USER, [ENTITY_TYPE_SYNC], opts);
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
  try { await unregisterExchanges(); } catch (e) { /* nothing */ }
};
// endregion

export const queueDetails = async (connectorId: string) => {
  return getConnectorQueueDetails(connectorId);
};

export const connectorUser = async (context: AuthContext, user: AuthUser, userId: string) => {
  if (isUserHasCapability(user, SETTINGS_SET_ACCESSES)) {
    return findById(context, user, userId);
  }
  return null;
};
