import EventSource from 'eventsource';
import { createEntity, deleteElementById, internalDeleteElementById, patchAttribute, updateAttribute } from '../database/middleware';
import { getHttpClient } from '../utils/http-client';
import { completeConnector, connector, connectors, connectorsFor } from '../database/repository';
import { getConnectorQueueDetails, purgeConnectorQueues, registerConnectorQueues, unregisterConnector, unregisterExchanges } from '../database/rabbitmq';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_SYNC, ENTITY_TYPE_WORK } from '../schema/internalObject';
import { FunctionalError, UnsupportedError, ValidationError } from '../config/errors';
import { validateFilterGroupForStixMatch } from '../utils/filtering/filtering-stix/stix-filtering';
import { isFilterGroupNotEmpty } from '../utils/filtering/filtering-utils';
import { now } from '../utils/format';
import { elLoadById } from '../database/engine';
import { INTERNAL_SYNC_QUEUE, isEmptyField, READ_INDEX_HISTORY } from '../database/utils';
import { ABSTRACT_INTERNAL_OBJECT, CONNECTOR_INTERNAL_EXPORT_FILE } from '../schema/general';
import { SYSTEM_USER } from '../utils/access';
import { delEditContext, notify, redisGetWork, setEditContext } from '../database/redis';
import { BUS_TOPICS, getPlatformHttpProxyAgent, logApp } from '../config/conf';
import { deleteWorkForConnector } from './work';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { publishUserAction } from '../listener/UserActionListener';

// region connectors
export const connectorForWork = async (context, user, id) => {
  const work = await elLoadById(context, user, id, { type: ENTITY_TYPE_WORK, indices: READ_INDEX_HISTORY });
  if (work) return connector(context, user, work.connector_id);
  return null;
};

export const computeWorkStatus = async (work) => {
  if (work.status === 'complete') {
    return { import_processed_number: work.completed_number, import_expected_number: work.import_expected_number };
  }
  // If running, information in redis.
  const redisData = await redisGetWork(work.id);
  // If data in redis not exist, just send default values
  return redisData ?? { import_processed_number: null, import_expected_number: null };
};
export const connectorsForExport = async (context, user, scope = null, onlyAlive = false) => {
  return connectorsFor(context, user, CONNECTOR_INTERNAL_EXPORT_FILE, scope, onlyAlive);
};
export const pingConnector = async (context, user, id, state) => {
  const creation = now();
  const conn = await storeLoadById(context, user, id, ENTITY_TYPE_CONNECTOR);
  if (!conn) {
    throw FunctionalError('No connector found with the specified ID', { id });
  }
  // Ensure queue are correctly setup
  const scopes = conn.connector_scope ? conn.connector_scope.split(',') : [];
  await registerConnectorQueues(conn.id, conn.name, conn.connector_type, scopes);
  // Patch the updated_at and the state if needed
  if (conn.connector_state_reset === true) {
    const statePatch = { connector_state_reset: false };
    await patchAttribute(context, user, id, ENTITY_TYPE_CONNECTOR, statePatch);
  } else {
    const updatePatch = { updated_at: creation, connector_state: state };
    await patchAttribute(context, user, id, ENTITY_TYPE_CONNECTOR, updatePatch);
  }
  return storeLoadById(context, user, id, 'Connector').then((data) => completeConnector(data));
};
export const resetStateConnector = async (context, user, id) => {
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
export const registerConnector = async (context, user, connectorData) => {
  // eslint-disable-next-line camelcase
  const { id, name, type, scope, auto = null, only_contextual = null, playbook_compatible = false } = connectorData;
  const conn = await storeLoadById(context, user, id, ENTITY_TYPE_CONNECTOR);
  // Register queues
  await registerConnectorQueues(id, name, type, scope);
  if (conn) {
    // Simple connector update
    const patch = {
      name,
      updated_at: now(),
      connector_user_id: user.id,
      connector_scope: scope && scope.length > 0 ? scope.join(',') : null,
      connector_type: type,
      auto,
      only_contextual,
      playbook_compatible
    };
    const { element } = await patchAttribute(context, user, id, ENTITY_TYPE_CONNECTOR, patch);
    // Notify configuration change for caching system
    await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
    return storeLoadById(context, user, id, ENTITY_TYPE_CONNECTOR).then((data) => completeConnector(data));
  }
  // Need to create the connector
  const connectorToCreate = {
    internal_id: id,
    name,
    connector_type: type,
    connector_scope: scope && scope.length > 0 ? scope.join(',') : null,
    auto,
    only_contextual,
    playbook_compatible,
    connector_user_id: user.id,
  };
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
export const connectorDelete = async (context, user, connectorId) => {
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

export const connectorTriggerUpdate = async (context, user, connectorId, input) => {
  const conn = await storeLoadById(context, user, connectorId, ENTITY_TYPE_CONNECTOR);
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
  const filtersItem = input.find((item) => item.key === 'connector_trigger_filters');
  if (filtersItem?.value) {
    const jsonFilters = JSON.parse(filtersItem.value);
    if (isFilterGroupNotEmpty(jsonFilters)) {
      // our stix matching is currently limited, we need to validate the input filters
      validateFilterGroupForStixMatch(jsonFilters);
    } else {
      filtersItem.value = ''; // empty filter
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
export const patchSync = async (context, user, id, patch) => {
  const patched = await patchAttribute(context, user, id, ENTITY_TYPE_SYNC, patch);
  return patched.element;
};
export const findSyncById = (context, user, syncId) => {
  return storeLoadById(context, user, syncId, ENTITY_TYPE_SYNC);
};
export const findAllSync = async (context, user, opts = {}) => {
  return listEntities(context, SYSTEM_USER, [ENTITY_TYPE_SYNC], opts);
};
export const httpBase = (baseUri) => (baseUri.endsWith('/') ? baseUri : `${baseUri}/`);
export const createSyncHttpUri = (sync, state, testMode) => {
  const { uri, stream_id: stream, no_dependencies: dep, listen_deletion: del } = sync;
  if (testMode) {
    logApp.debug(`[OPENCTI] Testing sync url with ${httpBase(uri)}stream/${stream}`);
    return `${httpBase(uri)}stream/${stream}`;
  }
  const from = isEmptyField(state) ? '0-0' : state;
  const recover = sync.recover ?? now();
  let streamUri = `${httpBase(uri)}stream/${stream}?from=${from}&listen-delete=${del}&no-dependencies=${dep}`;
  if (recover) {
    streamUri += `&recover=${recover}`;
  }
  return streamUri;
};
export const testSync = async (context, user, sync) => {
  const eventSourceUri = createSyncHttpUri(sync, now(), true);
  const { token, ssl_verify: ssl = false } = sync;
  return new Promise((resolve, reject) => {
    try {
      const eventSource = new EventSource(eventSourceUri, {
        rejectUnauthorized: ssl,
        headers: !isEmptyField(token) ? { authorization: `Bearer ${token}` } : undefined,
        agent: getPlatformHttpProxyAgent(eventSourceUri)
      });
      eventSource.on('connected', (d) => {
        const { connectionId } = JSON.parse(d.data);
        if (connectionId) {
          eventSource.close();
          resolve('Connection success');
        } else {
          eventSource.close();
          reject(UnsupportedError('Server cant generate connection id'));
        }
      });
      eventSource.on('error', (e) => {
        eventSource.close();
        reject(UnsupportedError(`Cant connect to remote opencti, ${e.message}`));
      });
    } catch (e) {
      reject(UnsupportedError('Cant connect to remote opencti, check your configuration'));
    }
  });
};
export const fetchRemoteStreams = async (context, user, { uri, token, ssl_verify }) => {
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
    const httpClientOptions = { headers, rejectUnauthorized: ssl_verify ?? false, responseType: 'json' };
    const httpClient = getHttpClient(httpClientOptions);
    const remoteUri = `${uri.endsWith('/') ? uri.slice(0, -1) : uri}/graphql`;
    const { data } = await httpClient.post(remoteUri, { query });
    return data.data.streamCollections.edges.map((e) => e.node);
  } catch (e) {
    throw ValidationError('uri', { message: 'Error getting the streams from remote OpenCTI', cause: e });
  }
};
export const registerSync = async (context, user, syncData) => {
  const data = { ...syncData, running: false };
  await testSync(context, user, data);
  const { element, isCreation } = await createEntity(context, user, data, ENTITY_TYPE_SYNC, { complete: true });
  if (isCreation) {
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
export const syncEditField = async (context, user, syncId, input) => {
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
export const syncDelete = async (context, user, syncId) => {
  const deleted = await deleteElementById(context, user, syncId, ENTITY_TYPE_SYNC);
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
export const syncCleanContext = async (context, user, syncId) => {
  await delEditContext(user, syncId);
  return storeLoadById(context, user, syncId, ENTITY_TYPE_SYNC)
    .then((syncToReturn) => notify(BUS_TOPICS[ENTITY_TYPE_SYNC].EDIT_TOPIC, syncToReturn, user));
};
export const syncEditContext = async (context, user, syncId, input) => {
  await setEditContext(user, syncId, input);
  return storeLoadById(context, user, syncId, ENTITY_TYPE_SYNC)
    .then((syncToReturn) => notify(BUS_TOPICS[ENTITY_TYPE_SYNC].EDIT_TOPIC, syncToReturn, user));
};
// endregion

// region testing
export const deleteQueues = async (context, user) => {
  try { await unregisterConnector(INTERNAL_SYNC_QUEUE); } catch (e) { /* nothing */ }
  const platformConnectors = await connectors(context, user);
  for (let index = 0; index < platformConnectors.length; index += 1) {
    const conn = platformConnectors[index];
    await unregisterConnector(conn.id);
  }
  try { await unregisterExchanges(); } catch (e) { /* nothing */ }
};
// endregion

export const queueDetails = async (connectorId) => {
  return await getConnectorQueueDetails(connectorId);
};
