import EventSource from 'eventsource';
import {
  createEntity,
  deleteElementById,
  internalDeleteElementById,
  patchAttribute,
  updateAttribute
} from '../database/middleware';
import { completeConnector, connectors, connectorsFor } from '../database/repository';
import { registerConnectorQueues, unregisterConnector, unregisterExchanges } from '../database/rabbitmq';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_SYNC, ENTITY_TYPE_WORK } from '../schema/internalObject';
import { FunctionalError, UnsupportedError } from '../config/errors';
import { now } from '../utils/format';
import { elLoadById } from '../database/engine';
import { INTERNAL_SYNC_QUEUE, isEmptyField, READ_INDEX_HISTORY } from '../database/utils';
import { ABSTRACT_INTERNAL_OBJECT, CONNECTOR_INTERNAL_EXPORT_FILE } from '../schema/general';
import { SYSTEM_USER } from '../utils/access';
import { delEditContext, notify, redisGetWork, setEditContext } from '../database/redis';
import { BUS_TOPICS, logApp } from '../config/conf';
import { deleteWorkForConnector } from './work';
import { listEntities, storeLoadById } from '../database/middleware-loader';

// region connectors
export const loadConnectorById = (context, user, id) => {
  return storeLoadById(context, user, id, ENTITY_TYPE_CONNECTOR).then((connector) => completeConnector(connector));
};
export const connectorForWork = async (context, user, id) => {
  const work = await elLoadById(context, user, id, ENTITY_TYPE_WORK, READ_INDEX_HISTORY);
  if (work) return loadConnectorById(context, user, work.connector_id);
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
export const connectorsForExport = async (context, user, scope, onlyAlive = false) => {
  return connectorsFor(context, user, CONNECTOR_INTERNAL_EXPORT_FILE, scope, onlyAlive);
};
export const pingConnector = async (context, user, id, state) => {
  const creation = now();
  const connector = await storeLoadById(context, user, id, ENTITY_TYPE_CONNECTOR);
  if (!connector) {
    throw FunctionalError('No connector found with the specified ID', { id });
  }
  // Ensure queue are correctly setup
  const scopes = connector.connector_scope ? connector.connector_scope.split(',') : [];
  await registerConnectorQueues(connector.id, connector.name, connector.connector_type, scopes);
  // Patch the updated_at and the state if needed
  if (connector.connector_state_reset === true) {
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
  await patchAttribute(context, user, id, ENTITY_TYPE_CONNECTOR, patch);
  return storeLoadById(context, user, id, ENTITY_TYPE_CONNECTOR).then((data) => completeConnector(data));
};
export const registerConnector = async (context, user, connectorData) => {
  // eslint-disable-next-line camelcase
  const { id, name, type, scope, auto = null, only_contextual = null } = connectorData;
  const connector = await storeLoadById(context, user, id, ENTITY_TYPE_CONNECTOR);
  // Register queues
  await registerConnectorQueues(id, name, type, scope);
  if (connector) {
    // Simple connector update
    const patch = {
      name,
      updated_at: now(),
      connector_user_id: user.id,
      connector_scope: scope && scope.length > 0 ? scope.join(',') : null,
      auto,
      only_contextual,
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
    connector_user_id: user.id,
  };
  const createdConnector = await createEntity(context, user, connectorToCreate, ENTITY_TYPE_CONNECTOR);
  // Notify configuration change for caching system
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC, createdConnector, user);
  // Return the connector
  return completeConnector(createdConnector);
};
export const connectorDelete = async (context, user, connectorId) => {
  await deleteWorkForConnector(context, user, connectorId);
  await unregisterConnector(connectorId);
  const { element } = await internalDeleteElementById(context, user, connectorId);
  // Notify configuration change for caching system
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, element, user);
  return element.internal_id;
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
  const recover = sync.recover ?? sync.created_at;
  let streamUri = `${httpBase(uri)}stream/${stream}?from=${from}&listen-delete=${del}&no-dependencies=${dep}`;
  if (recover) {
    streamUri += `&recover=${recover}`;
  }
  return streamUri;
};
export const testSync = async (context, user, sync) => {
  const eventSourceUri = createSyncHttpUri(sync, true);
  const { token, ssl_verify: ssl = false } = sync;
  return new Promise((resolve, reject) => {
    try {
      const eventSource = new EventSource(eventSourceUri, {
        rejectUnauthorized: ssl,
        headers: !isEmptyField(token) ? { authorization: `Bearer ${token}` } : undefined,
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
export const registerSync = async (context, user, syncData) => {
  const data = { ...syncData, running: false };
  await testSync(context, user, data);
  return createEntity(context, user, data, ENTITY_TYPE_SYNC);
};
export const syncEditField = async (context, user, syncId, input) => {
  const { element } = await updateAttribute(context, user, syncId, ENTITY_TYPE_SYNC, input);
  return notify(BUS_TOPICS[ENTITY_TYPE_SYNC].EDIT_TOPIC, element, user);
};
export const syncDelete = async (context, user, syncId) => {
  await deleteElementById(context, user, syncId, ENTITY_TYPE_SYNC);
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
    const connector = platformConnectors[index];
    await unregisterConnector(connector.id);
  }
  try { await unregisterExchanges(); } catch (e) { /* nothing */ }
};
// endregion
