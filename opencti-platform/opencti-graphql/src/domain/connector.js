import EventSource from 'eventsource';
import { assoc, filter, includes, map, pipe } from 'ramda';
import {
  createEntity,
  deleteElementById,
  listEntities,
  loadById,
  patchAttribute,
  updateAttribute,
} from '../database/middleware';
import { connectorConfig, registerConnectorQueues, unregisterConnector } from '../database/amqp';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_SYNC, ENTITY_TYPE_WORK } from '../schema/internalObject';
import { FunctionalError, UnsupportedError } from '../config/errors';
import { FROM_START_STR, now, sinceNowInMinutes } from '../utils/format';
import { elLoadById } from '../database/elasticSearch';
import { READ_INDEX_HISTORY } from '../database/utils';
import { CONNECTOR_INTERNAL_EXPORT_FILE, CONNECTOR_INTERNAL_IMPORT_FILE } from '../schema/general';
import { SYSTEM_USER } from '../utils/access';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { deleteWorkForConnector } from './work';

// region utils
const completeConnector = (connector) => {
  if (connector) {
    return pipe(
      assoc('connector_scope', connector.connector_scope ? connector.connector_scope.split(',') : []),
      assoc('config', connectorConfig(connector.id)),
      assoc('active', sinceNowInMinutes(connector.updated_at) < 5)
    )(connector);
  }
  return null;
};
// endregion

// region connectors
export const loadConnectorById = (user, id) => {
  return loadById(user, id, ENTITY_TYPE_CONNECTOR).then((connector) => completeConnector(connector));
};

export const connectorForWork = async (user, id) => {
  const work = await elLoadById(user, id, ENTITY_TYPE_WORK, READ_INDEX_HISTORY);
  if (work) return loadConnectorById(user, work.connector_id);
  return null;
};

export const connectors = (user) => {
  return listEntities(user, [ENTITY_TYPE_CONNECTOR], { connectionFormat: false }).then((elements) =>
    map((conn) => completeConnector(conn), elements)
  );
};

export const connectorsFor = async (user, type, scope, onlyAlive = false, onlyAuto = false, onlyContextual = false) => {
  const connects = await connectors(user);
  return pipe(
    filter((c) => c.connector_type === type),
    filter((c) => (onlyAlive ? c.active === true : true)),
    filter((c) => (onlyAuto ? c.auto === true : true)),
    filter((c) => (onlyContextual ? c.only_contextual === true : true)),
    // eslint-disable-next-line prettier/prettier
    filter((c) =>
      scope && c.connector_scope && c.connector_scope.length > 0
        ? includes(
            scope.toLowerCase(),
            map((s) => s.toLowerCase(), c.connector_scope)
          )
        : true
    )
  )(connects);
};

export const connectorsForExport = async (user, scope, onlyAlive = false) => {
  return connectorsFor(user, CONNECTOR_INTERNAL_EXPORT_FILE, scope, onlyAlive);
};

export const connectorsForImport = async (user, scope, onlyAlive = false, onlyAuto = false, onlyContextual = false) => {
  return connectorsFor(user, CONNECTOR_INTERNAL_IMPORT_FILE, scope, onlyAlive, onlyAuto, onlyContextual);
};
// endregion

// region mutations
export const pingConnector = async (user, id, state) => {
  const creation = now();
  const connector = await loadById(user, id, ENTITY_TYPE_CONNECTOR);
  if (!connector) {
    throw FunctionalError('No connector found with the specified ID', { id });
  }
  if (connector.connector_state_reset === true) {
    const statePatch = { connector_state_reset: false };
    await patchAttribute(user, id, ENTITY_TYPE_CONNECTOR, statePatch);
  } else {
    const updatePatch = { updated_at: creation, connector_state: state };
    await patchAttribute(user, id, ENTITY_TYPE_CONNECTOR, updatePatch);
  }
  return loadById(user, id, 'Connector').then((data) => completeConnector(data));
};

export const resetStateConnector = async (user, id) => {
  const patch = { connector_state: '', connector_state_reset: true };
  await patchAttribute(user, id, ENTITY_TYPE_CONNECTOR, patch);
  return loadById(user, id, ENTITY_TYPE_CONNECTOR).then((data) => completeConnector(data));
};

// region syncs
export const patchSync = async (user, id, patch) => {
  const patched = await patchAttribute(user, id, ENTITY_TYPE_SYNC, patch);
  return patched.element;
};
export const findSyncById = (user, syncId) => {
  return loadById(user, syncId, ENTITY_TYPE_SYNC);
};
export const findAllSync = async (user, opts = {}) => {
  return listEntities(SYSTEM_USER, [ENTITY_TYPE_SYNC], opts);
};
export const httpBase = (baseUri) => (baseUri.endsWith('/') ? baseUri : `${baseUri}/`);
export const createSyncHttpUri = (sync) => {
  const { uri, stream_id: stream, current_state: state, listen_deletion: deletion } = sync;
  return `${httpBase(uri)}stream/${stream}?from=${state ?? FROM_START_STR}&listen-delete=${deletion}`;
};
export const testSync = async (user, sync) => {
  const eventSourceUri = createSyncHttpUri(sync);
  const { token, ssl_verify: ssl = false } = sync;
  return new Promise((resolve, reject) => {
    try {
      const eventSource = new EventSource(eventSourceUri, {
        rejectUnauthorized: ssl,
        headers: { authorization: `Bearer ${token}` },
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
export const registerSync = async (user, syncData) => {
  const data = { ...syncData, running: false };
  await testSync(user, data);
  return createEntity(user, data, ENTITY_TYPE_SYNC);
};
export const syncEditField = async (user, syncId, input) => {
  const { element } = await updateAttribute(user, syncId, ENTITY_TYPE_SYNC, input);
  return notify(BUS_TOPICS[ENTITY_TYPE_SYNC].EDIT_TOPIC, element, user);
};
export const syncDelete = async (user, syncId) => {
  await deleteElementById(user, syncId, ENTITY_TYPE_SYNC);
  return syncId;
};
export const syncCleanContext = async (user, syncId) => {
  await delEditContext(user, syncId);
  return loadById(user, syncId, ENTITY_TYPE_SYNC).then((syncToReturn) =>
    notify(BUS_TOPICS[ENTITY_TYPE_SYNC].EDIT_TOPIC, syncToReturn, user)
  );
};
export const syncEditContext = async (user, syncId, input) => {
  await setEditContext(user, syncId, input);
  return loadById(user, syncId, ENTITY_TYPE_SYNC).then((syncToReturn) =>
    notify(BUS_TOPICS[ENTITY_TYPE_SYNC].EDIT_TOPIC, syncToReturn, user)
  );
};
// endregion

export const registerConnector = async (user, connectorData) => {
  // eslint-disable-next-line camelcase
  const { id, name, type, scope, auto = null, only_contextual = null } = connectorData;
  const connector = await loadById(user, id, ENTITY_TYPE_CONNECTOR);
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
    await patchAttribute(user, id, ENTITY_TYPE_CONNECTOR, patch);
    return loadById(user, id, ENTITY_TYPE_CONNECTOR).then((data) => completeConnector(data));
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
  const createdConnector = await createEntity(user, connectorToCreate, ENTITY_TYPE_CONNECTOR);
  // Return the connector
  return completeConnector(createdConnector);
};

export const connectorDelete = async (user, connectorId) => {
  await deleteWorkForConnector(user, connectorId);
  await unregisterConnector(connectorId);
  return deleteElementById(user, connectorId, ENTITY_TYPE_CONNECTOR);
};
// endregion
