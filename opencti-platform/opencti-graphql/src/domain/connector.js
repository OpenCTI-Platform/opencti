import { assoc, filter, includes, map, pipe } from 'ramda';
import {
  createEntity,
  deleteElementById,
  listEntities,
  loadById,
  now,
  patchAttribute,
  sinceNowInMinutes,
} from '../database/middleware';
import { connectorConfig, registerConnectorQueues, unregisterConnector } from '../database/rabbitmq';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import { FunctionalError } from '../config/errors';

export const CONNECTOR_INTERNAL_IMPORT_FILE = 'INTERNAL_IMPORT_FILE'; // Files mime types to support (application/json, ...) -> import-
export const CONNECTOR_INTERNAL_EXPORT_FILE = 'INTERNAL_EXPORT_FILE'; // Files mime types to generate (application/pdf, ...) -> export-

// region utils
const completeConnector = (connector) => {
  if (connector) {
    return pipe(
      assoc('connector_scope', connector.connector_scope.split(',')),
      assoc('config', connectorConfig(connector.id)),
      assoc('active', sinceNowInMinutes(connector.updated_at) < 2)
    )(connector);
  }
  return null;
};
// endregion

// region connectors
export const loadConnectorById = (id) => {
  return loadById(id, ENTITY_TYPE_CONNECTOR).then((connector) => completeConnector(connector));
};

export const connectors = () => {
  return listEntities([ENTITY_TYPE_CONNECTOR], { connectionFormat: false }).then((elements) =>
    map((conn) => completeConnector(conn), elements)
  );
};

export const connectorsFor = async (type, scope, onlyAlive = false, onlyAuto = false) => {
  const connects = await connectors();
  return pipe(
    filter((c) => c.connector_type === type),
    filter((c) => (onlyAlive ? c.active === true : true)),
    filter((c) => (onlyAuto ? c.auto === true : true)),
    // eslint-disable-next-line prettier/prettier
    filter((c) =>
      scope
        ? includes(
            scope.toLowerCase(),
            map((s) => s.toLowerCase(), c.connector_scope)
          )
        : true
    )
  )(connects);
};

export const connectorsForExport = async (scope, onlyAlive = false) => {
  return connectorsFor(CONNECTOR_INTERNAL_EXPORT_FILE, scope, onlyAlive);
};

export const connectorsForImport = async (scope, onlyAlive = false) => {
  return connectorsFor(CONNECTOR_INTERNAL_IMPORT_FILE, scope, onlyAlive);
};
// endregion

// region mutations
export const pingConnector = async (user, id, state) => {
  const creation = now();
  const connector = await loadById(id, ENTITY_TYPE_CONNECTOR);
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
  return loadById(id, 'Connector').then((data) => completeConnector(data));
};

export const resetStateConnector = async (user, id) => {
  const patch = { connector_state: '', connector_state_reset: true };
  await patchAttribute(user, id, ENTITY_TYPE_CONNECTOR, patch);
  return loadById(id, ENTITY_TYPE_CONNECTOR).then((data) => completeConnector(data));
};

export const registerConnector = async (user, connectorData) => {
  const { id, name, type, scope, auto = null } = connectorData;
  const connector = await loadById(id, ENTITY_TYPE_CONNECTOR);
  // Register queues
  await registerConnectorQueues(id, name, type, scope);
  if (connector) {
    // Simple connector update
    const patch = { name, updated_at: now(), connector_user_id: user.id, connector_scope: scope.join(','), auto };
    await patchAttribute(user, id, ENTITY_TYPE_CONNECTOR, patch);
    return loadById(id, ENTITY_TYPE_CONNECTOR).then((data) => completeConnector(data));
  }
  // Need to create the connector
  const connectorToCreate = {
    internal_id: id,
    name,
    connector_type: type,
    connector_scope: scope.join(','),
    auto,
    connector_user_id: user.id,
  };
  const createdConnector = await createEntity(user, connectorToCreate, ENTITY_TYPE_CONNECTOR);
  // Return the connector
  return completeConnector(createdConnector);
};

export const connectorDelete = async (user, connectorId) => {
  await unregisterConnector(connectorId);
  return deleteElementById(user, connectorId, ENTITY_TYPE_CONNECTOR);
};
// endregion
