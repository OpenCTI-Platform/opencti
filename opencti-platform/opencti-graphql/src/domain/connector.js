import { assoc, filter, includes, map, pipe } from 'ramda';
import {
  createEntity,
  deleteEntityById,
  find,
  loadEntityById,
  now,
  sinceNowInMinutes,
  updateAttr,
} from '../database/grakn';
import { connectorConfig, registerConnectorQueues, unregisterConnector } from '../database/rabbitmq';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';

export const CONNECTOR_INTERNAL_IMPORT_FILE = 'INTERNAL_IMPORT_FILE'; // Files mime types to support (application/json, ...) -> import-
export const CONNECTOR_INTERNAL_EXPORT_FILE = 'INTERNAL_EXPORT_FILE'; // Files mime types to generate (application/pdf, ...) -> export-

// region utils
const completeConnector = (connector) => {
  return pipe(
    assoc('connector_scope', connector.connector_scope.split(',')),
    assoc('config', connectorConfig(connector.id)),
    assoc('active', sinceNowInMinutes(connector.updated_at) < 2)
  )(connector);
};
// endregion

// region grakn fetch
export const loadConnectorById = (id) => loadEntityById(id, ENTITY_TYPE_CONNECTOR);
export const connectors = () => {
  const query = `match $c isa ${ENTITY_TYPE_CONNECTOR}; get;`;
  return find(query, ['c']).then((elements) => map((conn) => completeConnector(conn.c), elements));
};

export const connectorsFor = async (type, scope, onlyAlive = false) => {
  const connects = await connectors();
  return pipe(
    filter((c) => c.connector_type === type),
    filter((c) => (onlyAlive ? c.active === true : true)),
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

export const connectorsForExport = async (scope, onlyAlive = false) =>
  connectorsFor(CONNECTOR_INTERNAL_EXPORT_FILE, scope, onlyAlive);

export const connectorsForImport = async (scope, onlyAlive = false) =>
  connectorsFor(CONNECTOR_INTERNAL_IMPORT_FILE, scope, onlyAlive);
// endregion

// region mutations
export const pingConnector = async (user, id, state) => {
  const creation = now();
  const connector = await loadEntityById(id, ENTITY_TYPE_CONNECTOR);
  if (connector.connector_state_reset === true) {
    const stateInput = { key: 'connector_state_reset', value: [false] };
    await updateAttr(user, id, ENTITY_TYPE_CONNECTOR, stateInput, { noLog: true });
  } else {
    const updateInput = { key: 'updated_at', value: [creation] };
    const stateInput = { key: 'connector_state', value: [state] };
    await updateAttr(user, id, ENTITY_TYPE_CONNECTOR, [updateInput, stateInput], { noLog: true });
  }
  return loadEntityById(id, 'Connector').then((data) => completeConnector(data));
};

export const resetStateConnector = async (user, id) => {
  const stateInput = { key: 'connector_state', value: [''] };
  const stateResetInput = { key: 'connector_state_reset', value: [true] };
  await updateAttr(user, id, ENTITY_TYPE_CONNECTOR, [stateInput, stateResetInput], { noLog: true });
  return loadEntityById(id, ENTITY_TYPE_CONNECTOR).then((data) => completeConnector(data));
};

export const registerConnector = async (user, connectorData) => {
  const { id, name, type, scope } = connectorData;
  const connector = await loadEntityById(id, ENTITY_TYPE_CONNECTOR);
  // Register queues
  await registerConnectorQueues(id, name, type, scope);
  if (connector) {
    // Simple connector update
    const inputName = { key: 'name', value: [name] };
    const updatedInput = { key: 'updated_at', value: [now()] };
    const scopeInput = { key: 'connector_scope', value: [scope.join(',')] };
    await updateAttr(user, id, ENTITY_TYPE_CONNECTOR, [inputName, updatedInput, scopeInput], { noLog: true });
    return loadEntityById(id, ENTITY_TYPE_CONNECTOR).then((data) => completeConnector(data));
  }
  // Need to create the connector
  const connectorToCreate = { internal_id: id, name, connector_type: type, connector_scope: scope.join(',') };
  const createdConnector = await createEntity(user, connectorToCreate, ENTITY_TYPE_CONNECTOR, {
    noLog: true,
  });
  // Return the connector
  return completeConnector(createdConnector);
};

export const connectorDelete = async (user, connectorId) => {
  await unregisterConnector(connectorId);
  return deleteEntityById(user, connectorId, ENTITY_TYPE_CONNECTOR, { noLog: true });
};
// endregion
