import { assoc, filter, includes, map, pipe } from 'ramda';
import {
  executeWrite,
  find,
  loadEntityById,
  graknNow,
  now,
  sinceNowInMinutes,
  updateAttribute
} from '../database/grakn';
import { connectorConfig, registerConnectorQueues } from '../database/rabbitmq';
import { elLoadById } from '../database/elasticSearch';

export const CONNECTOR_INTERNAL_IMPORT_FILE = 'INTERNAL_IMPORT_FILE'; // Files mime types to support (application/json, ...) -> import-
export const CONNECTOR_INTERNAL_ENRICHMENT = 'INTERNAL_ENRICHMENT'; // Entity types to support (Report, Hash, ...) -> enrich-
export const CONNECTOR_INTERNAL_EXPORT_FILE = 'INTERNAL_EXPORT_FILE'; // Files mime types to generate (application/pdf, ...) -> export-

// region utils
const completeConnector = connector => {
  return pipe(
    assoc('connector_scope', connector.connector_scope.split(',')),
    assoc('config', connectorConfig(connector.id)),
    assoc('active', sinceNowInMinutes(connector.updated_at) < 2)
  )(connector);
};
// endregion

// region grakn fetch
export const connectors = () => {
  const query = `match $c isa Connector; get;`;
  return find(query, ['c']).then(elements => map(conn => completeConnector(conn.c), elements));
};
export const connectorsFor = async (type, scope, onlyAlive = false) => {
  const connects = await connectors();
  return pipe(
    filter(c => c.connector_type === type),
    filter(c => (onlyAlive ? c.active === true : true)),
    // eslint-disable-next-line prettier/prettier
    filter(c =>
      scope
        ? includes(
            scope.toLowerCase(),
            map(s => s.toLowerCase(), c.connector_scope)
          )
        : true
    )
  )(connects);
};
export const connectorsForEnrichment = async (scope, onlyAlive = false) =>
  connectorsFor(CONNECTOR_INTERNAL_ENRICHMENT, scope, onlyAlive);
export const connectorsForExport = async (scope, onlyAlive = false) =>
  connectorsFor(CONNECTOR_INTERNAL_EXPORT_FILE, scope, onlyAlive);
export const connectorsForImport = async (scope, onlyAlive = false) =>
  connectorsFor(CONNECTOR_INTERNAL_IMPORT_FILE, scope, onlyAlive);
// endregion

// region mutations
export const pingConnector = async (id, state) => {
  const creation = now();
  await executeWrite(async wTx => {
    const updateInput = { key: 'updated_at', value: [creation] };
    await updateAttribute(id, updateInput, wTx);
    const stateInput = { key: 'connector_state', value: [state] };
    await updateAttribute(id, stateInput, wTx);
  });
  return elLoadById(id).then(data => completeConnector(data));
};

export const registerConnector = async ({ id, name, type, scope }) => {
  const connector = await loadEntityById(id);
  // Register queues
  await registerConnectorQueues(id, name, type, scope);
  if (connector) {
    // Simple connector update
    await executeWrite(async wTx => {
      const inputName = { key: 'name', value: [name] };
      await updateAttribute(id, inputName, wTx);
      const updatedInput = { key: 'updated_at', value: [now()] };
      await updateAttribute(id, updatedInput, wTx);
      const scopeInput = { key: 'connector_scope', value: [scope.join(',')] };
      await updateAttribute(id, scopeInput, wTx);
    });
    return elLoadById(id).then(data => completeConnector(data));
  }
  // Need to create the connector
  const creation = graknNow();
  await executeWrite(async wTx => {
    const query = `insert $connector isa Connector, 
          has internal_id_key "${id}",
          has name "${name}",
          has connector_type "${type}",
          has connector_scope "${scope.join(',')}",
          has created_at ${creation},
          has updated_at ${creation};`;
    await wTx.tx.query(query);
  });
  // Return the connector
  return loadEntityById(id).then(data => completeConnector(data));
};
// endregion

