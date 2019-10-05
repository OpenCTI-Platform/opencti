import { assoc, filter, includes, map, pipe } from 'ramda';
import {
  closeWriteTx,
  commitWriteTx,
  find,
  getById,
  now,
  takeWriteTx,
  updateAttribute
} from '../database/grakn';
import { connectorConfig, registerConnectorQueues } from '../database/rabbitmq';

export const CONNECTOR_EXTERNAL_IMPORT = 'EXTERNAL_IMPORT'; // None
export const CONNECTOR_INTERNAL_IMPORT_FILE = 'INTERNAL_IMPORT_FILE'; // Files mime types to support (application/json, ...) -> import-
export const CONNECTOR_INTERNAL_ENRICHMENT = 'INTERNAL_ENRICHMENT'; // Entity types to support (Report, Hash, ...) -> enrich-
export const CONNECTOR_INTERNAL_EXPORT_FILE = 'INTERNAL_EXPORT_FILE'; // Files mime types to generate (application/pdf, ...) -> export-

const completeConnector = connector => {
  return pipe(
    assoc('connector_scope', connector.connector_scope.split(',')),
    assoc('config', connectorConfig(connector.id))
  )(connector);
};

export const connectors = () => {
  const query = `match $c isa Connector; get $c;`;
  return find(query, ['c']).then(elements =>
    map(conn => completeConnector(conn.c), elements)
  );
};

export const connectorsForExport = async mime => {
  const connects = await connectors();
  const exportConnects = filter(
    c => c.connector_type === 'INTERNAL_EXPORT_FILE',
    connects
  );
  return mime
    ? filter(c => includes(mime, c.connector_scope), exportConnects)
    : exportConnects;
};

export const pingConnector = async id => {
  const creation = now();
  return updateAttribute(id, {
    key: 'updated_at',
    value: [creation]
  }).then(data => assoc('config', connectorConfig(id), data));
};

export const registerConnector = async ({ id, name, type, scope }) => {
  const connector = await getById(id);
  const creation = now();
  // Register queues
  await registerConnectorQueues(id, name, type, scope);
  if (connector) {
    // Simple connector update
    const wTx = await takeWriteTx();
    const inputName = { key: 'name', value: [name] };
    await updateAttribute(id, inputName, wTx);
    const updatedInput = { key: 'updated_at', value: [creation] };
    await updateAttribute(id, updatedInput, wTx);
    const scopeInput = { key: 'connector_scope', value: [scope.join(',')] };
    await updateAttribute(id, scopeInput, wTx);
    await closeWriteTx(wTx);
  } else {
    // Need to create the connector
    // 01. Insert the connector
    const wTx = await takeWriteTx();
    const query = `insert $connector isa Connector, 
          has internal_id "${id}",
          has name "${name}",
          has connector_type "${type}",
          has connector_scope "${scope.join(',')}",
          has created_at ${creation},
          has updated_at ${creation};`;
    await wTx.tx.query(query);
    // 03. Finalize the registration
    await commitWriteTx(wTx);
  }
  return getById(id).then(data => completeConnector(data));
};
