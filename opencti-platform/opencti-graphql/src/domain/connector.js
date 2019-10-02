import { assoc, filter, map, pipe } from 'ramda';
import {
  commitWriteTx,
  find,
  getById,
  now,
  takeWriteTx,
  updateAttribute
} from '../database/grakn';
import { connectorConfig, registerConnectorQueues } from '../database/rabbitmq';

// EXTERNAL_IMPORT = None
// INTERNAL_IMPORT_FILE = Files mime types to support (application/json, ...) -> import-
// INTERNAL_ENRICHMENT = Entity types to support (Report, Hash, ...) -> enrich-
// INTERNAL_EXPORT_FILE = Files mime types to generate (application/pdf, ...) -> export-

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

export const connectorsForExport = async () => {
  const connects = await connectors();
  return filter(c => c.connector_type === 'INTERNAL_EXPORT_FILE', connects);
};

export const pingConnector = async id => {
  const creation = now();
  await updateAttribute(id, {
    key: 'updated_at',
    value: [creation]
  });
  return getById(id).then(data => assoc('config', connectorConfig(id), data));
};

export const registerConnector = async ({ id, name, type, scope }) => {
  const connector = await getById(id);
  const creation = now();
  // Register queues
  await registerConnectorQueues(id, type, scope);
  if (connector) {
    // Simple connector update
    await updateAttribute(id, { key: 'name', value: [name] });
    await updateAttribute(id, { key: 'updated_at', value: [creation] });
    await updateAttribute(id, {
      key: 'connector_scope',
      value: [scope.join(',')]
    });
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
