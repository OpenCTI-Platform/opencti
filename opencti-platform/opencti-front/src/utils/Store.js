import { ConnectionHandler } from 'relay-runtime';
import * as R from 'ramda';

export const isNodeInConnection = (payload, conn) => {
  const records = conn.getLinkedRecords('edges');
  const recordsIds = records.map((n) => n.getLinkedRecord('node').getValue('id'));
  const payloadId = payload.getValue('id');
  return R.includes(payloadId, recordsIds);
};

export const insertNode = (store, key, filters, rootField) => {
  // Build record ids
  const record = store.get(store.getRoot().getDataID());
  const conn = ConnectionHandler.getConnection(record, key, filters);
  // Build the payload to add
  const payload = store.getRootField(rootField);
  // If payload id not already in the list, add the node
  if (!isNodeInConnection(payload, conn)) {
    const newEdge = payload.setLinkedRecord(payload, 'node');
    ConnectionHandler.insertEdgeBefore(conn, newEdge);
  }
};

export const deleteNode = (store, key, filters, id) => {
  const conn = ConnectionHandler.getConnection(
    store.get(store.getRoot().getDataID()),
    key,
    filters,
  );
  ConnectionHandler.deleteNode(conn, id);
};
