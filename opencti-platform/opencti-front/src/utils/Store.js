import { ConnectionHandler } from 'relay-runtime';
import * as R from 'ramda';

export const insertNode = (store, key, filters, rootField) => {
  const conn = ConnectionHandler.getConnection(
    store.get(store.getRoot().getDataID()),
    key,
    filters,
  );
  const records = conn.getLinkedRecords('edges');
  const recordsIds = R.map(
    (n) => n.getLinkedRecord('node').getValue('id'),
    records,
  );
  const payload = store.getRootField(rootField);
  const payloadId = payload.getValue('id');
  if (!R.includes(payloadId, recordsIds)) {
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
