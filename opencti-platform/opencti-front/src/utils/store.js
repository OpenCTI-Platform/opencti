import * as R from 'ramda';
import { filter } from 'ramda';
import { ConnectionHandler } from 'relay-runtime';

export const isNodeInConnection = (payload, conn) => {
  const records = conn.getLinkedRecords('edges');
  const recordsIds = records.map((n) => n.getLinkedRecord('node').getValue('id'));
  const payloadId = payload.getValue('id');
  return R.includes(payloadId, recordsIds);
};

export const insertNode = (
  store,
  key,
  filters,
  rootField,
  objectId,
  linkedRecord,
  input,
  relKey,
) => {
  // Build record ids
  let record;
  if (objectId) {
    record = store.get(objectId);
  } else {
    record = store.get(store.getRoot().getDataID());
  }
  // Connections cannot use count as a filter because we NEED to update the count when we push new elements
  const params = { ...filters };
  delete params.count;
  delete params.id;
  let conn;
  if (Object.keys(params).length === 0) {
    conn = ConnectionHandler.getConnection(record, key);
  } else {
    conn = ConnectionHandler.getConnection(record, key, params);
  }
  if (conn) {
    // Build the payload to add
    let payload;
    if (linkedRecord && input && relKey) {
      const result = store
        .getRootField(rootField)
        .getLinkedRecord(linkedRecord, { input });
      payload = result.getLinkedRecord(relKey);
    } else {
      payload = store.getRootField(rootField);
    }
    // If payload id not already in the list, add the node
    if (!isNodeInConnection(payload, conn)) {
      const newEdge = payload.setLinkedRecord(payload, 'node');
      ConnectionHandler.insertEdgeBefore(conn, newEdge);
    }
  } else {
    throw new Error(`Cant insert node on not found connection ${key}`);
  }
};

export const deleteNodeFromId = (store, containerId, key, filters, id) => {
  const record = store.get(containerId);

  // Connections cannot use count as a filter because we NEED to update the count when we remove new elements
  const params = { ...filters };
  delete params.count;
  delete params.id;
  const conn = ConnectionHandler.getConnection(record, key, params);
  if (conn) {
    ConnectionHandler.deleteNode(conn, id);
  } else {
    throw new Error(`Delete node ${id} connection ${key} not found`);
  }
};

export const deleteNode = (store, key, filters, id) => {
  deleteNodeFromId(store, store.getRoot().getDataID(), key, filters, id);
};

export const deleteNodeFromEdge = (store, path, rootId, deleteId, params) => {
  const node = store.get(rootId);

  const records = node.getLinkedRecord(path, params);
  const edges = records.getLinkedRecords('edges');
  const newEdges = filter(
    (n) => n.getLinkedRecord('node').getValue('id') !== deleteId,
    edges,
  );
  records.setLinkedRecords(newEdges, 'edges');
};
