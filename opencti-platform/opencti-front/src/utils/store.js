import { ConnectionHandler } from 'relay-runtime';
import * as R from 'ramda';
import { filter } from 'ramda';

export const isNodeInConnection = (payload, conn) => {
  const records = conn.getLinkedRecords('edges');
  const recordsIds = records.map((n) => n.getLinkedRecord('node').getValue('id'));
  const payloadId = payload.getValue('id');
  return R.includes(payloadId, recordsIds);
};

export const insertNode = (store, key, filters, rootField) => {
  // Build record ids
  const record = store.get(store.getRoot().getDataID());

  // Connections cannot use count as a filter because we NEED to update the count when we push new elements
  const params = { ...filters };
  delete params.count;
  delete params.id;

  const conn = ConnectionHandler.getConnection(record, key, params);
  if (conn) {
    // Build the payload to add
    const payload = store.getRootField(rootField);
    // If payload id not already in the list, add the node
    if (!isNodeInConnection(payload, conn)) {
      const newEdge = payload.setLinkedRecord(payload, 'node');
      ConnectionHandler.insertEdgeBefore(conn, newEdge);
    }
  } else {
    throw new Error(`Cant insert node on not found connection ${{ key, params }}`);
  }
};

export const deleteNode = (store, key, filters, id) => {
  const record = store.get(store.getRoot().getDataID());

  // Connections cannot use count as a filter because we NEED to update the count when we remove new elements
  const params = { ...filters };
  delete params.count;
  delete params.id;

  const conn = ConnectionHandler.getConnection(record, key, params);
  if (conn) {
    ConnectionHandler.deleteNode(conn, id);
  } else {
    throw new Error(`Delete node connection not found ${{ key, params, id }}`);
  }
};

export const deleteNodeFromEdge = (store, path, rootId, deleteId) => {
  const node = store.get(rootId);

  const records = node.getLinkedRecord(path);
  const edges = records.getLinkedRecords('edges');
  const newEdges = filter(
    (n) => n.getLinkedRecord('node').getValue('id') !== deleteId,
    edges,
  );
  records.setLinkedRecords(newEdges, 'edges');
};
