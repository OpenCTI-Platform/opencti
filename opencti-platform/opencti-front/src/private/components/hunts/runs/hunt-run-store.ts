import { ConnectionHandler, RecordProxy, RecordSourceSelectorProxy } from 'relay-runtime';

export const HUNT_RUNS_CONNECTION_KEY = 'Pagination_huntRuns';

/** Adds freshly started runs at the top of the runs list of the hunt. A run already listed (a retry returning the
 * next attempt it already created) is not added twice. */
export const insertStartedHuntRuns = (
  store: RecordSourceSelectorProxy,
  records: ReadonlyArray<RecordProxy | null | undefined>,
  paginationOptions: Record<string, unknown>,
) => {
  const { count: _count, ...params } = paginationOptions;
  const connection = ConnectionHandler.getConnection(store.getRoot(), HUNT_RUNS_CONNECTION_KEY, params);
  if (!connection) {
    return;
  }
  const listed = new Set((connection.getLinkedRecords('edges') ?? []).map((edge) => edge?.getLinkedRecord('node')?.getDataID()));
  records.forEach((record) => {
    if (record && !listed.has(record.getDataID())) {
      listed.add(record.getDataID());
      const edge = ConnectionHandler.createEdge(store, connection, record, 'HuntRunEdge');
      ConnectionHandler.insertEdgeBefore(connection, edge);
    }
  });
};
