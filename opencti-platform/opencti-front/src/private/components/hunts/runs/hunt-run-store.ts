import { ConnectionHandler, RecordProxy, RecordSourceSelectorProxy } from 'relay-runtime';

export const HUNT_RUNS_CONNECTION_KEY = 'Pagination_huntRuns';

/** Adds freshly started runs at the top of the runs list of the hunt. */
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
  records.forEach((record) => {
    if (record) {
      const edge = ConnectionHandler.createEdge(store, connection, record, 'HuntRunEdge');
      ConnectionHandler.insertEdgeBefore(connection, edge);
    }
  });
};
