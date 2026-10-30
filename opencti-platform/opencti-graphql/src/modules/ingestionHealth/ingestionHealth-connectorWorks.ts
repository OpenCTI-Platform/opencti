import { Promise as BluePromise } from 'bluebird';
import { FilterOperator } from '../../generated/graphql';
import { ENTITY_TYPE_CONNECTOR } from '../../schema/internalObject';
import { fullEntitiesList } from '../../database/middleware-loader';
import { ES_MAX_CONCURRENCY } from '../../database/engine';
import { worksForConnector } from '../../domain/work';
import { addFilter } from '../../utils/filtering/filtering-utils';
import type { BasicStoreEntityConnector, ConnectorInfo } from '../connector/connector-types';
import type { HealthCheckIngestor, RuntimeDataReadContext } from './ingestionHealth-types';

// A stream pushes events as they come: it creates no work
const CONNECTOR_TYPE_STREAM = 'STREAM';
// Source of the errors a connector reports on its own work (the worker ones carry the element as source)
const WORK_ERROR_SOURCE_CONNECTOR = 'CONNECTOR';
// A work is processed a few seconds to minutes after the end of its run: last_run_datetime is the end of the run
export const LAST_RUN_TOLERANCE_MS = 5 * 60 * 1000;

export interface ConnectorWorkError {
  message?: string;
  source?: string | null;
}

export interface ConnectorWork {
  timestamp: string;
  // Absent while the work is open, and for a work force-closed
  processed_time?: string | null;
  errors?: ConnectorWorkError[];
}

export interface ConnectorRuntimeState {
  connector_type: string;
  connector_info?: ConnectorInfo | null;
  // The most recent processed work: absent for a stream, and when purged or never run
  last_work?: ConnectorWork;
}

/**
 * Reads, for the connectors of the ingestors, what the runtime checks judge: connector_info, last work.
 * A read failure rejects: it must not be read as a missing value (registry contract).
 * The connectors are read ES_MAX_CONCURRENCY at a time: a platform may have hundreds.
 *
 * - connector_info is read from Elasticsearch, not from the cache: pings update it without refreshing the cache
 *   (same reason as findRegularlyPingingConnectors).
 * - last work: the most recent processed work, for every type. An open one says nothing yet, and reading it would clear
 *   the checks during every run of an external import. A run that left no work is caught by getConclusiveWork (last_run_datetime).
 *   A stream has no work: none is read.
 * Connectors not found are omitted.
 */
export const loadConnectorsRuntimeState = async (
  ingestors: HealthCheckIngestor[],
  read: RuntimeDataReadContext,
): Promise<Map<string, ConnectorRuntimeState>> => {
  const states = new Map<string, ConnectorRuntimeState>();
  if (ingestors.length === 0) {
    return states;
  }
  const { context, user } = read;
  const connectors = await fullEntitiesList<BasicStoreEntityConnector>(context, user, [ENTITY_TYPE_CONNECTOR], {
    ids: ingestors.map((ingestor) => ingestor.internal_id),
    baseData: true,
    baseFields: ['connector_type', 'connector_info'],
  });
  const processedOnly = addFilter(null, 'processed_time', [], FilterOperator.NotNil);
  await BluePromise.map(connectors, async (connector) => {
    const works = connector.connector_type === CONNECTOR_TYPE_STREAM
      ? []
      // work.js is untyped: elPaginate without connectionFormat returns the hits
      : await worksForConnector(context, user, connector.internal_id, { first: 1, filters: processedOnly }) as unknown as ConnectorWork[];
    states.set(connector.internal_id, {
      connector_type: connector.connector_type,
      connector_info: connector.connector_info,
      last_work: works[0],
    });
  }, { concurrency: ES_MAX_CONCURRENCY });
  return states;
};

/**
 * The last work, when it tells how the last run went.
 *
 * Not conclusive:
 * - no work: purged, or never run
 * - not processed: still open, or force-closed. Says nothing yet (the reader only returns processed works: a guard).
 * - processed long before the end of the last run: the last run left no processed work (it failed before creating one,
 *   or left it open, publishing only its successes), the work is the one of an earlier run. Skipped when last_run_datetime is unknown.
 */
export const getConclusiveWork = (state: ConnectorRuntimeState): ConnectorWork | undefined => {
  const work = state.last_work;
  if (!work?.processed_time) {
    return undefined;
  }
  const lastRun = state.connector_info?.last_run_datetime;
  if (lastRun && new Date(work.processed_time).getTime() < new Date(lastRun).getTime() - LAST_RUN_TOLERANCE_MS) {
    return undefined;
  }
  return work;
};

/**
 * Whether the connector failed its work: an entry without source is the connector's own (a work closed with an error),
 * the entries with another source are worker errors on an element, not a failure of the connector.
 * The messages are the ones of the connector: "CONNECTOR" entries (the exception raised) first, then the entries without source.
 */
export const getWorkFailure = (work: ConnectorWork): { failed: boolean; messages: string[] } => {
  const errors = work.errors ?? [];
  const connectorErrors = errors.filter((error) => error.source === WORK_ERROR_SOURCE_CONNECTOR);
  const sourceless = errors.filter((error) => !error.source);
  const messages = [...connectorErrors, ...sourceless]
    .map((error) => error.message)
    .filter((message): message is string => !!message);
  return { failed: sourceless.length > 0, messages };
};
