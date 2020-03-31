import { Promise } from 'bluebird';
import { map } from 'ramda';
import { connectorsFor } from './connector';
import { createWork } from './work';
import { pushToConnector } from '../database/rabbitmq';

export const CONNECTOR_INTERNAL_ENRICHMENT = 'INTERNAL_ENRICHMENT'; // Entity types to support (Report, Hash, ...) -> enrich-

export const connectorsForEnrichment = async (scope, onlyAlive = false) =>
  connectorsFor(CONNECTOR_INTERNAL_ENRICHMENT, scope, onlyAlive);

export const askEnrich = async (observableId, scope) => {
  // Get the list of compatible connectors
  const targetConnectors = await connectorsForEnrichment(scope, true);
  // Create a work for each connector
  const workList = await Promise.all(
    map((connector) => {
      return createWork(connector, 'Stix-Observable', observableId).then(({ job, work }) => {
        return { connector, job, work };
      });
    }, targetConnectors)
  );
  // Send message to all correct connectors queues
  await Promise.all(
    map((data) => {
      const { connector, work, job } = data;
      const message = { work_id: work.internal_id_key, job_id: job.internal_id_key, entity_id: observableId };
      return pushToConnector(connector, message);
    }, workList)
  );
  return workList;
};
