import { Promise } from 'bluebird';
import { map } from 'ramda';
import { connectorsFor } from './connector';
import { CONNECTOR_INTERNAL_ENRICHMENT, createWork } from './work';
import { pushToConnector } from '../database/rabbitmq';

export const connectorsForEnrichment = async (scope, onlyAlive = false, onlyAuto = false) =>
  connectorsFor(CONNECTOR_INTERNAL_ENRICHMENT, scope, onlyAlive, onlyAuto);

export const askEnrich = async (user, observableId, scope) => {
  // Get the list of compatible connectors
  const targetConnectors = await connectorsForEnrichment(scope, true, true);
  // Create a work for each connector
  const workList = await Promise.all(
    map((connector) => {
      return createWork(user, connector, `Enrichment (${observableId})`, observableId).then((work) => {
        return { connector, work };
      });
    }, targetConnectors)
  );
  // Send message to all correct connectors queues
  await Promise.all(
    map((data) => {
      const { connector, work } = data;
      const message = {
        internal: {
          work_id: work.id, // Related action for history
          applicant_id: null, // User asking for the import
        },
        event: {
          entity_id: observableId,
        },
      };
      return pushToConnector(connector, message);
    }, workList)
  );
  return workList;
};
