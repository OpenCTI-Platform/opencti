import { Promise } from 'bluebird';
import { map } from 'ramda';
import { connectorsFor } from './connector';
import { createWork } from './work';
import { pushToConnector } from '../database/amqp';
import { CONNECTOR_INTERNAL_ENRICHMENT } from '../schema/general';

export const connectorsForEnrichment = async (user, scope, onlyAlive = false, onlyAuto = false) =>
  connectorsFor(user, CONNECTOR_INTERNAL_ENRICHMENT, scope, onlyAlive, onlyAuto);

export const askEnrich = async (user, stixCoreObjectId, scope) => {
  // Get the list of compatible connectors
  const targetConnectors = await connectorsForEnrichment(user, scope, true, true);
  // Create a work for each connector
  const workList = await Promise.all(
    map((connector) => {
      return createWork(user, connector, `Enrichment (${stixCoreObjectId})`, stixCoreObjectId).then((work) => {
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
          entity_id: stixCoreObjectId,
        },
      };
      return pushToConnector(connector, message);
    }, workList)
  );
  return workList;
};
