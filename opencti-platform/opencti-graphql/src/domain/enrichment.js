import { Promise } from 'bluebird';
import { map } from 'ramda';
import { createWork } from './work';
import { pushToConnector } from '../database/rabbitmq';
import { connectorsEnrichment } from '../database/repository';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import { getEntitiesListFromCache } from '../database/cache';

export const createEntityAutoEnrichment = async (context, user, stixCoreObjectId, scope) => {
  // Get the list of compatible connectors
  const connectors = await getEntitiesListFromCache(context, user, ENTITY_TYPE_CONNECTOR);
  const targetConnectors = connectorsEnrichment(connectors, scope, true, true);
  // Create a work for each connector
  const workList = await Promise.all(
    map((connector) => {
      return createWork(context, user, connector, `Enrichment (${stixCoreObjectId})`, stixCoreObjectId).then((work) => {
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
      return pushToConnector(connector.internal_id, message);
    }, workList)
  );
  return workList;
};
