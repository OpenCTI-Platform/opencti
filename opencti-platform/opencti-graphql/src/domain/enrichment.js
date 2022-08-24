import { Promise } from 'bluebird';
import { map } from 'ramda';
import { createWork } from './work';
import { pushToConnector } from '../database/rabbitmq';
import { connectorsEnrichment } from '../database/repository';
import { getEntitiesFromCache } from '../manager/cacheManager';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';

export const createEntityAutoEnrichment = async (user, stixCoreObjectId, scope) => {
  // Get the list of compatible connectors
  const connectors = await getEntitiesFromCache(ENTITY_TYPE_CONNECTOR);
  const targetConnectors = connectorsEnrichment(connectors, scope, true, true);
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
