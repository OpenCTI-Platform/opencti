import { Promise } from 'bluebird';
import { map } from 'ramda';
import { createWork } from './work';
import { pushToConnector } from '../database/rabbitmq';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import { isStixObject } from '../schema/stixCoreObject';
import { getEntitiesListFromCache } from '../database/cache';
import { CONNECTOR_INTERNAL_ENRICHMENT } from '../schema/general';
import { isStixMatchFilterGroup } from '../utils/filtering/filtering-stix/stix-filtering';
import { isFilterGroupNotEmpty } from '../utils/filtering/filtering-utils';
import { SYSTEM_USER } from '../utils/access';
import { convertStoreToStix } from '../database/stix-converter';
import { inDraftContext } from '../database/engine';

export const createEntityAutoEnrichment = async (context, user, element, scope) => {
  const draftContext = inDraftContext(context, user);
  if (!isStixObject(element.entity_type) || draftContext) {
    return null; // we only enrich stix core objects, and we disable enrichment in draft context
  }
  const elementStandardId = element.standard_id;
  // Get the list of compatible connectors
  const targetConnectors = await findConnectorsForElementEnrichment(context, user, element, scope);
  // Create a work for each connector
  const workList = await Promise.all(
    map((connector) => {
      return createWork(context, user, connector, `Enrichment (${elementStandardId})`, elementStandardId).then((work) => {
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
          applicant_id: null, // No specific user asking for the import
        },
        event: {
          event_type: CONNECTOR_INTERNAL_ENRICHMENT,
          entity_id: elementStandardId,
          entity_type: element.entity_type,
        },
      };
      return pushToConnector(connector.internal_id, message);
    }, workList)
  );
  return workList;
};

const findConnectorsForElementEnrichment = async (context, user, element, scope) => {
  const connectors = await getEntitiesListFromCache(context, user, ENTITY_TYPE_CONNECTOR);
  return filterConnectorsForElementEnrichment(context, connectors, element, scope);
};

export const filterConnectorsForElementEnrichment = async (context, connectors, element, scope) => {
  // first filter active & enrichment connectors only
  const activeConnectors = connectors.filter((conn) => conn.active === true && conn.connector_type === CONNECTOR_INTERNAL_ENRICHMENT);
  const targetConnectors = [];
  for (let i = 0; i < activeConnectors.length; i += 1) {
    const conn = activeConnectors[i];
    const scopeMatch = scope ? (conn.connector_scope ?? []).some((s) => s.toLowerCase() === scope.toLowerCase()) : true;
    const autoTrigger = conn.connector_trigger_filters ? await isStixMatchConnectorFilter(context, element, conn.connector_trigger_filters) : conn.auto === true;
    if (scopeMatch && autoTrigger) {
      targetConnectors.push(conn);
    }
  }
  return targetConnectors;
};

const isStixMatchConnectorFilter = async (context, element, stringFilters) => {
  if (!stringFilters) {
    return true; // no filters -> match all
  }
  const jsonFilters = JSON.parse(stringFilters);
  if (!isFilterGroupNotEmpty(jsonFilters)) {
    return true; // filters empty -> match all
  }
  const stix = convertStoreToStix(element);
  return isStixMatchFilterGroup(context, SYSTEM_USER, stix, jsonFilters);
};
