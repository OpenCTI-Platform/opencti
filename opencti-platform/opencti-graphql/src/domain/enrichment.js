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
import { getDraftContext } from '../utils/draftContext';
import { convertStoreToStix_2_1 } from '../database/stix-2-1-converter';

const publishEventToConnectors = async (context, user, element, targetConnectors, trigger, stixLoaders) => {
  const draftContext = getDraftContext(context, user);
  const contextOutOfDraft = { ...context, draft_context: '' };
  const elementStandardId = element.standard_id;
  // Create a work for each connector
  const workMessage = draftContext ? `Enrichment (${elementStandardId}) in draft ${draftContext}` : `Enrichment (${elementStandardId})`;
  const workList = await Promise.all(
    map((connector) => {
      return createWork(contextOutOfDraft, user, connector, workMessage, elementStandardId, { draftContext }).then((work) => {
        return { connector, work };
      });
    }, targetConnectors)
  );
  // Send message to all correct connectors queues
  for (let index = 0; index < workList.length; index += 1) {
    const workListElement = workList[index];
    const { connector, work } = workListElement;
    let stix_objects = null;
    const stixResolutionMode = connector.enrichment_resolution ?? 'stix_bundle';
    const stix_entity = await stixLoaders.loadById();
    if (stixResolutionMode === 'stix_bundle') {
      stix_objects = await stixLoaders.bundleById();
    }
    const message = {
      internal: {
        work_id: work.id, // Related action for history
        applicant_id: null, // No specific user asking for the import
        draft_id: draftContext ?? null,
        trigger, // create | update
        mode: 'auto'
      },
      event: {
        event_type: CONNECTOR_INTERNAL_ENRICHMENT,
        entity_id: elementStandardId,
        entity_type: element.entity_type,
        stix_entity,
        stix_objects
      },
    };
    await pushToConnector(connector.internal_id, message);
  }
  return workList;
};

export const updateEntityAutoEnrichment = async (context, user, element, scope, stixLoaders) => {
  if (!isStixObject(element.entity_type)) {
    return null; // we only enrich stix core objects
  }
  if (element.auto_enrichment_disable) {
    return null;
  }
  // Get the list of compatible connectors
  const targetConnectors = await findConnectorsForElementEnrichment(context, user, element, scope, { mode: 'update' });
  return publishEventToConnectors(context, user, element, targetConnectors, 'update', stixLoaders);
};

export const createEntityAutoEnrichment = async (context, user, element, scope, stixLoaders) => {
  if (!isStixObject(element.entity_type)) {
    return null; // we only enrich stix core objects
  }
  if (element.auto_enrichment_disable) {
    return null;
  }
  // Get the list of compatible connectors
  const targetConnectors = await findConnectorsForElementEnrichment(context, user, element, scope, { mode: 'creation' });
  return publishEventToConnectors(context, user, element, targetConnectors, 'create', stixLoaders);
};

const findConnectorsForElementEnrichment = async (context, user, element, scope, opts = {}) => {
  const connectors = await getEntitiesListFromCache(context, user, ENTITY_TYPE_CONNECTOR);
  return filterConnectorsForElementEnrichment(context, connectors, element, scope, opts);
};

export const filterConnectorsForElementEnrichment = async (context, connectors, element, scope, opts = {}) => {
  const { mode = 'creation' } = opts;
  // first filter active & enrichment connectors only
  const activeConnectors = connectors.filter((conn) => conn.active === true && conn.connector_type === CONNECTOR_INTERNAL_ENRICHMENT);
  const targetConnectors = [];
  for (let i = 0; i < activeConnectors.length; i += 1) {
    const conn = activeConnectors[i];
    const scopeMatch = scope ? (conn.connector_scope ?? []).some((s) => s.toLowerCase() === scope.toLowerCase()) : true;
    let autoTrigger = false;
    if (mode === 'creation') {
      autoTrigger = conn.connector_trigger_filters ? await isStixMatchConnectorFilter(context, element, conn.connector_trigger_filters) : conn.auto === true;
    } else if (mode === 'update') {
      autoTrigger = conn.auto_update;
    }
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
  const stix = convertStoreToStix_2_1(element);
  return isStixMatchFilterGroup(context, SYSTEM_USER, stix, jsonFilters);
};
