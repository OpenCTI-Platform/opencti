import { type ManagerDefinition, registerManager } from './managerModule';
import { executionContext, PIR_MANAGER_USER } from '../utils/access';
import type { DataEvent, SseEvent } from '../types/event';
import { isStixMatchFilterGroup } from '../utils/filtering/filtering-stix/stix-filtering';
import { ABSTRACT_STIX_CORE_OBJECT, STIX_TYPE_RELATION } from '../schema/general';
import { stixObjectOrRelationshipDeleteRefRelation } from '../domain/stixObjectOrStixRelationship';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { RELATION_IN_PIR } from '../schema/stixRefRelationship';
import type { AuthContext } from '../types/user';
import { FunctionalError } from '../config/errors';
import { listRelationsPaginated } from '../database/middleware-loader';
import { type BasicStoreEntityPIR, ENTITY_TYPE_PIR, type ParsedPIRCriterion, type PirDependency } from '../modules/pir/pir-types';
import { parsePir, updatePirDependencies } from '../modules/pir/pir-utils';
import { getEntitiesListFromCache } from '../database/cache';
import { createRedisClient, fetchStreamEventsRange } from '../database/redis';
import { updatePir } from '../modules/pir/pir-domain';
import { pushToWorkerForConnector } from '../database/rabbitmq';
import { connectorIdFromIngestId } from '../domain/connector';
import { createWork } from '../domain/work';
import { ConnectorType } from '../generated/graphql';
import convertEntityPIRToStix from '../modules/pir/pir-converter';
import { buildStixBundle } from '../database/stix-2-1-converter';

const PIR_MANAGER_ID = 'PIR_MANAGER';
const PIR_MANAGER_LABEL = 'PIR Manager';
const PIR_MANAGER_CONTEXT = 'pir_manager';

const PIR_MANAGER_INTERVAL = 6000; // TODO PIR: use config instead
const PIR_MANAGER_LOCK_KEY = 'pir_manager_lock'; // TODO PIR: use config instead
const PIR_MANAGER_ENABLED = true; // TODO PIR: use config instead

/**
 * Called when an event of delete a relationship matches a PIR criteria.
 *
 * @param context To be able to call engine.
 * @param relationship The caught relationship matching the PIR.
 * @param pir The PIR matched by the relationship.
 */
const onRelationDeleted = async (context: AuthContext, relationship: any, pir: BasicStoreEntityPIR) => {
  console.log('[POC PIR] Event delete matching', { relationship, pir });
  // fetch rel between object and pir
  const sourceId: string = relationship.extensions?.[STIX_EXT_OCTI]?.source_ref;
  if (!sourceId) throw FunctionalError(`Cannot flag the source with PIR ${pir.id}, no source id found`);
  const relationshipId: string = relationship.extensions?.[STIX_EXT_OCTI]?.id;
  if (!relationshipId) throw FunctionalError(`Cannot flag the source with PIR ${pir.id}, no relationship id found`);
  const rels = await listRelationsPaginated(context, PIR_MANAGER_USER, RELATION_IN_PIR, { fromId: sourceId, toId: pir.id }); // TODO PIR don't use pagination
  // eslint-disable-next-line no-restricted-syntax
  for (const rel of rels.edges) {
    const relDependencies = (rel as any).node.pir_dependencies as PirDependency[];
    const newRelDependencies = relDependencies.filter((dep) => dep.relationship_id !== relationshipId);
    console.log('newRelDependencies', newRelDependencies);
    if (newRelDependencies.length === 0) {
      // delete the rel between source and PIR
      await stixObjectOrRelationshipDeleteRefRelation(context, PIR_MANAGER_USER, sourceId, pir.id, RELATION_IN_PIR, ABSTRACT_STIX_CORE_OBJECT);
      console.log('[POC PIR] PIR rel deleted');
    } else if (newRelDependencies.length < relDependencies.length) {
      // update dependencies
      await updatePirDependencies(context, PIR_MANAGER_USER, sourceId, pir.id, newRelDependencies);
      console.log('[POC PIR] PIR rel updated', { newRelDependencies });
    } // nothing to do
  }
};
// endregion

const addPirDependencyToQueue = async (
  context: AuthContext,
  pir: BasicStoreEntityPIR,
  relationshipId: string,
  sourceId: string,
  matchingCriteria: ParsedPIRCriterion[],
) => {
  const connectorId = connectorIdFromIngestId(pir.id);
  const work: any = await createWork(
    context,
    PIR_MANAGER_USER,
    { internal_id: connectorId, connector_type: ConnectorType.InternalIngestionPir },
    `Add dependency ${matchingCriteria} for ${sourceId} in pir ${pir.name}`
  );
  const stixPir = convertEntityPIRToStix(pir);
  stixPir.extensions[STIX_EXT_OCTI].opencti_operation = 'add_pir_dependency';
  const formattedMatchingCriteria = matchingCriteria.map((c) => ({
    ...c,
    filters: JSON.stringify(c.filters),
  }));
  const pirBundle = {
    ...stixPir,
    input: { relationshipId, sourceId, matchingCriteria: formattedMatchingCriteria },
  };
  const stixPirBundle = buildStixBundle([pirBundle]);
  const jsonBundle = JSON.stringify(stixPirBundle);
  const content = Buffer.from(jsonBundle, 'utf-8').toString('base64');
  console.log('jsonBundle', jsonBundle);
  const message = {
    type: 'bundle',
    applicant_id: PIR_MANAGER_USER.id,
    work_id: work.id,
    update: true,
    content,
  };
  await pushToWorkerForConnector(connectorId, message);
};

const processStreamEventsForPir = (context:AuthContext, pir: BasicStoreEntityPIR) => {
  const parsedPir = parsePir(pir);

  return async (streamEvents: Array<SseEvent<DataEvent>>) => {
    const eventsContent = streamEvents
      .map((e) => e.data)
      .filter((e) => e.data.type === STIX_TYPE_RELATION);

    if (eventsContent.length > 0) {
      console.log(`PIR ${pir.name}: events`, { streamEvents });
    }

    // Check every event received to see if it matches the PIR.
    await Promise.all(eventsContent.map(async (event) => {
      const { data } = event;
      // Check PIR filters (filters that do not count as criteria).
      const eventMatchesPirFilters = await isStixMatchFilterGroup(context, PIR_MANAGER_USER, data, parsedPir.pirFilters);
      if (eventMatchesPirFilters) {
        // Check PIR criteria one by one (because we need to know which one matches or not).
        const matchingCriteria: typeof parsedPir.pirCriteria = [];
        // eslint-disable-next-line no-restricted-syntax
        for (const pirCriterion of parsedPir.pirCriteria) {
          const isMatch = await isStixMatchFilterGroup(context, PIR_MANAGER_USER, data, pirCriterion.filters);
          if (isMatch) {
            matchingCriteria.push(pirCriterion);
          }
        }
        // If the event matches PIR, do the right thing depending on the type of event.
        if (matchingCriteria.length > 0) {
          const sourceId: string = data.extensions?.[STIX_EXT_OCTI]?.source_ref;
          if (!sourceId) throw FunctionalError(`Cannot flag the source with PIR ${pir.id}, no source id found`);
          const relationshipId: string = data.extensions?.[STIX_EXT_OCTI]?.id;
          if (!relationshipId) throw FunctionalError(`Cannot flag the source with PIR ${pir.id}, no relationship id found`);
          switch (event.type) {
            case 'create':
              // send addPirDependency to queue
              await addPirDependencyToQueue(context, pir, relationshipId, sourceId, matchingCriteria);
              break;
            case 'delete':
              await onRelationDeleted(context, data, pir);
              break;
            default: // Nothing to do. // TODO PIR update logic
          }
        }
      }
    }));
  };
};

/**
 * Handler called every {PIR_MANAGER_INTERVAL} and studying a range of stream events.
 */
const pirManagerHandler = async () => {
  const redisClient = await createRedisClient(PIR_MANAGER_LABEL, false);
  const context = executionContext(PIR_MANAGER_CONTEXT);
  const allPIR = await getEntitiesListFromCache<BasicStoreEntityPIR>(context, PIR_MANAGER_USER, ENTITY_TYPE_PIR); // TODO PIR cache ?

  // Loop through all PIR one by one.
  await Promise.all(allPIR.map(async (pir) => { // TODO PIR blue promise (gérer le max concurrence des promesses pouvant etre faites en parallèle)
    // Fetch stream events since last event id caught by the PIR.
    console.log(`PIR ${pir.name}: from ${pir.lastEventId ?? '$'}`);
    const { lastEventId } = await fetchStreamEventsRange(
      redisClient,
      pir.lastEventId,
      processStreamEventsForPir(context, pir),
      { streamBatchTime: PIR_MANAGER_INTERVAL }
    );
    // Update pir last event id.
    if (lastEventId !== pir.lastEventId) {
      await updatePir(context, PIR_MANAGER_USER, pir.id, [{ key: 'lastEventId', value: [lastEventId] }]);
    }
  }));
};

// Configuration of the manager.
const PIR_MANAGER_DEFINITION: ManagerDefinition = {
  id: PIR_MANAGER_ID,
  label: PIR_MANAGER_LABEL,
  executionContext: PIR_MANAGER_CONTEXT,
  enabledByConfig: PIR_MANAGER_ENABLED,
  enabled(): boolean {
    return this.enabledByConfig;
  },
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  cronSchedulerHandler: {
    handler: pirManagerHandler,
    interval: PIR_MANAGER_INTERVAL,
    lockKey: PIR_MANAGER_LOCK_KEY,
  }
};
// Automatically register manager on start.
registerManager(PIR_MANAGER_DEFINITION);
