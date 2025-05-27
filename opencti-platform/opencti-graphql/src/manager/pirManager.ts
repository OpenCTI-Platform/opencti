import { type ManagerDefinition, registerManager } from './managerModule';
import { executionContext, SYSTEM_USER } from '../utils/access';
import type { DataEvent, SseEvent } from '../types/event';
import { isStixMatchFilterGroup } from '../utils/filtering/filtering-stix/stix-filtering';
import { ABSTRACT_STIX_CORE_OBJECT, STIX_TYPE_RELATION } from '../schema/general';
import { stixObjectOrRelationshipDeleteRefRelation } from '../domain/stixObjectOrStixRelationship';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { RELATION_IN_PIR } from '../schema/stixRefRelationship';
import type { AuthContext } from '../types/user';
import { FunctionalError } from '../config/errors';
import { findById } from '../domain/stixCoreObject';
import { listRelationsPaginated } from '../database/middleware-loader';
import { type BasicStoreEntityPIR, ENTITY_TYPE_PIR, type ParsedPIR, type PirDependency } from '../modules/pir/pir-types';
import { EditOperation } from '../generated/graphql';
import { flagSource, parsePir, updatePirDependencies } from '../modules/pir/pir-utils';
import { getEntitiesListFromCache } from '../database/cache';
import { createRedisClient, fetchStreamEventsRange } from '../database/redis';
import { updatePir } from '../modules/pir/pir-domain';

const PIR_MANAGER_ID = 'PIR_MANAGER';
const PIR_MANAGER_LABEL = 'PIR Manager';
const PIR_MANAGER_CONTEXT = 'pir_manager';

const PIR_MANAGER_INTERVAL = 6000; // TODO PIR: use config instead
const PIR_MANAGER_LOCK_KEY = 'pir_manager_lock'; // TODO PIR: use config instead
const PIR_MANAGER_ENABLED = true; // TODO PIR: use config instead

// region relationship create/delete
/**
 * Called when an event of create new relationship matches a PIR criteria.
 * If the source of the relationship is already flagged update its dependencies,
 * otherwise create a new meta relationship between the source and the PIR.
 *
 * @param context To be able to call engine.
 * @param relationship The caught relationship matching the PIR.
 * @param pir The PIR matched by the relationship.
 * @param matchingCriteria The criteria that match.
 */
const onRelationCreated = async (
  context: AuthContext,
  relationship: any,
  pir: BasicStoreEntityPIR,
  matchingCriteria: ParsedPIR['pirCriteria']
) => {
  const sourceId: string = relationship.extensions?.[STIX_EXT_OCTI]?.source_ref;
  if (!sourceId) throw FunctionalError(`Cannot flag the source with PIR ${pir.id}, no source id found`);
  const relationshipId: string = relationship.extensions?.[STIX_EXT_OCTI]?.id;
  if (!relationshipId) throw FunctionalError(`Cannot flag the source with PIR ${pir.id}, no relationship id found`);

  const source = await findById(context, SYSTEM_USER, sourceId);
  const sourceFlagged = (source[RELATION_IN_PIR] ?? []).length > 0;
  console.log('[POC PIR] Event create matching', { source, relationship, matchingCriteria });

  const pirDependencies = matchingCriteria.map((criterion) => ({
    relationship_id: relationshipId,
    criterion: {
      ...criterion,
      filters: JSON.stringify(criterion.filters)
    },
  }));

  if (sourceFlagged) {
    console.log('[POC PIR] Source already flagged');
    await updatePirDependencies(context, sourceId, pir, pirDependencies, EditOperation.Add);
    console.log('[POC PIR] Meta Ref relation updated');
  } else {
    console.log('[POC PIR] Source NOT flagged');
    await flagSource(context, sourceId, pir, pirDependencies);
    console.log('[POC PIR] Meta Ref relation created');
  }
};

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
  const rels = await listRelationsPaginated(context, SYSTEM_USER, RELATION_IN_PIR, { fromId: sourceId, toId: pir.id }); // TODO PIR don't use pagination
  // eslint-disable-next-line no-restricted-syntax
  for (const rel of rels.edges) {
    const relDependencies = (rel as any).node.pir_dependencies as PirDependency[];
    const newRelDependencies = relDependencies.filter((dep) => dep.relationship_id !== relationshipId);
    console.log('newRelDependencies', newRelDependencies);
    if (newRelDependencies.length === 0) {
      // delete the rel between source and PIR
      await stixObjectOrRelationshipDeleteRefRelation(context, SYSTEM_USER, sourceId, pir.id, RELATION_IN_PIR, ABSTRACT_STIX_CORE_OBJECT);
      console.log('[POC PIR] PIR rel deleted');
    } else if (newRelDependencies.length < relDependencies.length) {
      // update dependencies
      await updatePirDependencies(context, sourceId, pir, newRelDependencies);
      console.log('[POC PIR] PIR rel updated', { newRelDependencies });
    } // nothing to do
  }
};
// endregion

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
      const eventMatchesPirFilters = await isStixMatchFilterGroup(context, SYSTEM_USER, data, parsedPir.pirFilters);
      if (eventMatchesPirFilters) {
        // Check PIR criteria one by one (because we need to know which one matches or not).
        const matchingCriteria: typeof parsedPir.pirCriteria = [];
        // eslint-disable-next-line no-restricted-syntax
        for (const pirCriterion of parsedPir.pirCriteria) {
          const isMatch = await isStixMatchFilterGroup(context, SYSTEM_USER, data, pirCriterion.filters);
          if (isMatch) {
            matchingCriteria.push(pirCriterion);
          }
        }
        // If the event matches PIR, do the right thing depending on the type of event.
        if (matchingCriteria.length > 0) {
          switch (event.type) {
            case 'create':
              await onRelationCreated(context, data, pir, matchingCriteria);
              break;
            case 'delete':
              await onRelationDeleted(context, data, pir);
              break;
            default: // Nothing to do.
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
  const allPIR = await getEntitiesListFromCache<BasicStoreEntityPIR>(context, SYSTEM_USER, ENTITY_TYPE_PIR);

  // Loop through all PIR one by one.
  await Promise.all(allPIR.map(async (pir) => {
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
      await updatePir(context, SYSTEM_USER, pir.id, [{ key: 'lastEventId', value: [lastEventId] }]);
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
