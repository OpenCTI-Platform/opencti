import { type ManagerDefinition, registerManager } from './managerModule';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { FAKE_PIR, type PIR } from '../modules/pir/pir.fake';
import type { DataEvent, SseEvent } from '../types/event';
import { isStixMatchFilterGroup } from '../utils/filtering/filtering-stix/stix-filtering';
import { ABSTRACT_STIX_CORE_OBJECT, STIX_TYPE_RELATION } from '../schema/general';
import { stixObjectOrRelationshipAddRefRelation } from '../domain/stixObjectOrStixRelationship';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { RELATION_IN_PIR } from '../schema/stixRefRelationship';
import type { AuthContext } from '../types/user';
import { FunctionalError } from '../config/errors';

const PIR_MANAGER_ID = 'PIR_MANAGER';
const PIR_MANAGER_LABEL = 'PIR Manager';
const PIR_MANAGER_CONTEXT = 'pir_manager';

const PIR_MANAGER_INTERVAL = 10000; // TODO PIR: use config instead
const PIR_MANAGER_LOCK_KEY = 'pir_manager_lock'; // TODO PIR: use config instead
const PIR_MANAGER_ENABLED = true; // TODO PIR: use config instead

/**
 * Flag the source of the relationship by creating a meta relationship 'in-pir'
 * between the source and the PIR.
 *
 * @param context To be able to create the relationship.
 * @param source STIX of the source
 * @param pirId ID of the PIR.
 */
const flagSource = async (context: AuthContext, source: any, pirId: string) => {
  const sourceId = source.extensions?.[STIX_EXT_OCTI]?.source_ref;
  const sourceType = source.extensions?.[STIX_EXT_OCTI]?.source_type;
  if (!sourceId || !sourceType) {
    throw FunctionalError(`Cannot flag the source with PIR ${pirId}, no sourceId or sourceType`);
  }

  const addRefInput = {
    relationship_type: RELATION_IN_PIR,
    toId: pirId,
  };
  const ref = await stixObjectOrRelationshipAddRefRelation(
    context,
    SYSTEM_USER,
    sourceId,
    addRefInput,
    ABSTRACT_STIX_CORE_OBJECT
  );
  console.log('[POC PIR] Meta Ref relation created', { ref });
};

const onRelationCreated = async (context: AuthContext, data: any, pir: PIR) => {
  // - if source not flagged
  // create rel
  // - if source already flagged
  // update the score and the matching Criteria
  console.log('[POC PIR] Event create matching', { data });
  await flagSource(context, data, pir.id);
};

const onRelationDeleted = async (context: AuthContext, data: any, pir: PIR) => {
  console.log('[POC PIR] Event delete matching', { data });
  // eventually remove the entity flag or update matching criteria
};

/**
 * Handler called every {PIR_MANAGER_INTERVAL} with new events received.
 * @param streamEvents The new events received since last call to the handler.
 */
const pirManagerHandler = async (streamEvents: Array<SseEvent<DataEvent>>) => {
  const context = executionContext(PIR_MANAGER_CONTEXT);
  const allPIR = [FAKE_PIR]; // TODO PIR: fetch real ones from elastic.

  // TODO PIR: add PIR filters id in Resolved Filters cache

  // Keep only events for relationships
  const eventsContent = streamEvents
    .map((e) => e.data)
    .filter((e) => e.data.type === STIX_TYPE_RELATION);

  if (eventsContent.length > 0) {
    // Loop through all PIR one by one.
    await Promise.all(allPIR.map(async (pir) => {
      // Check every event received to see if it matches the PIR.
      await Promise.all(eventsContent.map(async (event) => {
        const { data } = event;
        // check filters
        const eventMatchesPirFilters = await isStixMatchFilterGroup(context, SYSTEM_USER, data, pir.pirFilters);
        if (eventMatchesPirFilters) {
          // check criteria
          const matchingCriteria: typeof pir.pirCriteria = [];
          // eslint-disable-next-line no-restricted-syntax
          for (const pirCriterion of pir.pirCriteria) {
            const isMatch = await isStixMatchFilterGroup(context, SYSTEM_USER, data, pirCriterion.filters);
            if (isMatch) {
              matchingCriteria.push(pirCriterion);
            }
          }
          if (matchingCriteria.length > 0) {
            console.log('[POC PIR] Matching event', { event, matchingCriteria });
            // If the event matches PIR, do the right thing depending on the type of event.
            switch (event.type) {
              case 'create':
                await onRelationCreated(context, data, pir);
                break;
              case 'delete':
                await onRelationDeleted(context, data, pir);
                break;
              default: // nothing to do
            }
          }
        }
      }));
    }));
  } else {
    // TODO PIR: remove this else when no need for debugging anymore.
    // console.log('[POC PIR] Nothing to do, get some rest');
  }
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
  streamSchedulerHandler: {
    handler: pirManagerHandler,
    streamProcessorStartFrom: () => 'live',
    interval: PIR_MANAGER_INTERVAL,
    lockKey: PIR_MANAGER_LOCK_KEY,
    streamOpts: {
      withInternal: true
    }
  }
};
// Automatically register manager on start.
registerManager(PIR_MANAGER_DEFINITION);
