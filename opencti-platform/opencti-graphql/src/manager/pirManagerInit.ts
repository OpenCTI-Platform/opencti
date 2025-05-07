import { type BasicStoreEntityPIR, ENTITY_TYPE_PIR, type ParsedPIR } from '../modules/pir/pir-types';
import { type ManagerDefinition, type ManagerStreamScheduler } from './managerModule';
import type { DataEvent, SseEvent } from '../types/event';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { STIX_TYPE_RELATION } from '../schema/general';
import { flagSource, parsePir, updatePirDependencies } from '../modules/pir/pir-utils';
import { patchAttribute } from '../database/middleware';
import { logApp } from '../config/conf';
import { isStixMatchFilterGroup } from '../utils/filtering/filtering-stix/stix-filtering';
import { RELATION_IN_PIR } from '../schema/stixRefRelationship';
import type { AuthContext } from '../types/user';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { FunctionalError } from '../config/errors';
import { internalLoadById } from '../database/middleware-loader';
import type { BasicStoreCommon } from '../types/store';
import { EditOperation } from '../generated/graphql';

const PIR_MANAGER_ID = 'PIR_MANAGER';
const PIR_MANAGER_LABEL = 'PIR Manager';
const PIR_MANAGER_CONTEXT = 'pir_manager';

const PIR_MANAGER_INTERVAL = 10000; // TODO PIR: use config instead
const PIR_MANAGER_LOCK_KEY = 'pir_manager_lock'; // TODO PIR: use config instead
const PIR_MANAGER_ENABLED = true; // TODO PIR: use config instead

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

  const source = await internalLoadById<BasicStoreCommon>(context, SYSTEM_USER, sourceId);
  const sourceFlagged = (source[RELATION_IN_PIR] ?? []).includes(pir.id);
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

const newPirManagerHandler = async (
  pir: BasicStoreEntityPIR,
  streamEvents: Array<SseEvent<DataEvent>>,
  lastEventId: string // TODO PIR: use this to not missing messages
) => {
  const logPrefix = `[POC PIR ${pir.name}]`;
  const parsedPir = parsePir(pir);
  const context = executionContext(PIR_MANAGER_CONTEXT);

  // Keep only events for relationships.
  const eventsContent = streamEvents
    .map((e) => e.data)
    .filter((e) => e.data.type === STIX_TYPE_RELATION);

  if (eventsContent.length > 0) {
    // Check every event received to see if it matches the PIR.
    await Promise.all(eventsContent.map(async ({ data, type }) => {
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
          switch (type) {
            case 'create':
              await onRelationCreated(context, data, pir, matchingCriteria);
              break;
            case 'delete':
              console.log(`${logPrefix} new delete event`, { data });
              break;
            default: // Nothing to do.
          }
        }
      }
    }));
  }

  // Save the last processed event
  logApp.debug(`[OPENCTI-MODULE] PIR Manager ${pir.name} - Saving last event processed: ${lastEventId}`);
  await patchAttribute(context, SYSTEM_USER, pir.id, ENTITY_TYPE_PIR, { lastEventId });
};

export const createPirManager = (pir: BasicStoreEntityPIR): ManagerDefinition => {
  const id = `${PIR_MANAGER_ID}__${pir.id}`;
  const label = `${PIR_MANAGER_LABEL} ${pir.id}`;
  const lockKey = `${PIR_MANAGER_LOCK_KEY}__${pir.id}`;

  const handler: ManagerStreamScheduler['handler'] = (...args) => {
    return newPirManagerHandler(pir, ...args);
  };

  return {
    id,
    label,
    executionContext: PIR_MANAGER_CONTEXT,
    enabledByConfig: PIR_MANAGER_ENABLED,
    enabled(): boolean {
      return this.enabledByConfig;
    },
    enabledToStart(): boolean {
      return this.enabledByConfig;
    },
    streamSchedulerHandler: {
      handler,
      streamProcessorStartFrom: () => pir.lastEventId ?? 'live',
      interval: PIR_MANAGER_INTERVAL,
      lockKey,
      streamOpts: {
        withInternal: true
      }
    }
  };
};
