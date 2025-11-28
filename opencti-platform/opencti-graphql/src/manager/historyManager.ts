import * as R from 'ramda';
import { clearIntervalAsync, setIntervalAsync, type SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import * as jsonpatch from 'fast-json-patch';
import { createStreamProcessor } from '../database/stream/stream-handler';
import { type StreamProcessor } from '../database/stream/stream-utils';
import { lockResources } from '../lock/master-lock';
import conf, { booleanConf, ENABLED_DEMO_MODE, logApp } from '../config/conf';
import { EVENT_TYPE_UPDATE, INDEX_HISTORY, isEmptyField, isNotEmptyField } from '../database/utils';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { executionContext, REDACTED_USER, SYSTEM_USER } from '../utils/access';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import type { Change, SseEvent, StreamDataEvent, UpdateEvent } from '../types/event';
import { utcDate } from '../utils/format';
import { elIndexElements } from '../database/engine';
import type { StixRelation, StixSighting } from '../types/stix-2-1-sro';
import { internalFindByIds, topEntitiesList } from '../database/middleware-loader';
import type { BasicRuleEntity, BasicStoreBase, BasicStoreEntity } from '../types/store';
import { BASE_TYPE_ENTITY, STIX_TYPE_RELATION, STIX_TYPE_SIGHTING } from '../schema/general';
import { generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_HISTORY, ENTITY_TYPE_PIR_HISTORY } from '../schema/internalObject';
import type { StixId } from '../types/stix-2-1-common';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { getEntitiesMapFromCache } from '../database/cache';
import type { AuthContext } from '../types/user';
import { FilterMode, FilterOperator, OrderingMode } from '../generated/graphql';
import { extractStixRepresentative } from '../database/stix-representative';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { RELATION_IN_PIR } from '../schema/internalRelationship';

const HISTORY_ENGINE_KEY = conf.get('history_manager:lock_key');
const HISTORY_WITH_INFERENCES = booleanConf('history_manager:include_inferences', false);
const SCHEDULE_TIME = 10000;

interface HistoryContext {
  id: string;
  entity_type: string;
  entity_name: string;
  message: string;
  from_id?: string | undefined;
  to_id?: string | undefined;
  commit?: string | undefined;
  external_references?: Array<string>;
  creator_ids?: Array<string>;
  labels_ids?: Array<string>;
  created_by_ref_id?: string;
  marking_definitions?: Array<string>;
  pir_ids?: Array<string>;
  pir_score?: number;
  pir_match_from?: boolean;
  changes?: Array<Change>;
}

export interface HistoryData extends BasicStoreEntity {
  event_type: string;
  timestamp: string;
  entity_type: 'History';
  user_id: string | undefined;
  applicant_id: string | undefined;
  context_data: HistoryContext;
}

/**
 * Function to resolve granted_refs when granted_refs_ids are not present (have been added on nov 2024)
 * This is needed to be able to process older events, and will be removed after a year
 * @param context
 * @param events
 */
export const resolveGrantedRefsIds = async (context: AuthContext, events: Array<SseEvent<StreamDataEvent>>) => {
  const grantedRefsToResolve: StixId[] = [];
  events.forEach((event) => {
    const stix = event.data.data;
    const eventGrantedRefsIds = (stix.extensions[STIX_EXT_OCTI].granted_refs_ids ?? []);
    const eventGrantedRefsStandardIds = (stix.extensions[STIX_EXT_OCTI].granted_refs ?? []);
    if (eventGrantedRefsIds.length === 0 && eventGrantedRefsStandardIds.length > 0) {
      grantedRefsToResolve.push(...eventGrantedRefsStandardIds);
    }
  });
  const organizationByIdsMap = new Map<string, string>();
  if (grantedRefsToResolve.length === 0) {
    return organizationByIdsMap; // nothing to resolve
  }
  const organizationsByIds = await internalFindByIds(context, SYSTEM_USER, R.uniq(grantedRefsToResolve), {
    type: ENTITY_TYPE_IDENTITY_ORGANIZATION,
    baseData: true,
    baseFields: ['standard_id', 'internal_id'],
  }) as BasicStoreBase[];
  organizationsByIds.forEach((o) => {
    organizationByIdsMap.set(o.standard_id, o.internal_id);
  });
  return organizationByIdsMap;
};

export const generatePirContextData = (event: SseEvent<StreamDataEvent>): Partial<HistoryContext> => {
  let pir_ids: string[] = [];
  let from_id: string | undefined;
  let to_id: string | undefined;
  let pir_match_from = false;
  let pir_score: number | undefined;
  // Listened events: stix core relationships, pir relationships, 'contains' flagged entities
  const eventData = event.data.data;
  // 1. detect stix core relationships
  if (eventData.type === 'relationship') {
    const relationEvent = eventData as StixRelation;
    if (isStixCoreRelationship(relationEvent.relationship_type)) {
      const extensions = relationEvent.extensions[STIX_EXT_OCTI];
      from_id = extensions.source_ref;
      to_id = extensions.target_ref;
      if ((extensions.source_ref_pir_refs ?? []).length > 0) {
        pir_match_from = true;
        pir_ids = extensions.source_ref_pir_refs ?? [];
      } else if ((extensions.target_ref_pir_refs ?? []).length > 0) {
        pir_ids = extensions.target_ref_pir_refs ?? [];
      }
    }
  } else if (eventData.type === 'internal-relationship'
    && eventData.extensions[STIX_EXT_OCTI].type === RELATION_IN_PIR
  ) { // 2. detect in-pir relations
    const relationEvent = eventData as StixRelation;
    const extensions = relationEvent.extensions[STIX_EXT_OCTI];
    from_id = extensions.source_ref;
    pir_ids = [extensions.target_ref];
    pir_score = extensions.pir_score;
  } else if (event.event === 'update' && (event.data as UpdateEvent).context.patch) {
    const updateEvent: UpdateEvent = event.data as UpdateEvent;
    // 3. detect 'contains' rel
    const pirIds = updateEvent.context.pir_ids ?? [];
    if (pirIds.length > 0) {
      pir_ids = pirIds;
    }
  }
  return {
    pir_ids,
    from_id,
    to_id,
    pir_match_from,
    pir_score,
  };
};

export const buildHistoryElementsFromEvents = async (context: AuthContext, events: Array<SseEvent<StreamDataEvent>>) => {
  // load all markings to resolve object_marking_refs
  const markingsById = await getEntitiesMapFromCache<BasicRuleEntity>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  // resolve granted_refs
  const grantedRefsResolved = await resolveGrantedRefsIds(context, events);
  // Build the history data
  return events.map((event) => {
    const [time] = event.id.split('-');
    const eventDate = utcDate(parseInt(time, 10)).toISOString();
    const stix = event.data.data;
    const eventMarkingRefs = (stix.object_marking_refs ?? [])
      .map((stixId) => markingsById.get(stixId)?.internal_id)
      .filter((o) => isNotEmptyField(o)) as string[];
    let eventGrantedRefsIds: string[] = (stix.extensions[STIX_EXT_OCTI].granted_refs_ids ?? []);
    const eventGrantedRefsStandardIds = (stix.extensions[STIX_EXT_OCTI].granted_refs ?? []);
    if (eventGrantedRefsIds.length === 0 && eventGrantedRefsStandardIds.length > 0) {
      eventGrantedRefsIds = eventGrantedRefsStandardIds
        .map((stixId) => grantedRefsResolved.get(stixId))
        .filter((o) => isNotEmptyField(o)) as string[];
    }
    let contextData: HistoryContext = {
      id: stix.extensions[STIX_EXT_OCTI].id,
      message: event.data.message,
      entity_type: stix.extensions[STIX_EXT_OCTI].type,
      entity_name: extractStixRepresentative(stix),
      creator_ids: stix.extensions[STIX_EXT_OCTI].creator_ids,
      labels_ids: stix.extensions[STIX_EXT_OCTI].labels_ids,
      created_by_ref_id: stix.extensions[STIX_EXT_OCTI].created_by_ref_id,
    };
    if (event.data.type === EVENT_TYPE_UPDATE) {
      const updateEvent: UpdateEvent = event.data as UpdateEvent;
      contextData.commit = updateEvent.commit?.message;
      contextData.external_references = updateEvent.commit?.external_references ?? [];
      // Previous markings must be kept to ensure data visibility restrictions
      const { newDocument: previous } = jsonpatch.applyPatch(structuredClone(stix), updateEvent.context.reverse_patch);
      const previousMarkingRefs = (previous.object_marking_refs ?? [])
        .map((stixId) => markingsById.get(stixId)?.internal_id)
        .filter((o) => isNotEmptyField(o)) as string[];
      eventMarkingRefs.push(...previousMarkingRefs);
      // Get related restrictions (e.g. markings of added objects in a container)
      if (updateEvent.context.related_restrictions) {
        const relatedMarkings = updateEvent.context.related_restrictions.markings ?? [];
        eventMarkingRefs.push(...relatedMarkings);
      }
      // add changes
      contextData.changes = updateEvent.context.changes;
    }
    if (stix.type === STIX_TYPE_RELATION) {
      const rel: StixRelation = stix as StixRelation;
      contextData.from_id = rel.extensions[STIX_EXT_OCTI].source_ref;
      contextData.to_id = rel.extensions[STIX_EXT_OCTI].target_ref;
      // Markings of the source/target must be taken into account to ensure data visibility restrictions
      eventMarkingRefs.push(...(rel.extensions[STIX_EXT_OCTI].source_ref_object_marking_refs ?? []));
      eventMarkingRefs.push(...(rel.extensions[STIX_EXT_OCTI].target_ref_object_marking_refs ?? []));
    }
    if (stix.type === STIX_TYPE_SIGHTING) {
      const sighting: StixSighting = stix as StixSighting;
      contextData.from_id = sighting.extensions[STIX_EXT_OCTI].sighting_of_ref;
      contextData.to_id = R.head(sighting.extensions[STIX_EXT_OCTI].where_sighted_refs);
      // Markings of the source/target must be taken into account to ensure data visibility restrictions
      eventMarkingRefs.push(...(sighting.extensions[STIX_EXT_OCTI].sighting_of_ref_object_marking_refs ?? []));
      eventMarkingRefs.push(...(sighting.extensions[STIX_EXT_OCTI].where_sighted_refs_object_marking_refs ?? []));
    }
    if (R.uniq(eventMarkingRefs).length > 0) {
      contextData.marking_definitions = R.uniq(eventMarkingRefs).map((n) => markingsById.get(n)?.definition ?? 'Unknown');
    }
    const activityDate = utcDate(eventDate).toDate();
    const standardId = generateStandardId(ENTITY_TYPE_HISTORY, { internal_id: event.id }) as StixId;
    // add Pir context data for concerned events
    contextData = {
      ...contextData,
      ...generatePirContextData(event),
    };
    // history type is different for events concerning pir relationships
    const eventData = event.data.data;
    const entity_type = eventData.type === 'internal-relationship' && eventData.extensions[STIX_EXT_OCTI].type === RELATION_IN_PIR
      ? ENTITY_TYPE_PIR_HISTORY
      : ENTITY_TYPE_HISTORY;
    // return history object
    return {
      _index: INDEX_HISTORY,
      internal_id: event.id,
      standard_id: standardId,
      base_type: BASE_TYPE_ENTITY,
      created_at: activityDate,
      updated_at: activityDate,
      entity_type,
      event_type: 'mutation',
      event_scope: event.event,
      user_id: ENABLED_DEMO_MODE ? REDACTED_USER.id : event.data.origin?.user_id,
      group_ids: event.data.origin?.group_ids ?? [],
      organization_ids: event.data.origin?.organization_ids ?? [],
      applicant_id: event.data.origin?.applicant_id,
      user_metadata: event.data.origin?.user_metadata,
      timestamp: eventDate,
      context_data: contextData,
      restricted_members: stix.extensions[STIX_EXT_OCTI].authorized_members,
      'rel_object-marking.internal_id': R.uniq(eventMarkingRefs),
      'rel_granted.internal_id': R.uniq(eventGrantedRefsIds),
    };
  });
};

const eventsApplyHandler = async (context: AuthContext, events: Array<SseEvent<StreamDataEvent>>) => {
  if (isEmptyField(events) || events.length === 0) {
    return;
  }
  // Build the history data
  const historyElements = await buildHistoryElementsFromEvents(context, events);
  // Bulk the history data insertions
  await elIndexElements(context, SYSTEM_USER, ENTITY_TYPE_HISTORY, historyElements);
};

const historyStreamHandler = async (streamEvents: Array<SseEvent<StreamDataEvent>>) => {
  try {
    // Create list of events to process
    // Events must be in a compatible version and not inferences events
    // Inferences directly handle recursively by the manager
    // Events must be of scope external or in-pir relationships
    const compatibleEvents = streamEvents.filter((event) => {
      const isInference = event.data?.data?.extensions[STIX_EXT_OCTI].is_inferred;
      const validEvent = HISTORY_WITH_INFERENCES || !isInference;
      const eventVersion = parseInt(event.data?.version ?? '0', 10);
      const noHistory = event.data?.noHistory === true;
      const isExternalScopeOrInPir = event.data?.scope !== 'internal'
        || event.data?.data?.extensions?.[STIX_EXT_OCTI]?.type === RELATION_IN_PIR; // if scope=internal, only keep in-pir relations
      return eventVersion >= 4 && !noHistory && validEvent && isExternalScopeOrInPir;
    });
    if (compatibleEvents.length > 0) {
      // Execute the events
      const context = executionContext('history_manager');
      await eventsApplyHandler(context, compatibleEvents);
    }
  } catch (e) {
    logApp.error('[OPENCTI-MODULE] History manager stream error', { cause: e, manager: 'HISTORY_MANAGER' });
  }
};

const initHistoryManager = () => {
  const WAIT_TIME_ACTION = 2000;
  let scheduler: SetIntervalAsyncTimer<[]>;
  let streamProcessor: StreamProcessor;
  let running = false;
  let shutdown = false;
  const wait = (ms: number) => {
    return new Promise((resolve) => {
      setTimeout(resolve, ms);
    });
  };
  const historyHandler = async (lastEventId: string) => {
    let lock;
    try {
      // Lock the manager
      lock = await lockResources([HISTORY_ENGINE_KEY], { retryCount: 0 });
      running = true;
      logApp.info('[OPENCTI-MODULE] Running history manager');
      streamProcessor = createStreamProcessor('History manager', historyStreamHandler, { bufferTime: 5000, withInternal: true });
      await streamProcessor.start(lastEventId);
      while (!shutdown && streamProcessor.running()) {
        lock.signal.throwIfAborted();
        await wait(WAIT_TIME_ACTION);
      }
      logApp.info('[OPENCTI-MODULE] End of history manager processing');
    } catch (e: any) {
      if (e.name === TYPE_LOCK_ERROR) {
        logApp.debug('[OPENCTI-MODULE] History manager already started by another API');
      } else {
        logApp.error('[OPENCTI-MODULE] History manager handling error', { cause: e, manager: 'HISTORY_MANAGER' });
      }
    } finally {
      running = false;
      if (streamProcessor) await streamProcessor.shutdown();
      if (lock) await lock.unlock();
    }
  };
  return {
    start: async () => {
      // To start the manager we need to find the last event id indexed
      // and restart the stream consumption from this point.
      const context = executionContext('history_manager');
      const histoElements = await topEntitiesList<HistoryData>(context, SYSTEM_USER, [ENTITY_TYPE_HISTORY], {
        first: 1,
        indices: [INDEX_HISTORY],
        orderBy: ['timestamp'],
        orderMode: OrderingMode.Desc,
        filters: {
          mode: FilterMode.And,
          filters: [{ key: ['event_access'], values: [], operator: FilterOperator.Nil }],
          filterGroups: [],
        },
        noFiltersChecking: true,
      });
      let lastEventId = '0-0';
      if (histoElements.length > 0) {
        const histoDate = histoElements[0].timestamp;
        lastEventId = `${utcDate(histoDate).unix() * 1000}-0`;
      }
      // Start the listening of events
      scheduler = setIntervalAsync(async () => {
        await historyHandler(lastEventId);
      }, SCHEDULE_TIME);
    },
    status: () => {
      return {
        id: 'HISTORY_MANAGER',
        enable: booleanConf('history_manager:enabled', false),
        running,
      };
    },
    shutdown: async () => {
      logApp.info('[OPENCTI-MODULE] Stopping history manager');
      shutdown = true;
      if (scheduler) {
        await clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};
const historyManager = initHistoryManager();

export default historyManager;
