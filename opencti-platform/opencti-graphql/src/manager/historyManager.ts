import * as R from 'ramda';
import { clearIntervalAsync, setIntervalAsync, type SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import * as jsonpatch from 'fast-json-patch';
import { createStreamProcessor, lockResource, type StreamProcessor } from '../database/redis';
import conf, { booleanConf, ENABLED_DEMO_MODE, logApp } from '../config/conf';
import { EVENT_TYPE_UPDATE, INDEX_HISTORY, isEmptyField, isNotEmptyField } from '../database/utils';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { executionContext, REDACTED_USER, SYSTEM_USER } from '../utils/access';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import type { SseEvent, StreamDataEvent, UpdateEvent } from '../types/event';
import { utcDate } from '../utils/format';
import { elIndexElements } from '../database/engine';
import type { StixRelation, StixSighting } from '../types/stix-sro';
import { listEntities } from '../database/middleware-loader';
import type { BasicRuleEntity, BasicStoreEntity } from '../types/store';
import { BASE_TYPE_ENTITY, STIX_TYPE_RELATION, STIX_TYPE_SIGHTING } from '../schema/general';
import { generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_HISTORY } from '../schema/internalObject';
import type { StixId } from '../types/stix-common';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { getEntitiesMapFromCache } from '../database/cache';
import type { AuthContext } from '../types/user';
import { FilterMode, FilterOperator, OrderingMode } from '../generated/graphql';
import { extractStixRepresentative } from '../database/stix-representative';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';

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
}

export interface HistoryData extends BasicStoreEntity {
  event_type: string;
  timestamp: string;
  entity_type: 'History';
  user_id: string | undefined;
  applicant_id: string | undefined;
  context_data: HistoryContext;
}

const eventsApplyHandler = async (context: AuthContext, events: Array<SseEvent<StreamDataEvent>>) => {
  if (isEmptyField(events) || events.length === 0) {
    return;
  }
  const markingsById = await getEntitiesMapFromCache<BasicRuleEntity>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  const organizationsById = await getEntitiesMapFromCache<BasicStoreEntity>(context, SYSTEM_USER, ENTITY_TYPE_IDENTITY_ORGANIZATION);
  // Build the history data
  const historyElements = events.map((event) => {
    const [time] = event.id.split('-');
    const eventDate = utcDate(parseInt(time, 10)).toISOString();
    const stix = event.data.data;
    const eventMarkingRefs = (stix.object_marking_refs ?? [])
      .map((stixId) => markingsById.get(stixId)?.internal_id)
      .filter((o) => isNotEmptyField(o));
    const eventGrantedRefs = (stix.extensions[STIX_EXT_OCTI].granted_refs ?? [])
      .map((stixId) => organizationsById.get(stixId)?.internal_id)
      .filter((o) => isNotEmptyField(o));
    const contextData: HistoryContext = {
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
        .filter((o) => isNotEmptyField(o));
      eventMarkingRefs.push(...previousMarkingRefs);
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
    const activityDate = utcDate(eventDate).toDate();
    const standardId = generateStandardId(ENTITY_TYPE_HISTORY, { internal_id: event.id }) as StixId;

    return {
      _index: INDEX_HISTORY,
      internal_id: event.id,
      standard_id: standardId,
      base_type: BASE_TYPE_ENTITY,
      created_at: activityDate,
      updated_at: activityDate,
      entity_type: ENTITY_TYPE_HISTORY,
      event_type: 'mutation',
      event_scope: event.event,
      user_id: ENABLED_DEMO_MODE ? REDACTED_USER.id : event.data.origin?.user_id,
      group_ids: event.data.origin?.group_ids ?? [],
      organization_ids: event.data.origin?.organization_ids ?? [],
      applicant_id: event.data.origin?.applicant_id,
      timestamp: eventDate,
      context_data: contextData,
      authorized_members: stix.extensions[STIX_EXT_OCTI].authorized_members,
      'rel_object-marking.internal_id': R.uniq(eventMarkingRefs),
      'rel_granted.internal_id': R.uniq(eventGrantedRefs)
    };
  });
  // Bulk the history data insertions
  await elIndexElements(context, SYSTEM_USER, `history (${historyElements.length})`, historyElements);
};

const historyStreamHandler = async (streamEvents: Array<SseEvent<StreamDataEvent>>) => {
  try {
    // Create list of events to process
    // Events must be in a compatible version and not inferences events
    // Inferences directly handle recursively by the manager
    const compatibleEvents = streamEvents.filter((event) => {
      const isInference = event.data?.data?.extensions[STIX_EXT_OCTI].is_inferred;
      const validEvent = HISTORY_WITH_INFERENCES || !isInference;
      const eventVersion = parseInt(event.data?.version ?? '0', 10);
      return eventVersion >= 4 && validEvent;
    });
    if (compatibleEvents.length > 0) {
      // Execute the events
      const context = executionContext('history_manager');
      await eventsApplyHandler(context, compatibleEvents);
    }
  } catch (e) {
    logApp.error(e, { manager: 'HISTORY_MANAGER' });
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
      lock = await lockResource([HISTORY_ENGINE_KEY], { retryCount: 0 });
      running = true;
      logApp.info('[OPENCTI-MODULE] Running history manager');
      streamProcessor = createStreamProcessor(SYSTEM_USER, 'History manager', historyStreamHandler);
      await streamProcessor.start(lastEventId);
      while (!shutdown && streamProcessor.running()) {
        lock.signal.throwIfAborted();
        await wait(WAIT_TIME_ACTION);
      }
      logApp.info('[OPENCTI-MODULE] End of history manager processing');
    } catch (e: any) {
      if (e.extensions.name === TYPE_LOCK_ERROR) {
        logApp.debug('[OPENCTI-MODULE] History manager already started by another API');
      } else {
        logApp.error(e, { manager: 'HISTORY_MANAGER' });
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
      const histoElements = await listEntities<HistoryData>(context, SYSTEM_USER, [ENTITY_TYPE_HISTORY], {
        first: 1,
        indices: [INDEX_HISTORY],
        connectionFormat: false,
        orderBy: ['timestamp'],
        orderMode: OrderingMode.Desc,
        filters: {
          mode: FilterMode.And,
          filters: [{ key: ['event_access'], values: [], operator: FilterOperator.Nil }],
          filterGroups: [],
        },
        noFiltersChecking: true
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
