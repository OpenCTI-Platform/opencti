import * as R from 'ramda';
import { clearIntervalAsync, setIntervalAsync, SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import { createStreamProcessor, lockResource, StreamProcessor } from '../database/redis';
import conf, { booleanConf, logApp } from '../config/conf';
import { EVENT_TYPE_UPDATE, INDEX_HISTORY, isEmptyField, isNotEmptyField } from '../database/utils';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import type { SseEvent, StreamDataEvent, UpdateEvent } from '../types/event';
import { utcDate } from '../utils/format';
import { elIndexElements } from '../database/engine';
import type { StixRelation, StixSighting } from '../types/stix-sro';
import { listEntities } from '../database/middleware-loader';
import type { BasicRuleEntity, BasicStoreEntity } from '../types/store';
import { BASE_TYPE_ENTITY } from '../schema/general';
import { generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_HISTORY } from '../schema/internalObject';
import type { StixId } from '../types/stix-common';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { getEntitiesMapFromCache } from '../database/cache';
import type { AuthContext } from '../types/user';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../schema/stixDomainObject';
import { OrderingMode } from '../generated/graphql';

const HISTORY_ENGINE_KEY = conf.get('history_manager:lock_key');
const SCHEDULE_TIME = 10000;

interface HistoryContext {
  id: string;
  entity_type: string;
  message: string;
  from_id?: string | undefined;
  to_id?: string | undefined;
  commit?: string | undefined;
  external_references?: Array<string>;
}

interface HistoryData extends BasicStoreEntity {
  event_type: string;
  timestamp: string;
  entity_type: 'History';
  user_id: string | undefined;
  applicant_id: string | undefined;
  context_data: HistoryContext;
}

export const eventsApplyHandler = async (context: AuthContext, events: Array<SseEvent<StreamDataEvent>>) => {
  if (isEmptyField(events) || events.length === 0) {
    return;
  }
  const markingsById = await getEntitiesMapFromCache<BasicRuleEntity>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  const organizationsById = await getEntitiesMapFromCache<BasicStoreEntity>(context, SYSTEM_USER, ENTITY_TYPE_IDENTITY_ORGANIZATION);
  const filteredEvents = events.filter((event) => {
    // Filter update events with only files modification
    if (event.event === EVENT_TYPE_UPDATE) {
      const { patch } = (event.data as UpdateEvent).context;
      const noFilePatches = patch.filter((p) => !p.path.startsWith(`/extensions/${STIX_EXT_OCTI}/files`));
      return noFilePatches.length > 0;
    }
    // Deletion and creation events are not filtered
    return true;
  });
  // Build the history data
  const historyElements = filteredEvents.map((event) => {
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
    };
    if (event.data.type === EVENT_TYPE_UPDATE) {
      const updateEvent: UpdateEvent = event.data as UpdateEvent;
      contextData.commit = updateEvent.commit?.message;
      contextData.external_references = updateEvent.commit?.external_references ?? [];
    }
    if (stix.type === 'relationship') {
      const rel: StixRelation = stix as StixRelation;
      contextData.from_id = rel.extensions[STIX_EXT_OCTI].source_ref;
      contextData.to_id = rel.extensions[STIX_EXT_OCTI].target_ref;
      eventMarkingRefs.push(...(rel.extensions[STIX_EXT_OCTI].source_ref_object_marking_refs ?? []));
      eventMarkingRefs.push(...(rel.extensions[STIX_EXT_OCTI].target_ref_object_marking_refs ?? []));
    }
    if (stix.type === 'sighting') {
      const sighting: StixSighting = stix as StixSighting;
      contextData.from_id = sighting.extensions[STIX_EXT_OCTI].sighting_of_ref;
      contextData.to_id = R.head(sighting.extensions[STIX_EXT_OCTI].where_sighted_refs);
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
      event_type: event.event,
      user_id: event.data.origin?.user_id,
      applicant_id: event.data.origin?.applicant_id,
      timestamp: eventDate,
      context_data: contextData,
      'rel_object-marking.internal_id': eventMarkingRefs,
      'rel_granted.internal_id': eventGrantedRefs
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
      const eventVersion = parseInt(event.data?.version ?? '0', 10);
      return eventVersion >= 4;
    });
    if (compatibleEvents.length > 0) {
      // Execute the events
      const context = executionContext('history_manager');
      await eventsApplyHandler(context, compatibleEvents);
    }
  } catch (e) {
    logApp.error('[OPENCTI-MODULE] Error executing history manager', { error: e });
  }
};

const initHistoryManager = () => {
  const WAIT_TIME_ACTION = 2000;
  let scheduler: SetIntervalAsyncTimer<[]>;
  let streamProcessor: StreamProcessor;
  let syncListening = true;
  let running = false;
  const wait = (ms: number) => {
    return new Promise((resolve) => {
      setTimeout(resolve, ms);
    });
  };
  const historyHandler = async (lastEventId: string) => {
    let lock;
    try {
      // Lock the manager
      lock = await lockResource([HISTORY_ENGINE_KEY]);
      running = true;
      logApp.info('[OPENCTI-MODULE] Running history manager');
      streamProcessor = createStreamProcessor(SYSTEM_USER, 'History manager', historyStreamHandler);
      await streamProcessor.start(lastEventId);
      while (syncListening) {
        await wait(WAIT_TIME_ACTION);
      }
    } catch (e: any) {
      if (e.name === TYPE_LOCK_ERROR) {
        logApp.info('[OPENCTI-MODULE] History manager already started by another API');
      } else {
        logApp.error('[OPENCTI-MODULE] history manager failed to start', { error: e });
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
      });
      let lastEventId = '0-0';
      if (histoElements.length > 0) {
        const histoDate = histoElements[0].timestamp;
        lastEventId = `${utcDate(histoDate).unix() * 1000}-0`;
      }
      // Start the listening of events
      scheduler = setIntervalAsync(async () => {
        if (syncListening) {
          await historyHandler(lastEventId);
        }
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
      syncListening = false;
      if (scheduler) {
        await clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};
const historyManager = initHistoryManager();

export default historyManager;
