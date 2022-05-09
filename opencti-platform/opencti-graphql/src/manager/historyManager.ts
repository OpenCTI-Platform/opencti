import * as R from 'ramda';
import { clearIntervalAsync, setIntervalAsync, SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import { createStreamProcessor, lockResource } from '../database/redis';
import conf, { logApp } from '../config/conf';
import { INDEX_HISTORY, isEmptyField } from '../database/utils';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { SYSTEM_USER } from '../utils/access';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import type { StreamEvent, UpdateEvent } from '../types/event';
import { utcDate } from '../utils/format';
import { elIndexElements } from '../database/engine';
import { EVENT_TYPE_UPDATE } from '../database/rabbitmq';
import { isStixRelationship } from '../schema/stixRelationship';
import type { StixRelation, StixSighting } from '../types/stix-sro';
import { listEntities } from '../database/middleware-loader';
import type { StoreProxyEntity } from '../types/store';
import { BASE_TYPE_ENTITY } from '../schema/general';
import { generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_HISTORY } from '../schema/internalObject';
import type { StixId } from '../types/stix-common';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';

const HISTORY_ENGINE_KEY = conf.get('history_manager:lock_key');
const SCHEDULE_TIME = 10000;

interface HistoryContext {
  id: string;
  entity_type: string;
  message: string;
  from_id?: string | undefined;
  to_id?: string | undefined;
  commit?: string | undefined;
  references?: Array<string>;
}
interface HistoryData extends StoreProxyEntity {
  event_type: string;
  timestamp: string;
  entity_type: 'History';
  user_id: string | undefined;
  applicant_id: string | undefined;
  context_data: HistoryContext
}

export const eventsApplyHandler = async (events: Array<StreamEvent>) => {
  if (isEmptyField(events) || events.length === 0) {
    return;
  }
  // Build the history data
  const historyElements: Array<HistoryData> = events.map((event) => {
    const [time] = event.id.split('-');
    const eventDate = utcDate(parseInt(time, 10)).toISOString();
    const stix = event.data.data;
    const contextData: HistoryContext = {
      id: stix.extensions[STIX_EXT_OCTI].id,
      message: event.data.message,
      entity_type: stix.extensions[STIX_EXT_OCTI].type,
    };
    if (event.data.type === EVENT_TYPE_UPDATE) {
      const updateEvent: UpdateEvent = event.data as UpdateEvent;
      contextData.commit = updateEvent.commit?.message;
      contextData.references = updateEvent.commit?.references;
    }
    if (isStixRelationship(event.data.type)) {
      const rel: StixRelation = stix as StixRelation;
      contextData.from_id = rel.extensions[STIX_EXT_OCTI].source_ref;
      contextData.to_id = rel.extensions[STIX_EXT_OCTI].target_ref;
    }
    if (isStixSightingRelationship(event.data.type)) {
      const sighting: StixSighting = stix as StixSighting;
      contextData.from_id = sighting.extensions[STIX_EXT_OCTI].sighting_of_ref;
      contextData.to_id = R.head(sighting.extensions[STIX_EXT_OCTI].where_sighted_refs);
    }
    const activityDate = utcDate(eventDate).toDate();
    const standardId = generateStandardId(ENTITY_TYPE_HISTORY, { internal_id: event.id }) as StixId;
    const data:HistoryData = {
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
      context_data: contextData
    };
    return data;
  });
  // Bulk the history data insertions
  await elIndexElements(historyElements);
};

const historyStreamHandler = async (streamEvents: Array<StreamEvent>) => {
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
      await eventsApplyHandler(compatibleEvents);
    }
  } catch (e) {
    logApp.error('[OPENCTI-MODULE] Error executing history manager', { error: e });
  }
};

const initHistoryManager = () => {
  const WAIT_TIME_ACTION = 2000;
  let scheduler: SetIntervalAsyncTimer;
  let streamProcessor;
  let syncListening = true;
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
      logApp.info('[OPENCTI-MODULE] Running history manager');
      streamProcessor = createStreamProcessor(SYSTEM_USER, 'History manager', historyStreamHandler);
      await streamProcessor.start(lastEventId);
      while (syncListening) {
        await wait(WAIT_TIME_ACTION);
      }
      await streamProcessor.shutdown();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (e: any) {
      if (e.name === TYPE_LOCK_ERROR) {
        logApp.info('[OPENCTI-MODULE] History manager already started by another API');
      } else {
        logApp.error('[OPENCTI-MODULE] history manager failed to start', { error: e });
      }
    } finally {
      if (lock) await lock.unlock();
    }
  };
  const shutdown = async () => {
    syncListening = false;
    if (scheduler) {
      return clearIntervalAsync(scheduler);
    }
    return true;
  };
  return {
    start: async () => {
      // To start the manager we need to find the last event id indexed
      // and restart the stream consumption from this point.
      const histoElements = await listEntities<HistoryData>(SYSTEM_USER, [ENTITY_TYPE_HISTORY], {
        first: 1,
        indices: [INDEX_HISTORY],
        connectionFormat: false,
        orderBy: ['timestamp'],
        orderMode: 'desc'
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
    shutdown,
  };
};
const historyManager = initHistoryManager();

export default historyManager;
