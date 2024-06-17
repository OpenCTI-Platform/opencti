/*
Copyright (c) 2021-2024 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import { clearIntervalAsync, setIntervalAsync, type SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import { ACTIVITY_STREAM_NAME, createStreamProcessor, lockResource, storeNotificationEvent, type StreamProcessor } from '../database/redis';
import conf, { booleanConf, ENABLED_DEMO_MODE, logApp } from '../config/conf';
import { INDEX_HISTORY, isEmptyField, isNotEmptyField } from '../database/utils';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { executionContext, REDACTED_USER, SYSTEM_USER } from '../utils/access';
import type { SseEvent } from '../types/event';
import { utcDate } from '../utils/format';
import { listEntities } from '../database/middleware-loader';
import { ENTITY_TYPE_ACTIVITY, ENTITY_TYPE_HISTORY, ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER } from '../schema/internalObject';
import type { AuthContext, AuthUser } from '../types/user';
import { FilterMode, OrderingMode } from '../generated/graphql';
import type { HistoryData } from './historyManager';
import type { ActivityStreamEvent } from './activityListener';
import { BASE_TYPE_ENTITY } from '../schema/general';
import { elIndexElements } from '../database/engine';
import { getEntitiesMapFromCache, getEntityFromCache } from '../database/cache';
import type { BasicStoreSettings } from '../types/settings';
import type { ActivityNotificationEvent, NotificationUser, ResolvedLive, ResolvedTrigger } from './notificationManager';
import { convertToNotificationUser, EVENT_NOTIFICATION_VERSION, getNotifications } from './notificationManager';
import { isActivityEventMatchFilterGroup } from '../utils/filtering/filtering-activity-event/activity-event-filtering';

const ACTIVITY_ENGINE_KEY = conf.get('activity_manager:lock_key');
const SCHEDULE_TIME = 10000;

export const isLiveActivity = (n: ResolvedTrigger): n is ResolvedLive => n.trigger.trigger_type === 'live'
  && n.trigger.trigger_scope === 'activity';

export const getLiveActivityNotifications = async (context: AuthContext): Promise<Array<ResolvedLive>> => {
  const liveNotifications = await getNotifications(context);
  return liveNotifications.filter(isLiveActivity);
};

const alertingTriggers = async (context: AuthContext, events: Array<SseEvent<ActivityStreamEvent>>) => {
  const platformUsers = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const triggers = await getLiveActivityNotifications(context);
  for (let index = 0; index < events.length; index += 1) {
    // type: 'authentication' | 'read' | 'mutation' | 'file' | 'command'
    // event_scope: 'read' | 'create' | 'update' | 'delete' | 'merge' | 'login' | 'logout' | 'unauthorized' | 'export' | 'import' | 'enrich' | 'analyze'
    // status: 'error' | 'success'
    const event = events[index];
    const { message, data, origin, event_scope } = event.data;
    let sourceUser = origin.user_id ? platformUsers.get(origin.user_id) : SYSTEM_USER;
    if (ENABLED_DEMO_MODE) sourceUser = REDACTED_USER;
    for (let triggerIndex = 0; triggerIndex < triggers.length; triggerIndex += 1) {
      const { trigger, users } = triggers[triggerIndex];
      const { internal_id: notification_id, notifiers } = trigger;
      const triggerFilters = trigger.filters ? JSON.parse(trigger.filters) : null;
      // Filter the event
      const isMatchFilter = triggerFilters ? await isActivityEventMatchFilterGroup(event.data, triggerFilters) : true;
      if (isMatchFilter) {
        const targets: Array<{ user: NotificationUser, type: string, message: string }> = [];
        const version = EVENT_NOTIFICATION_VERSION;
        for (let indexUser = 0; indexUser < users.length; indexUser += 1) {
          const user = users[indexUser];
          targets.push({ user: convertToNotificationUser(user, notifiers), type: event_scope, message: `\`${sourceUser?.name}\` ${message}` });
        }
        const notificationEvent: ActivityNotificationEvent = { version, notification_id, type: 'live', targets, data, origin };
        await storeNotificationEvent(context, notificationEvent);
      }
    }
  }
};

const historyIndexing = async (context: AuthContext, events: Array<SseEvent<ActivityStreamEvent>>) => {
  const historyElements = events.filter((e) => !e.data.prevent_indexing)
    .map((event: SseEvent<ActivityStreamEvent>) => {
      const [time] = event.id.split('-');
      const eventDate = utcDate(parseInt(time, 10)).toISOString();
      const contextData = { ...event.data.data, message: event.data.message };
      const activityDate = utcDate(eventDate).toDate();
      const isAdminEvent = event.data.event_access === 'administration';
      return {
        _index: INDEX_HISTORY,
        internal_id: event.id,
        base_type: BASE_TYPE_ENTITY,
        created_at: activityDate,
        updated_at: activityDate,
        entity_type: isAdminEvent ? ENTITY_TYPE_ACTIVITY : ENTITY_TYPE_HISTORY,
        event_type: event.event,
        event_status: event.data.status,
        event_access: event.data.event_access,
        event_scope: event.data.event_scope,
        user_id: ENABLED_DEMO_MODE ? REDACTED_USER.id : event.data.origin?.user_id,
        user_metadata: event.data.origin?.user_metadata,
        group_ids: event.data.origin?.group_ids ?? [],
        organization_ids: event.data.origin?.organization_ids ?? [],
        applicant_id: event.data.origin?.applicant_id,
        timestamp: eventDate,
        context_data: contextData,
        'rel_object-marking.internal_id': event.data.data.object_marking_refs_ids,
        'rel_granted.internal_id': event.data.data.granted_refs_ids,
      };
    });
  // Bulk the history data insertions
  return elIndexElements(context, SYSTEM_USER, `activity (${historyElements.length})`, historyElements);
};

const eventsApplyHandler = async (context: AuthContext, events: Array<SseEvent<ActivityStreamEvent>>) => {
  if (events.length > 0) {
    const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
    // If no events or enterprise edition is not activated
    if (isEmptyField(settings.enterprise_edition) || isEmptyField(events) || events.length === 0) {
      return;
    }
    // Handle alerting and indexing
    const alertingTriggersPromise = alertingTriggers(context, events);
    const indexingPromise = historyIndexing(context, events);
    await Promise.all([alertingTriggersPromise, indexingPromise]);
  }
};

const activityStreamHandler = async (streamEvents: Array<SseEvent<ActivityStreamEvent>>) => {
  try {
    const context = executionContext('activity_manager');
    await eventsApplyHandler(context, streamEvents);
  } catch (e) {
    logApp.error(e, { manager: 'ACTIVITY_MANAGER' });
  }
};

const initActivityManager = () => {
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
  const activityHandler = async (lastEventId: string) => {
    let lock;
    try {
      // Lock the manager
      lock = await lockResource([ACTIVITY_ENGINE_KEY], { retryCount: 0 });
      running = true;
      logApp.info('[OPENCTI-MODULE] Running activity manager');
      const streamOpts = { streamName: ACTIVITY_STREAM_NAME };
      streamProcessor = createStreamProcessor(SYSTEM_USER, 'Activity manager', activityStreamHandler, streamOpts);
      await streamProcessor.start(lastEventId);
      while (!shutdown && streamProcessor.running()) {
        lock.signal.throwIfAborted();
        await wait(WAIT_TIME_ACTION);
      }
      logApp.info('[OPENCTI-MODULE] End of Activity manager processing');
    } catch (e: any) {
      if (e.name === TYPE_LOCK_ERROR) {
        logApp.debug('[OPENCTI-MODULE] Activity manager already started by another API');
      } else {
        logApp.error(e, { manager: 'ACTIVITY_MANAGER' });
      }
    } finally {
      running = false;
      if (streamProcessor) await streamProcessor.shutdown();
      if (lock) await lock.unlock();
    }
  };
  return {
    start: async () => {
      shutdown = false;
      // To start the manager we need to find the last event id indexed
      // and restart the stream consumption from this point.
      const context = executionContext('activity_manager');
      const histoElements = await listEntities<HistoryData>(context, SYSTEM_USER, [ENTITY_TYPE_ACTIVITY], {
        first: 1,
        indices: [INDEX_HISTORY],
        connectionFormat: false,
        orderBy: ['timestamp'],
        orderMode: OrderingMode.Desc,
        filters: {
          mode: FilterMode.And,
          filters: [{ key: ['event_access'], values: ['EXISTS'] }],
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
        await activityHandler(lastEventId);
      }, SCHEDULE_TIME);
    },
    status: (settings?: BasicStoreSettings) => {
      return {
        id: 'ACTIVITY_MANAGER',
        enable: isNotEmptyField(settings?.enterprise_edition) && booleanConf('activity_manager:enabled', false),
        running,
      };
    },
    shutdown: async () => {
      logApp.info('[OPENCTI-MODULE] Stopping activity manager');
      shutdown = true;
      if (scheduler) {
        await clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};
const activityManager = initActivityManager();

export default activityManager;
