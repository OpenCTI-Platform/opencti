/*
Copyright (c) 2021-2023 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import { clearIntervalAsync, setIntervalAsync, SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import {
  ACTIVITY_STREAM_NAME,
  createStreamProcessor,
  lockResource,
  storeNotificationEvent,
  StreamProcessor
} from '../database/redis';
import conf, { ENABLED_DEMO_MODE, logApp } from '../config/conf';
import { INDEX_HISTORY, isEmptyField, isNotEmptyField } from '../database/utils';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { executionContext, REDACTED_USER, SYSTEM_USER } from '../utils/access';
import type { SseEvent } from '../types/event';
import { utcDate } from '../utils/format';
import { listEntities } from '../database/middleware-loader';
import {
  ENTITY_TYPE_ACTIVITY,
  ENTITY_TYPE_HISTORY,
  ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER,
} from '../schema/internalObject';
import type { AuthContext, AuthUser } from '../types/user';
import { OrderingMode } from '../generated/graphql';
import type { HistoryData } from './historyManager';
import type { ActivityStreamEvent } from './activityListener';
import { BASE_TYPE_ENTITY } from '../schema/general';
import { elIndexElements } from '../database/engine';
import { getEntitiesMapFromCache, getEntityFromCache } from '../database/cache';
import type { BasicStoreSettings } from '../types/settings';
import type {
  ActivityNotificationEvent,
  NotificationUser,
  ResolvedLive,
  ResolvedTrigger
} from './notificationManager';
import { convertToNotificationUser, EVENT_NOTIFICATION_VERSION, getNotifications } from './notificationManager';
import { convertFiltersFrontendFormat } from '../utils/filtering';
import type { BasicStoreEntityLiveTrigger } from '../modules/notification/notification-types';

const ACTIVITY_ENGINE_KEY = conf.get('activity_manager:lock_key');
const SCHEDULE_TIME = 10000;

export const isLiveActivity = (n: ResolvedTrigger): n is ResolvedLive => n.trigger.trigger_type === 'live'
    && n.trigger.trigger_scope === 'activity';

export const getLiveActivityNotifications = async (context: AuthContext): Promise<Array<ResolvedLive>> => {
  const liveNotifications = await getNotifications(context);
  return liveNotifications.filter(isLiveActivity);
};

const isEventMatchFilter = async (context: AuthContext, trigger: BasicStoreEntityLiveTrigger, event: ActivityStreamEvent) => {
  const { type, event_scope, status, origin } = event;
  const { filters: rawFilters } = trigger;
  const filters = rawFilters ? JSON.parse(rawFilters) : {};
  const adaptedFilters = await convertFiltersFrontendFormat(context, SYSTEM_USER, filters);
  for (let index = 0; index < adaptedFilters.length; index += 1) {
    const { key, values } = adaptedFilters[index];
    if (values.length > 0) {
      if (key === 'event_type') {
        const ids = values.map((v) => v.id);
        if (!ids.includes(type)) {
          return false;
        }
      }
      if (key === 'event_scope') {
        const ids = values.map((v) => v.id);
        if (!ids.includes(event_scope)) {
          return false;
        }
      }
      if (key === 'members_user') {
        const ids = values.map((v) => v.id);
        if (!ids.includes(origin.user_id)) {
          return false;
        }
      }
      if (key === 'members_group') {
        const ids = values.map((v) => v.id);
        if (!ids.some((id) => (origin.group_ids ?? []).includes(id))) {
          return false;
        }
      }
      if (key === 'members_organization') {
        const ids = values.map((v) => v.id);
        if (!ids.some((id) => (origin.organization_ids ?? []).includes(id))) {
          return false;
        }
      }
      if (key === 'activity_statuses') {
        const ids = values.map((v) => v.id);
        if (!ids.includes(status)) {
          return false;
        }
      }
    }
  }
  return true;
};

const alertingTriggers = async (context: AuthContext, events: Array<SseEvent<ActivityStreamEvent>>) => {
  const platformUsers = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const triggers = await getLiveActivityNotifications(context);
  for (let index = 0; index < events.length; index += 1) {
    // type: 'authentication' | 'read' | 'mutation' | 'file' | 'command'
    // event_scope: 'read' | 'create' | 'update' | 'delete' | 'merge' | 'login' | 'logout' | 'unauthorized' | 'export' | 'import' | 'enrich'
    // status: 'error' | 'success'
    const event = events[index];
    const { message, data, origin, event_scope } = event.data;
    let sourceUser = origin.user_id ? platformUsers.get(origin.user_id) : SYSTEM_USER;
    if (ENABLED_DEMO_MODE) sourceUser = REDACTED_USER;
    for (let triggerIndex = 0; triggerIndex < triggers.length; triggerIndex += 1) {
      const { trigger, users } = triggers[triggerIndex];
      const { internal_id: notification_id, outcomes } = trigger;
      // Filter the event
      const isMatchFilter = await isEventMatchFilter(context, trigger, event.data);
      if (isMatchFilter) {
        const targets: Array<{ user: NotificationUser, type: string, message: string }> = [];
        const version = EVENT_NOTIFICATION_VERSION;
        for (let indexUser = 0; indexUser < users.length; indexUser += 1) {
          const user = users[indexUser];
          targets.push({ user: convertToNotificationUser(user, outcomes), type: event_scope, message: `\`${sourceUser?.name}\` ${message}` });
        }
        const notificationEvent: ActivityNotificationEvent = { version, notification_id, type: 'live', targets, data };
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
        group_ids: event.data.origin?.group_ids ?? [],
        organization_ids: event.data.origin?.organization_ids ?? [],
        applicant_id: event.data.origin?.applicant_id,
        timestamp: eventDate,
        context_data: contextData,
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
    logApp.error('[OPENCTI-MODULE] Error executing activity manager', { error: e });
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
        await wait(WAIT_TIME_ACTION);
      }
      logApp.info('[OPENCTI-MODULE] End of Activity manager processing');
    } catch (e: any) {
      if (e.name === TYPE_LOCK_ERROR) {
        logApp.debug('[OPENCTI-MODULE] Activity manager already started by another API');
      } else {
        logApp.error('[OPENCTI-MODULE] Activity manager failed to start', { error: e });
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
        filters: [{ key: ['event_access'], values: ['EXISTS'] }]
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
        enable: isNotEmptyField(settings?.enterprise_edition),
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
