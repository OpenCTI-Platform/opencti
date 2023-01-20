import ejs from 'ejs';
import axios from 'axios';
import { clearIntervalAsync, setIntervalAsync, SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import { createStreamProcessor, lockResource, NOTIFICATION_STREAM_NAME, StreamProcessor } from '../database/redis';
import conf, { booleanConf, getBaseUrl, logApp } from '../config/conf';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { executionContext, SYSTEM_USER } from '../utils/access';
import {
  DigestEvent,
  getNotifications,
  NotificationEvent,
  NotificationUser,
  STATIC_OUTCOMES
} from './notificationManager';
import type { SseEvent, StreamNotifEvent } from '../types/event';
import { extractStixRepresentative } from '../database/stix-converter';
import { sendMail } from '../database/smtp';
import { getEntityFromCache } from '../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import type { BasicStoreSettings } from '../types/store';
import { addNotification } from '../modules/notification/notification-domain';
import type { AuthContext } from '../types/user';
import type { StixCoreObject, StixRelationshipObject } from '../types/stix-common';
import { now } from '../utils/format';
import type { NotificationContentEvent } from '../modules/notification/notification-types';

const DOC_URI = 'https://filigran.notion.site/OpenCTI-Public-Knowledge-Base-d411e5e477734c59887dad3649f20518';
const PUBLISHER_ENGINE_KEY = conf.get('publisher_manager:lock_key');
const STREAM_SCHEDULE_TIME = 10000;
const OUTCOME_TYPE_UI = 'UI';
const OUTCOME_TYPE_EMAIL = 'EMAIL';
const OUTCOME_TYPE_WEBHOOK = 'WEBHOOK';

const processNotificationEvent = async (
  context: AuthContext,
  notificationId: string,
  user: NotificationUser,
  data: Array<{ notification_id: string, instance: StixCoreObject | StixRelationshipObject, type: string }>
) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const outcomeMap = new Map(STATIC_OUTCOMES.map((n) => [n.internal_id, n]));
  const notifications = await getNotifications(context);
  const notificationMap = new Map(notifications.map((n) => [n.trigger.internal_id, n.trigger]));
  const notification = notificationMap.get(notificationId);
  if (!notification) {
    return;
  }
  const { name: notification_name, trigger_type } = notification;
  for (let outcomeIndex = 0; outcomeIndex < user.outcomes.length; outcomeIndex += 1) {
    const outcome = user.outcomes[outcomeIndex];
    const { outcome_type, configuration } = outcomeMap.get(outcome) ?? {};
    const generatedContent: Record<string, Array<NotificationContentEvent>> = {};
    for (let index = 0; index < data.length; index += 1) {
      const { notification_id, instance, type } = data[index];
      const event = { operation: type, message: `[${instance.type}] ${(extractStixRepresentative(instance))}`, instance_id: instance.id };
      const eventNotification = notificationMap.get(notification_id);
      if (eventNotification) {
        const notificationName = eventNotification.name;
        if (generatedContent[notificationName]) {
          generatedContent[notificationName] = [...generatedContent[notificationName], event];
        } else {
          generatedContent[notificationName] = [event];
        }
      }
    }
    const content = Object.entries(generatedContent).map(([k, v]) => ({ title: k, events: v }));
    // region data generation
    const background_color = (settings.platform_theme_dark_background ?? '#0a1929').substring(1);
    const platformOpts = { doc_uri: DOC_URI, platform_uri: getBaseUrl(), background_color };
    const title = `New ${trigger_type} notification for ${notification.name}`;
    const templateData = { title, content, notification, settings, user, data, ...platformOpts };
    // endregion
    if (outcome_type === OUTCOME_TYPE_UI) {
      const createNotification = {
        name: notification_name,
        notification_type: trigger_type,
        user_id: user.user_id,
        content,
        created: now(),
        created_at: now(),
        updated_at: now(),
        is_read: false
      };
      addNotification(context, SYSTEM_USER, createNotification).catch((err) => {
        logApp.error('[OPENCTI-MODULE] Error executing publication', { error: err });
      });
    }
    if (outcome_type === OUTCOME_TYPE_EMAIL) {
      const { template } = configuration ?? {};
      const generatedEmail = ejs.render(template, templateData);
      const mail = { from: settings.platform_email, to: user.user_email, subject: title, html: generatedEmail };
      sendMail(mail).catch((err) => {
        logApp.error('[OPENCTI-MODULE] Error executing publication', { error: err });
      });
    }
    if (outcome_type === OUTCOME_TYPE_WEBHOOK) {
      const { uri, template } = configuration ?? {};
      const generatedWebhook = ejs.render(template, templateData);
      const dataJson = JSON.parse(generatedWebhook);
      axios.post(uri, dataJson).catch((err) => {
        logApp.error('[OPENCTI-MODULE] Error executing publication', { error: err });
      });
    }
  }
};

const processLiveNotificationEvent = async (context: AuthContext, event: NotificationEvent) => {
  const { targets, data: instance } = event;
  for (let index = 0; index < targets.length; index += 1) {
    const { user, type } = targets[index];
    const data = [{ notification_id: event.notification_id, instance, type }];
    await processNotificationEvent(context, event.notification_id, user, data);
  }
};

const processDigestNotificationEvent = async (context: AuthContext, event: DigestEvent) => {
  const { target: user, data } = event;
  await processNotificationEvent(context, event.notification_id, user, data);
};

const publisherStreamHandler = async (streamEvents: Array<SseEvent<StreamNotifEvent>>) => {
  try {
    const context = executionContext('publisher_manager');
    const notifications = await getNotifications(context);
    const notificationMap = new Map(notifications.map((n) => [n.trigger.internal_id, n.trigger]));
    for (let index = 0; index < streamEvents.length; index += 1) {
      const streamEvent = streamEvents[index];
      const { data: { notification_id } } = streamEvent;
      const notification = notificationMap.get(notification_id);
      if (notification) {
        if (notification.trigger_type === 'live') {
          const liveEvent = streamEvent as SseEvent<NotificationEvent>;
          await processLiveNotificationEvent(context, liveEvent.data);
        }
        if (notification.trigger_type === 'digest') {
          const digestEvent = streamEvent as SseEvent<DigestEvent>;
          await processDigestNotificationEvent(context, digestEvent.data);
        }
      }
    }
  } catch (e) {
    logApp.error('[OPENCTI-MODULE] Error executing publisher manager', { error: e });
  }
};

const initPublisherManager = () => {
  const WAIT_TIME_ACTION = 2000;
  let streamScheduler: SetIntervalAsyncTimer<[]>;
  let streamProcessor: StreamProcessor;
  let publisherListening = true;
  const wait = (ms: number) => {
    return new Promise((resolve) => {
      setTimeout(resolve, ms);
    });
  };
  const notificationHandler = async () => {
    if (!publisherListening) return;
    let lock;
    try {
      // Lock the manager
      lock = await lockResource([PUBLISHER_ENGINE_KEY]);
      logApp.info('[OPENCTI-MODULE] Running publisher manager');
      const opts = { withInternal: false, streamName: NOTIFICATION_STREAM_NAME };
      streamProcessor = createStreamProcessor(SYSTEM_USER, 'Publisher manager', publisherStreamHandler, opts);
      await streamProcessor.start('live');
      while (publisherListening) {
        await wait(WAIT_TIME_ACTION);
      }
    } catch (e: any) {
      if (e.name === TYPE_LOCK_ERROR) {
        logApp.info('[OPENCTI-MODULE] Publisher manager already started by another API');
      } else {
        logApp.error('[OPENCTI-MODULE] Publisher manager failed to start', { error: e });
      }
    } finally {
      if (streamProcessor) await streamProcessor.shutdown();
      if (lock) await lock.unlock();
    }
  };
  return {
    start: async () => {
      streamScheduler = setIntervalAsync(() => notificationHandler(), STREAM_SCHEDULE_TIME);
    },
    status: () => {
      return {
        id: 'PUBLISHER_MANAGER',
        enable: booleanConf('publisher_manager:enabled', false),
        running: false,
      };
    },
    shutdown: async () => {
      publisherListening = false;
      if (streamScheduler) await clearIntervalAsync(streamScheduler);
      return true;
    },
  };
};
const publisherManager = initPublisherManager();

export default publisherManager;
