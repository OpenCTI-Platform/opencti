import ejs from 'ejs';
import * as R from 'ramda';
import { clearIntervalAsync, setIntervalAsync, type SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import conf, { booleanConf, getBaseUrl, logApp } from '../config/conf';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { getEntitiesListFromCache, getEntityFromCache } from '../database/cache';
import { createStreamProcessor, lockResource, NOTIFICATION_STREAM_NAME, type StreamProcessor } from '../database/redis';
import { sendMail, smtpIsAlive } from '../database/smtp';
import type { NotifierTestInput } from '../generated/graphql';
import { addNotification } from '../modules/notification/notification-domain';
import type { BasicStoreEntityTrigger, NotificationContentEvent } from '../modules/notification/notification-types';
import {
  NOTIFIER_CONNECTOR_EMAIL,
  type NOTIFIER_CONNECTOR_EMAIL_INTERFACE,
  NOTIFIER_CONNECTOR_SIMPLIFIED_EMAIL,
  type NOTIFIER_CONNECTOR_SIMPLIFIED_EMAIL_INTERFACE,
  NOTIFIER_CONNECTOR_UI,
  NOTIFIER_CONNECTOR_WEBHOOK,
  type NOTIFIER_CONNECTOR_WEBHOOK_INTERFACE,
  SIMPLIFIED_EMAIL_TEMPLATE,
} from '../modules/notifier/notifier-statics';
import { type BasicStoreEntityNotifier, ENTITY_TYPE_NOTIFIER } from '../modules/notifier/notifier-types';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import type { SseEvent, StreamNotifEvent } from '../types/event';
import type { BasicStoreSettings } from '../types/settings';
import type { AuthContext } from '../types/user';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { now } from '../utils/format';
import type { NotificationData } from '../utils/publisher-mock';
import { type ActivityNotificationEvent, type DigestEvent, getNotifications, type KnowledgeNotificationEvent, type NotificationUser } from './notificationManager';
import { getHttpClient } from '../utils/http-client';

const DOC_URI = 'https://filigran.notion.site/OpenCTI-Public-Knowledge-Base-d411e5e477734c59887dad3649f20518';
const PUBLISHER_ENGINE_KEY = conf.get('publisher_manager:lock_key');
const STREAM_SCHEDULE_TIME = 10000;

export const internalProcessNotification = async (
  context: AuthContext,
  settings: BasicStoreSettings,
  notificationMap: Map<string, BasicStoreEntityTrigger>,
  user: NotificationUser,
  notifier: BasicStoreEntityNotifier | NotifierTestInput,
  data: NotificationData[],
  notification: BasicStoreEntityTrigger,
  // eslint-disable-next-line consistent-return
): Promise<{ error: string } | void> => {
  try {
    const { name: notification_name, trigger_type } = notification;
    const { notifier_connector_id, notifier_configuration: configuration } = notifier;
    const generatedContent: Record<string, Array<NotificationContentEvent>> = {};
    for (let index = 0; index < data.length; index += 1) {
      const { notification_id, instance, type, message } = data[index];
      const event = { operation: type, message, instance_id: instance.id };
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
    const templateData = { content, notification, settings, user, data, ...platformOpts };
    // endregion
    if (notifier_connector_id === NOTIFIER_CONNECTOR_UI) {
      const createNotification = {
        name: notification_name,
        notification_type: trigger_type,
        user_id: user.user_id,
        notification_content: content,
        created: now(),
        created_at: now(),
        updated_at: now(),
        is_read: false
      };
      addNotification(context, SYSTEM_USER, createNotification).catch((err) => {
        logApp.error(err, { manager: 'PUBLISHER_MANAGER' });
        return { error: err };
      });
    } else if (notifier_connector_id === NOTIFIER_CONNECTOR_EMAIL) {
      const { title, template } = JSON.parse(configuration ?? '{}') as NOTIFIER_CONNECTOR_EMAIL_INTERFACE;
      const generatedTitle = ejs.render(title, templateData);
      const generatedEmail = ejs.render(template, templateData);
      const mail = { from: settings.platform_email, to: user.user_email, subject: generatedTitle, html: generatedEmail };
      await sendMail(mail).catch((err) => {
        logApp.error(err, { manager: 'PUBLISHER_MANAGER' });
        return { error: err };
      });
    } else if (notifier_connector_id === NOTIFIER_CONNECTOR_SIMPLIFIED_EMAIL) {
      const {
        title,
        header,
        logo,
        footer,
        background_color: bgColor,
      } = JSON.parse(configuration ?? '{}') as NOTIFIER_CONNECTOR_SIMPLIFIED_EMAIL_INTERFACE;

      const finalTemplateData = {
        ...templateData,
        header,
        logo,
        footer,
        background_color: bgColor,
      };

      const generatedTitle = ejs.render(title, finalTemplateData);
      const generatedEmail = ejs.render(SIMPLIFIED_EMAIL_TEMPLATE, finalTemplateData);
      const mail = { from: settings.platform_email, to: user.user_email, subject: generatedTitle, html: generatedEmail };
      await sendMail(mail).catch((err) => {
        logApp.error(err, { manager: 'PUBLISHER_MANAGER' });
        return { error: err };
      });
    } else if (notifier_connector_id === NOTIFIER_CONNECTOR_WEBHOOK) {
      const { url, template, verb, params, headers } = JSON.parse(configuration ?? '{}') as NOTIFIER_CONNECTOR_WEBHOOK_INTERFACE;
      const generatedWebhook = ejs.render(template, templateData);
      const dataJson = JSON.parse(generatedWebhook);
      const dataHeaders = R.fromPairs((headers ?? []).map((h) => [h.attribute, h.value]));
      const dataParameters = R.fromPairs((params ?? []).map((h) => [h.attribute, h.value]));
      const httpClient = getHttpClient({ responseType: 'json', headers: dataHeaders });
      await httpClient({ url, method: verb, params: dataParameters, data: dataJson }).catch((err) => {
        logApp.error(err, { manager: 'PUBLISHER_MANAGER' });
        return { error: err };
      });
    } else {
      // Push the event to the external connector
      // TODO
    }
  } catch (e: unknown) {
    return { error: (e as Error).message };
  }
};

const processNotificationEvent = async (
  context: AuthContext,
  notificationMap: Map<string, BasicStoreEntityTrigger>,
  notificationId: string,
  user: NotificationUser,
  data: NotificationData[]
) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const notification = notificationMap.get(notificationId);
  if (!notification) {
    return;
  }
  const userNotifiers = user.notifiers ?? []; // No notifier is possible for live trigger only targeting digest
  const notifiers = await getEntitiesListFromCache<BasicStoreEntityNotifier>(context, SYSTEM_USER, ENTITY_TYPE_NOTIFIER);
  const notifierMap = new Map(notifiers.map((n) => [n.internal_id, n]));
  for (let notifierIndex = 0; notifierIndex < userNotifiers.length; notifierIndex += 1) {
    const notifier = userNotifiers[notifierIndex];
    internalProcessNotification(context, settings, notificationMap, user, notifierMap.get(notifier) ?? {} as BasicStoreEntityNotifier, data, notification);
  }
};

const processLiveNotificationEvent = async (
  context: AuthContext,
  notificationMap: Map<string, BasicStoreEntityTrigger>,
  event: KnowledgeNotificationEvent | ActivityNotificationEvent
) => {
  const { targets, data: instance } = event;
  for (let index = 0; index < targets.length; index += 1) {
    const { user, type, message } = targets[index];
    const data = [{ notification_id: event.notification_id, instance, type, message }];
    await processNotificationEvent(context, notificationMap, event.notification_id, user, data);
  }
};

const processDigestNotificationEvent = async (context: AuthContext, notificationMap: Map<string, BasicStoreEntityTrigger>, event: DigestEvent) => {
  const { target: user, data } = event;
  await processNotificationEvent(context, notificationMap, event.notification_id, user, data);
};

const publisherStreamHandler = async (streamEvents: Array<SseEvent<StreamNotifEvent>>) => {
  try {
    const context = executionContext('publisher_manager');
    const notifications = await getNotifications(context);
    const notificationMap = new Map(notifications.map((n) => [n.trigger.internal_id, n.trigger]));
    for (let index = 0; index < streamEvents.length; index += 1) {
      const streamEvent = streamEvents[index];
      const { data: { notification_id, type } } = streamEvent;
      if (type === 'live') {
        const liveEvent = streamEvent as SseEvent<KnowledgeNotificationEvent>;
        await processLiveNotificationEvent(context, notificationMap, liveEvent.data);
      }
      if (type === 'digest') {
        const digestEvent = streamEvent as SseEvent<DigestEvent>;
        // Add virtual notification in map for playbook execution
        if (digestEvent.data.playbook_source) {
          notificationMap.set(notification_id, { name: digestEvent.data.playbook_source, trigger_type: type } as BasicStoreEntityTrigger);
        }
        await processDigestNotificationEvent(context, notificationMap, digestEvent.data);
      }
    }
  } catch (e) {
    logApp.error(e, { manager: 'PUBLISHER_MANAGER' });
  }
};

const initPublisherManager = () => {
  const WAIT_TIME_ACTION = 2000;
  let streamScheduler: SetIntervalAsyncTimer<[]>;
  let streamProcessor: StreamProcessor;
  let running = false;
  let shutdown = false;
  let isSmtpActive = false;
  const wait = (ms: number) => {
    return new Promise((resolve) => {
      setTimeout(resolve, ms);
    });
  };
  const notificationHandler = async () => {
    let lock;
    try {
      // Lock the manager
      lock = await lockResource([PUBLISHER_ENGINE_KEY], { retryCount: 0 });
      running = true;
      logApp.info('[OPENCTI-PUBLISHER] Running publisher manager');
      const opts = { withInternal: false, streamName: NOTIFICATION_STREAM_NAME };
      streamProcessor = createStreamProcessor(SYSTEM_USER, 'Publisher manager', publisherStreamHandler, opts);
      await streamProcessor.start('live');
      while (!shutdown && streamProcessor.running()) {
        lock.signal.throwIfAborted();
        await wait(WAIT_TIME_ACTION);
      }
      logApp.info('[OPENCTI-MODULE] End of publisher manager processing');
    } catch (e: any) {
      if (e.name === TYPE_LOCK_ERROR) {
        logApp.debug('[OPENCTI-PUBLISHER] Publisher manager already started by another API');
      } else {
        logApp.error(e, { manager: 'PUBLISHER_MANAGER' });
      }
    } finally {
      if (streamProcessor) await streamProcessor.shutdown();
      if (lock) await lock.unlock();
    }
  };
  return {
    start: async () => {
      isSmtpActive = await smtpIsAlive();
      streamScheduler = setIntervalAsync(async () => {
        await notificationHandler();
      }, STREAM_SCHEDULE_TIME);
    },
    status: () => {
      return {
        id: 'PUBLISHER_MANAGER',
        enable: booleanConf('publisher_manager:enabled', false),
        is_smtp_active: isSmtpActive,
        running,
      };
    },
    shutdown: async () => {
      logApp.info('[OPENCTI-MODULE] Stopping publisher manager');
      shutdown = true;
      if (streamScheduler) await clearIntervalAsync(streamScheduler);
      return true;
    },
  };
};
const publisherManager = initPublisherManager();

export default publisherManager;
