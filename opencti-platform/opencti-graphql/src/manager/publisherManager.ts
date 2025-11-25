import ejs from 'ejs';
import { clearIntervalAsync, setIntervalAsync, type SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import conf, { booleanConf, getBaseUrl, logApp } from '../config/conf';
import { FunctionalError, TYPE_LOCK_ERROR } from '../config/errors';
import { getEntitiesListFromCache, getEntitiesMapFromCache, getEntityFromCache } from '../database/cache';
import { createStreamProcessor, NOTIFICATION_STREAM_NAME, type StreamProcessor } from '../database/redis';
import { lockResources } from '../lock/master-lock';
import { sendMail, smtpIsAlive } from '../database/smtp';
import type { NotifierTestInput } from '../generated/graphql';
import { addNotification } from '../modules/notification/notification-domain';
import type { BasicStoreEntityTrigger, NotificationContentEvent, NotificationAddInput } from '../modules/notification/notification-types';
import {
  NOTIFIER_CONNECTOR_EMAIL,
  type NOTIFIER_CONNECTOR_EMAIL_INTERFACE,
  NOTIFIER_CONNECTOR_SIMPLIFIED_EMAIL,
  type NOTIFIER_CONNECTOR_SIMPLIFIED_EMAIL_INTERFACE,
  NOTIFIER_CONNECTOR_UI,
  NOTIFIER_CONNECTOR_WEBHOOK,
  type NOTIFIER_CONNECTOR_WEBHOOK_INTERFACE,
  SIMPLIFIED_EMAIL_TEMPLATE
} from '../modules/notifier/notifier-statics';
import { type BasicStoreEntityNotifier, ENTITY_TYPE_NOTIFIER } from '../modules/notifier/notifier-types';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER } from '../schema/internalObject';
import type { SseEvent, StreamNotifEvent } from '../types/event';
import type { BasicStoreSettings } from '../types/settings';
import type { AuthContext, AuthUser, UserOrigin } from '../types/user';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { now } from '../utils/format';
import type { NotificationData } from '../utils/publisher-mock';
import {
  type ActionNotificationEvent,
  type ActivityNotificationEvent,
  type DigestEvent,
  getNotifications,
  type KnowledgeNotificationEvent,
  type NotificationUser
} from './notificationManager';
import { type GetHttpClient, getHttpClient } from '../utils/http-client';
import { extractRepresentative } from '../database/entity-representative';
import { extractStixRepresentativeForUser } from '../database/stix-representative';
import { EVENT_TYPE_UPDATE } from '../database/utils';
import NotificationTool from '../utils/NotificationTool';

const DOC_URI = 'https://docs.opencti.io';
const PUBLISHER_ENGINE_KEY = conf.get('publisher_manager:lock_key');
const PUBLISHER_ENABLE_BUFFERING = conf.get('publisher_manager:enable_buffering');
const PUBLISHER_BUFFERING_SECONDS = conf.get('publisher_manager:buffering_seconds');
const STREAM_SCHEDULE_TIME = 10000;

export async function processNotificationData(
  context: AuthContext,
  notificationMap: Map<string, BasicStoreEntityTrigger>,
  user: NotificationUser,
  data: NotificationData[],
  usersMap: Map<string, AuthUser>,
) {
  const generatedContent: Record<string, NotificationContentEvent[]> = {};

  for (let i = 0; i < data.length; i += 1) {
    const { notification_id, instance, type, message } = data[i];
    const eventNotification = notificationMap.get(notification_id);
    if (eventNotification) {
      const event: NotificationContentEvent = {
        operation: type,
        message,
        instance_id: instance.id
      };

      const notificationUser = usersMap.get(user.user_id);
      if (!notificationUser) {
        throw FunctionalError(`Notification user not found ${user.user_id}`);
      }
      const notificationName = 'extensions' in instance
        ? await extractStixRepresentativeForUser(context, notificationUser, instance, true)
        : extractRepresentative(instance)?.main;

      if (notificationName) {
        if (!generatedContent[notificationName]) {
          generatedContent[notificationName] = [];
        }
        generatedContent[notificationName].push(event);
      }
    }
  }

  return generatedContent;
}

export function assembleTemplateData(
  content: Array<{ title: string; events: NotificationContentEvent[] }>,
  triggers: BasicStoreEntityTrigger[],
  settings: BasicStoreSettings,
  user: NotificationUser,
  data: NotificationData[]
) {
  const platformBackgroundColor = (settings.platform_theme_dark_background ?? '#0a1929').substring(1);
  return {
    content,
    notification_content: content,
    notification: triggers[0],
    settings,
    user,
    data,
    doc_uri: DOC_URI,
    platform_uri: getBaseUrl(),
    background_color: platformBackgroundColor
  };
}

export async function handleUINotification(
  context: AuthContext,
  notificationName: string,
  triggerIds: Array<string | undefined>,
  notificationType: string,
  user: NotificationUser,
  content: Array<{ title: string; events: NotificationContentEvent[] }>
) {
  const notificationPayload = {
    name: notificationName,
    trigger_id: triggerIds,
    notification_type: notificationType,
    user_id: user.user_id,
    notification_content: content,
    created: now(),
    created_at: now(),
    updated_at: now(),
    is_read: false
  } as NotificationAddInput;

  try {
    await addNotification(context, SYSTEM_USER, notificationPayload);
  } catch (error) {
    logApp.error('[OPENCTI-MODULE] Publisher manager add notification error', { cause: error, manager: 'PUBLISHER_MANAGER' });
    throw error;
  }
}

export async function handleEmailNotification(
  settings: BasicStoreSettings,
  user: NotificationUser,
  configurationString: string | undefined,
  templateData: object,
  triggerIds: string[],
) {
  const { title, template, url_suffix: urlSuffix } = JSON.parse(configurationString ?? '{}') as NOTIFIER_CONNECTOR_EMAIL_INTERFACE;

  const renderedTitle = ejs.render(title, templateData);
  const octiTool = new NotificationTool();
  const renderedEmail = ejs.render(template, { ...templateData, url_suffix: urlSuffix, octi: octiTool });

  const emailPayload = {
    from: `${settings.platform_title} <${settings.platform_email}>`,
    to: user.user_email,
    subject: renderedTitle,
    html: renderedEmail
  };

  try {
    await sendMail(emailPayload, { identifier: triggerIds, category: 'notification' });
  } catch (error) {
    logApp.error('[OPENCTI-MODULE] Publisher manager send email error', { cause: error, manager: 'PUBLISHER_MANAGER' });
    throw error;
  }
}

export async function handleSimplifiedEmailNotification(
  settings: BasicStoreSettings,
  user: NotificationUser,
  configurationString: string | undefined,
  templateData: object,
  triggerIds: string[],
) {
  const {
    title,
    header,
    logo,
    footer,
    background_color: bgColor,
    url_suffix: urlSuffix
  } = JSON.parse(configurationString ?? '{}') as NOTIFIER_CONNECTOR_SIMPLIFIED_EMAIL_INTERFACE;

  const finalTemplateData = { ...templateData, header, logo, footer, background_color: bgColor, url_suffix: urlSuffix };
  const renderedTitle = ejs.render(title, finalTemplateData);
  const renderedEmail = ejs.render(SIMPLIFIED_EMAIL_TEMPLATE, finalTemplateData);

  const emailPayload = {
    from: `${settings.platform_title} <${settings.platform_email}>`,
    to: user.user_email,
    subject: renderedTitle,
    html: renderedEmail
  };
  if (!emailPayload.to) {
    logApp.warn('[OPENCTI-MODULE] No recipient defined in email payload', { toId: user.user_id, manager: 'PUBLISHER_MANAGER' });
  } else {
    try {
      await sendMail(emailPayload, { identifier: triggerIds, category: 'notification' });
    } catch (error) {
      logApp.error('[OPENCTI-MODULE] Publisher manager send email error', { cause: error, manager: 'PUBLISHER_MANAGER' });
      throw error;
    }
  }
}

export async function handleWebhookNotification(configurationString: string | undefined, templateData: object) {
  const { url, template, verb, params, headers } = JSON.parse(configurationString ?? '{}') as NOTIFIER_CONNECTOR_WEBHOOK_INTERFACE;

  // Use ejs.render with escape function that uses JSON.stringify
  const renderedWebhookTemplate = ejs.render(template, templateData, {
    escape: (value: any) => {
      const result = JSON.stringify(value);
      return result.startsWith('"') && result.endsWith('"') ? result.slice(1, -1) : result;
    }
  });
  const webhookPayload = JSON.parse(renderedWebhookTemplate);

  const headersObject = Object.fromEntries((headers ?? []).map((header) => [header.attribute, header.value]));
  const paramsObject = Object.fromEntries((params ?? []).map((param) => [param.attribute, param.value]));

  const httpClientOptions: GetHttpClient = { responseType: 'json', headers: headersObject };
  const httpClient = getHttpClient(httpClientOptions);

  try {
    await httpClient.call({ url, method: verb, params: paramsObject, data: webhookPayload });
  } catch (error) {
    logApp.error('[OPENCTI-MODULE] Publisher manager webhook error', { cause: error, manager: 'PUBLISHER_MANAGER', url });
    throw error;
  }
}

export const internalProcessNotification = async (
  authContext: AuthContext,
  storeSettings: BasicStoreSettings,
  notificationEntities: Map<string, BasicStoreEntityTrigger>,
  notificationUser: NotificationUser,
  notifier: BasicStoreEntityNotifier | NotifierTestInput,
  notificationData: NotificationData[],
  triggerList: BasicStoreEntityTrigger[],
  usersMap: Map<string, AuthUser>,
  // eslint-disable-next-line consistent-return
): Promise<{ error: string } | void> => {
  if (notificationUser.user_service_account) {
    return { error: 'Cannot send notification to service account user' };
  }
  const notificationName = triggerList.map((trigger) => trigger?.name).join(';');
  const notificationType = triggerList.length > 1 ? 'buffer' : triggerList[0].trigger_type;
  const triggerIds = triggerList.map((trigger) => trigger?.id).filter((id) => id);

  const { notifier_connector_id: notifierConnectorId, notifier_configuration: notifierConfigurationString } = notifier;

  const contentEventMapping = await processNotificationData(authContext, notificationEntities, notificationUser, notificationData, usersMap);

  const content = Object.entries(contentEventMapping).map(([title, events]) => ({ title, events }));

  const assembledTemplateData = assembleTemplateData(content, triggerList, storeSettings, notificationUser, notificationData);

  switch (notifierConnectorId) {
    case NOTIFIER_CONNECTOR_UI:
      await handleUINotification(authContext, notificationName, triggerIds, notificationType, notificationUser, content);
      break;
    case NOTIFIER_CONNECTOR_EMAIL:
      await handleEmailNotification(storeSettings, notificationUser, notifierConfigurationString, assembledTemplateData, triggerIds);
      break;
    case NOTIFIER_CONNECTOR_SIMPLIFIED_EMAIL:
      await handleSimplifiedEmailNotification(storeSettings, notificationUser, notifierConfigurationString, assembledTemplateData, triggerIds);
      break;
    case NOTIFIER_CONNECTOR_WEBHOOK:
      await handleWebhookNotification(notifierConfigurationString, assembledTemplateData);
      break;
    default:
      // TODO: Handle other notifier scenarios
      break;
  }
};

export const processNotificationEvent = async (
  context: AuthContext,
  notificationMap: Map<string, BasicStoreEntityTrigger>,
  notificationId: string,
  user: NotificationUser,
  notificationData: NotificationData[],
  usersMap: Map<string, AuthUser>,
): Promise<void> => {
  const storeSettings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);

  const notificationTrigger = notificationMap.get(notificationId);
  if (!notificationTrigger) {
    return;
  }

  const userNotifiers = user.notifiers ?? []; // No notifier is possible for live trigger only targeting digest

  const allNotifiers = await getEntitiesListFromCache<BasicStoreEntityNotifier>(context, SYSTEM_USER, ENTITY_TYPE_NOTIFIER);
  const notifierMap = new Map<string, BasicStoreEntityNotifier>(
    allNotifiers.map((notifier) => [notifier.internal_id, notifier])
  );

  for (let i = 0; i < userNotifiers.length; i += 1) {
    const userNotifierId = userNotifiers[i];
    const notifier = notifierMap.get(userNotifierId) ?? {} as BasicStoreEntityNotifier;

    // There is no await in purpose; the goal is to send notification and continue without waiting result.
    internalProcessNotification(context, storeSettings, notificationMap, user, notifier, notificationData, [notificationTrigger], usersMap)
      .catch((reason) => logApp.error('[OPENCTI-MODULE] Publisher manager unknown error.', { cause: reason }));
  }
};

const createFullNotificationMessage = (
  notificationMessage: string,
  usersMap: Map<string, AuthUser>,
  streamMessage?: string,
  origin?: Partial<UserOrigin>,
  eventType?: string,
) => {
  let fullMessage = notificationMessage;
  if (eventType === EVENT_TYPE_UPDATE && origin && streamMessage) { // add precision for update events
    const { user_id } = origin;
    const streamUser = usersMap.get(user_id ?? '');
    if (streamUser) {
      const streamBuiltMessage = `\`${streamUser.name}\` ${streamMessage}`;
      if (streamBuiltMessage !== notificationMessage) {
        fullMessage = `${notificationMessage} - ${streamBuiltMessage}`;
      }
    }
  }

  return fullMessage;
};

export const processLiveNotificationEvent = async (
  context: AuthContext,
  notificationMap: Map<string, BasicStoreEntityTrigger>,
  event: KnowledgeNotificationEvent | ActivityNotificationEvent | ActionNotificationEvent
): Promise<void> => {
  const { targets, data: instance, origin, notification_id } = event as KnowledgeNotificationEvent;
  const usersMap = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const { streamMessage } = event as KnowledgeNotificationEvent;

  for (let i = 0; i < targets.length; i += 1) {
    const target = targets[i];
    const { user, type, message } = target;
    const notificationMessage = createFullNotificationMessage(message, usersMap, streamMessage, origin, type);
    const notificationData = [{ notification_id, instance, type, message: notificationMessage }];
    await processNotificationEvent(context, notificationMap, notification_id, user, notificationData, usersMap);
  }
};

const processDigestNotificationEvent = async (context: AuthContext, notificationMap: Map<string, BasicStoreEntityTrigger>, event: DigestEvent) => {
  const { target: user, data } = event;
  const usersMap = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const dataWithFullMessage = data.map((d) => {
    return { ...d, message: createFullNotificationMessage(d.message, usersMap, d.streamMessage, d.origin, d.type) };
  });
  await processNotificationEvent(context, notificationMap, event.notification_id, user, dataWithFullMessage, usersMap);
};

const liveNotificationBufferPerEntity: Record<string, { timestamp: number, events: SseEvent<KnowledgeNotificationEvent>[] }> = {};

const processBufferedEvents = async (
  context: AuthContext,
  triggerMap: Map<string, BasicStoreEntityTrigger>,
  events: KnowledgeNotificationEvent[]
) => {
  const usersFromCache = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const notifDataPerUser: Record<string, { user: NotificationUser, data: NotificationData }[]> = {};
  // We process all events to transform them into notification data per user
  for (let i = 0; i < events.length; i += 1) {
    const event = events[i];
    const { targets, data: instance, origin } = event;
    // For each event, transform it into NotificationData for all targets
    for (let index = 0; index < targets.length; index += 1) {
      const { user, type, message } = targets[index];
      const notificationMessage = createFullNotificationMessage(message, usersFromCache, event.streamMessage, origin, type);
      const currentData = { notification_id: event.notification_id, instance, type, message: notificationMessage };
      const currentNotifDataForUser = notifDataPerUser[user.user_id];
      if (currentNotifDataForUser) {
        currentNotifDataForUser.push({ user, data: currentData });
      } else {
        notifDataPerUser[user.user_id] = [{ user, data: currentData }];
      }
    }
  }
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const allNotifiers = await getEntitiesListFromCache<BasicStoreEntityNotifier>(context, SYSTEM_USER, ENTITY_TYPE_NOTIFIER);
  const allNotifiersMap = new Map(allNotifiers.map((n) => [n.internal_id, n]));

  const notifUsers = Object.keys(notifDataPerUser);
  // Handle notification data for each user
  for (let i = 0; i < notifUsers.length; i += 1) {
    const currentUserId = notifUsers[i];
    const userNotificationData = notifDataPerUser[currentUserId];
    const userNotifiers = [...new Set(userNotificationData.map((d) => d.user.notifiers).flat())];

    // For each notifier of the user, filter the relevant notification data, and send it
    for (let notifierIndex = 0; notifierIndex < userNotifiers.length; notifierIndex += 1) {
      const notifier = userNotifiers[notifierIndex];

      // Only include the notificationData that has the current notifier included in its trigger config
      const impactedData = userNotificationData.filter((d) => d.user.notifiers.includes(notifier));
      if (impactedData.length > 0) {
        const currentUser = impactedData[0].user;
        const dataToSend = impactedData.map((d) => d.data);
        const triggersInDataToSend = [...new Set(dataToSend.map((d) => triggerMap.get(d.notification_id)).filter((t) => t))];
        // If triggers can't be found, no need to send the data
        if (triggersInDataToSend.length >= 1) {
          // There is no await in purpose, the goal is to send notification and continue without waiting result.
          internalProcessNotification(
            context,
            settings,
            triggerMap,
            currentUser,
            allNotifiersMap.get(notifier) ?? {} as BasicStoreEntityNotifier,
            dataToSend,
            triggersInDataToSend as BasicStoreEntityTrigger[],
            usersFromCache,
          ).catch((reason) => logApp.error('[OPENCTI-MODULE] Publisher manager unknown error.', { cause: reason }));
        }
      }
    }
  }
};

const handleEntityNotificationBuffer = async (forceSend = false) => {
  const dateNow = Date.now();
  const context = executionContext('publisher_manager');
  const bufferKeys = Object.keys(liveNotificationBufferPerEntity);
  // Iterate on all buffers to check if they need to be sent
  for (let i = 0; i < bufferKeys.length; i += 1) {
    const key = bufferKeys[i];
    const value = liveNotificationBufferPerEntity[key];
    if (value) {
      const isBufferingTimeElapsed = (dateNow - value.timestamp) > PUBLISHER_BUFFERING_SECONDS * 1000;
      // If buffer is older than configured buffering time length OR we want to forceSend, it needs to be sent
      if (forceSend || isBufferingTimeElapsed) {
        const bufferEvents = value.events.map((e) => e.data);
        // We remove current buffer from buffers map before processing buffer events, otherwise some new events coming in might be lost
        // This way, if new events are coming in from the stream, they will initiate a new buffer that will be handled later
        delete liveNotificationBufferPerEntity[key];
        const allExistingTriggers = await getNotifications(context);
        const allExistingTriggersMap = new Map(allExistingTriggers.map((n) => [n.trigger.internal_id, n.trigger]));
        await processBufferedEvents(context, allExistingTriggersMap, bufferEvents);
      }
    }
  }
};

const publisherStreamHandler = async (streamEvents: Array<SseEvent<StreamNotifEvent>>) => {
  try {
    if (streamEvents.length === 0) {
      // return;
    }
    const context = executionContext('publisher_manager');
    const notifications = await getNotifications(context);
    const notificationMap = new Map(notifications.map((n) => [n.trigger.internal_id, n.trigger]));
    for (let index = 0; index < streamEvents.length; index += 1) {
      const streamEvent = streamEvents[index];
      const { data: { notification_id, type } } = streamEvent;
      if (type === 'live' || type === 'action') {
        const liveEvent = streamEvent as SseEvent<KnowledgeNotificationEvent>;
        // If buffering is enabled, we store the event in local buffer instead of handling it directly
        if (PUBLISHER_ENABLE_BUFFERING) {
          const liveEventEntityId = liveEvent.data.data.id;
          const currentEntityBuffer = liveNotificationBufferPerEntity[liveEventEntityId];
          // If there are buffered events already, simply add current event to array of buffered events
          if (currentEntityBuffer) {
            currentEntityBuffer.events.push(liveEvent);
          } else { // If there are currently no buffered events for this entity, initialize them using current time as timestamp
            liveNotificationBufferPerEntity[liveEventEntityId] = { timestamp: Date.now(), events: [liveEvent] };
          }
        } else { // If no buffering is enabled, we handle the notification directly
          await processLiveNotificationEvent(context, notificationMap, liveEvent.data);
        }
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
    logApp.error('[OPENCTI-MODULE] Publisher manager stream error', { cause: e, manager: 'PUBLISHER_MANAGER' });
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
      lock = await lockResources([PUBLISHER_ENGINE_KEY], { retryCount: 0 });
      running = true;
      logApp.info('[OPENCTI-PUBLISHER] Running publisher manager');
      const opts = { withInternal: false, streamName: NOTIFICATION_STREAM_NAME, bufferTime: 5000 };
      streamProcessor = createStreamProcessor(SYSTEM_USER, 'Publisher manager', publisherStreamHandler, opts);
      await streamProcessor.start('live');
      while (!shutdown && streamProcessor.running()) {
        lock.signal.throwIfAborted();
        if (PUBLISHER_ENABLE_BUFFERING) {
          await handleEntityNotificationBuffer();
        }
        await wait(WAIT_TIME_ACTION);
      }
      logApp.info('[OPENCTI-MODULE] End of publisher manager processing');
    } catch (e: any) {
      if (e.name === TYPE_LOCK_ERROR) {
        logApp.debug('[OPENCTI-PUBLISHER] Publisher manager already started by another API');
      } else {
        logApp.error('[OPENCTI-MODULE] Publisher manager error', { cause: e, manager: 'PUBLISHER_MANAGER' });
      }
    } finally {
      if (streamProcessor) await streamProcessor.shutdown();
      if (PUBLISHER_ENABLE_BUFFERING) {
        await handleEntityNotificationBuffer(true);
      }
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
