var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import ejs from 'ejs';
import * as R from 'ramda';
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/fixed';
import conf, { booleanConf, getBaseUrl, logApp } from '../config/conf';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { getEntitiesListFromCache, getEntityFromCache } from '../database/cache';
import { createStreamProcessor, lockResource, NOTIFICATION_STREAM_NAME } from '../database/redis';
import { sendMail, smtpIsAlive } from '../database/smtp';
import { addNotification } from '../modules/notification/notification-domain';
import { NOTIFIER_CONNECTOR_EMAIL, NOTIFIER_CONNECTOR_SIMPLIFIED_EMAIL, NOTIFIER_CONNECTOR_UI, NOTIFIER_CONNECTOR_WEBHOOK, SIMPLIFIED_EMAIL_TEMPLATE, } from '../modules/notifier/notifier-statics';
import { ENTITY_TYPE_NOTIFIER } from '../modules/notifier/notifier-types';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { now } from '../utils/format';
import { getNotifications } from './notificationManager';
import { getHttpClient } from '../utils/http-client';
const DOC_URI = 'https://docs.opencti.io';
const PUBLISHER_ENGINE_KEY = conf.get('publisher_manager:lock_key');
const STREAM_SCHEDULE_TIME = 10000;
export const internalProcessNotification = (context, settings, notificationMap, user, notifier, data, notification) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const { name: notification_name, trigger_type } = notification;
        const { notifier_connector_id, notifier_configuration: configuration } = notifier;
        const generatedContent = {};
        for (let index = 0; index < data.length; index += 1) {
            const { notification_id, instance, type, message } = data[index];
            const event = { operation: type, message, instance_id: instance.id };
            const eventNotification = notificationMap.get(notification_id);
            if (eventNotification) {
                const notificationName = eventNotification.name;
                if (generatedContent[notificationName]) {
                    generatedContent[notificationName] = [...generatedContent[notificationName], event];
                }
                else {
                    generatedContent[notificationName] = [event];
                }
            }
        }
        const content = Object.entries(generatedContent).map(([k, v]) => ({ title: k, events: v }));
        // region data generation
        const background_color = ((_a = settings.platform_theme_dark_background) !== null && _a !== void 0 ? _a : '#0a1929').substring(1);
        const platformOpts = { doc_uri: DOC_URI, platform_uri: getBaseUrl(), background_color };
        const templateData = Object.assign({ content, notification_content: content, notification, settings, user, data }, platformOpts);
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
        }
        else if (notifier_connector_id === NOTIFIER_CONNECTOR_EMAIL) {
            const { title, template } = JSON.parse(configuration !== null && configuration !== void 0 ? configuration : '{}');
            const generatedTitle = ejs.render(title, templateData);
            const generatedEmail = ejs.render(template, templateData);
            const mail = { from: settings.platform_email, to: user.user_email, subject: generatedTitle, html: generatedEmail };
            yield sendMail(mail).catch((err) => {
                logApp.error(err, { manager: 'PUBLISHER_MANAGER' });
                return { error: err };
            });
        }
        else if (notifier_connector_id === NOTIFIER_CONNECTOR_SIMPLIFIED_EMAIL) {
            const { title, header, logo, footer, background_color: bgColor, } = JSON.parse(configuration !== null && configuration !== void 0 ? configuration : '{}');
            const finalTemplateData = Object.assign(Object.assign({}, templateData), { header,
                logo,
                footer, background_color: bgColor });
            const generatedTitle = ejs.render(title, finalTemplateData);
            const generatedEmail = ejs.render(SIMPLIFIED_EMAIL_TEMPLATE, finalTemplateData);
            const mail = { from: settings.platform_email, to: user.user_email, subject: generatedTitle, html: generatedEmail };
            yield sendMail(mail).catch((err) => {
                logApp.error(err, { manager: 'PUBLISHER_MANAGER' });
                return { error: err };
            });
        }
        else if (notifier_connector_id === NOTIFIER_CONNECTOR_WEBHOOK) {
            const { url, template, verb, params, headers } = JSON.parse(configuration !== null && configuration !== void 0 ? configuration : '{}');
            const generatedWebhook = ejs.render(template, templateData);
            const dataJson = JSON.parse(generatedWebhook);
            const dataHeaders = R.fromPairs((headers !== null && headers !== void 0 ? headers : []).map((h) => [h.attribute, h.value]));
            const dataParameters = R.fromPairs((params !== null && params !== void 0 ? params : []).map((h) => [h.attribute, h.value]));
            const httpClient = getHttpClient({ responseType: 'json', headers: dataHeaders });
            yield httpClient({ url, method: verb, params: dataParameters, data: dataJson }).catch((err) => {
                logApp.error(err, { manager: 'PUBLISHER_MANAGER' });
                return { error: err };
            });
        }
        else {
            // Push the event to the external connector
            // TODO
        }
    }
    catch (e) {
        return { error: e.message };
    }
});
const processNotificationEvent = (context, notificationMap, notificationId, user, data) => __awaiter(void 0, void 0, void 0, function* () {
    var _b, _c;
    const settings = yield getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
    const notification = notificationMap.get(notificationId);
    if (!notification) {
        return;
    }
    const userNotifiers = (_b = user.notifiers) !== null && _b !== void 0 ? _b : []; // No notifier is possible for live trigger only targeting digest
    const notifiers = yield getEntitiesListFromCache(context, SYSTEM_USER, ENTITY_TYPE_NOTIFIER);
    const notifierMap = new Map(notifiers.map((n) => [n.internal_id, n]));
    for (let notifierIndex = 0; notifierIndex < userNotifiers.length; notifierIndex += 1) {
        const notifier = userNotifiers[notifierIndex];
        internalProcessNotification(context, settings, notificationMap, user, (_c = notifierMap.get(notifier)) !== null && _c !== void 0 ? _c : {}, data, notification);
    }
});
const processLiveNotificationEvent = (context, notificationMap, event) => __awaiter(void 0, void 0, void 0, function* () {
    const { targets, data: instance } = event;
    for (let index = 0; index < targets.length; index += 1) {
        const { user, type, message } = targets[index];
        const data = [{ notification_id: event.notification_id, instance, type, message }];
        yield processNotificationEvent(context, notificationMap, event.notification_id, user, data);
    }
});
const processDigestNotificationEvent = (context, notificationMap, event) => __awaiter(void 0, void 0, void 0, function* () {
    const { target: user, data } = event;
    yield processNotificationEvent(context, notificationMap, event.notification_id, user, data);
});
const publisherStreamHandler = (streamEvents) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const context = executionContext('publisher_manager');
        const notifications = yield getNotifications(context);
        const notificationMap = new Map(notifications.map((n) => [n.trigger.internal_id, n.trigger]));
        for (let index = 0; index < streamEvents.length; index += 1) {
            const streamEvent = streamEvents[index];
            const { data: { notification_id, type } } = streamEvent;
            if (type === 'live') {
                const liveEvent = streamEvent;
                yield processLiveNotificationEvent(context, notificationMap, liveEvent.data);
            }
            if (type === 'digest') {
                const digestEvent = streamEvent;
                // Add virtual notification in map for playbook execution
                if (digestEvent.data.playbook_source) {
                    notificationMap.set(notification_id, { name: digestEvent.data.playbook_source, trigger_type: type });
                }
                yield processDigestNotificationEvent(context, notificationMap, digestEvent.data);
            }
        }
    }
    catch (e) {
        logApp.error(e, { manager: 'PUBLISHER_MANAGER' });
    }
});
const initPublisherManager = () => {
    const WAIT_TIME_ACTION = 2000;
    let streamScheduler;
    let streamProcessor;
    let running = false;
    let shutdown = false;
    let isSmtpActive = false;
    const wait = (ms) => {
        return new Promise((resolve) => {
            setTimeout(resolve, ms);
        });
    };
    const notificationHandler = () => __awaiter(void 0, void 0, void 0, function* () {
        let lock;
        try {
            // Lock the manager
            lock = yield lockResource([PUBLISHER_ENGINE_KEY], { retryCount: 0 });
            running = true;
            logApp.info('[OPENCTI-PUBLISHER] Running publisher manager');
            const opts = { withInternal: false, streamName: NOTIFICATION_STREAM_NAME };
            streamProcessor = createStreamProcessor(SYSTEM_USER, 'Publisher manager', publisherStreamHandler, opts);
            yield streamProcessor.start('live');
            while (!shutdown && streamProcessor.running()) {
                lock.signal.throwIfAborted();
                yield wait(WAIT_TIME_ACTION);
            }
            logApp.info('[OPENCTI-MODULE] End of publisher manager processing');
        }
        catch (e) {
            if (e.name === TYPE_LOCK_ERROR) {
                logApp.debug('[OPENCTI-PUBLISHER] Publisher manager already started by another API');
            }
            else {
                logApp.error(e, { manager: 'PUBLISHER_MANAGER' });
            }
        }
        finally {
            if (streamProcessor)
                yield streamProcessor.shutdown();
            if (lock)
                yield lock.unlock();
        }
    });
    return {
        start: () => __awaiter(void 0, void 0, void 0, function* () {
            isSmtpActive = yield smtpIsAlive();
            streamScheduler = setIntervalAsync(() => __awaiter(void 0, void 0, void 0, function* () {
                yield notificationHandler();
            }), STREAM_SCHEDULE_TIME);
        }),
        status: () => {
            return {
                id: 'PUBLISHER_MANAGER',
                enable: booleanConf('publisher_manager:enabled', false),
                is_smtp_active: isSmtpActive,
                running,
            };
        },
        shutdown: () => __awaiter(void 0, void 0, void 0, function* () {
            logApp.info('[OPENCTI-MODULE] Stopping publisher manager');
            shutdown = true;
            if (streamScheduler)
                yield clearIntervalAsync(streamScheduler);
            return true;
        }),
    };
};
const publisherManager = initPublisherManager();
export default publisherManager;
