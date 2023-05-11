import ejs from 'ejs';
import axios from 'axios';
import { clearIntervalAsync, setIntervalAsync, SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import { createStreamProcessor, lockResource, NOTIFICATION_STREAM_NAME, StreamProcessor } from '../database/redis';
import conf, { booleanConf, getBaseUrl, logApp } from '../config/conf';
import { TYPE_LOCK_ERROR, UnsupportedError } from '../config/errors';
import { executionContext, SYSTEM_USER } from '../utils/access';
import {
  DigestEvent,
  getNotifications,
  NotificationEvent,
  NotificationUser,
  STATIC_OUTCOMES
} from './notificationManager';
import type { SseEvent, StreamNotifEvent } from '../types/event';
import { sendMail, smtpIsAlive } from '../database/smtp';
import { getEntityFromCache } from '../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import type { BasicStoreSettings } from '../types/store';
import { addNotification } from '../modules/notification/notification-domain';
import type { AuthContext } from '../types/user';
import type { StixObject, StixCoreObject, StixRelationshipObject } from '../types/stix-common';
import { hashValue, now } from '../utils/format';
import type { NotificationContentEvent } from '../modules/notification/notification-types';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { findById as findUser } from '../domain/user';
import { findById as findStixCoreObject } from '../domain/stixCoreObject';
import { isStixRelationship } from '../schema/stixRelationship';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INDICATOR,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_VULNERABILITY,
  isStixDomainObjectIdentity,
  isStixDomainObjectLocation
} from '../schema/stixDomainObject';
import {
  ENTITY_TYPE_EXTERNAL_REFERENCE,
  ENTITY_TYPE_KILL_CHAIN_PHASE,
  ENTITY_TYPE_LABEL,
  ENTITY_TYPE_MARKING_DEFINITION
} from '../schema/stixMetaObject';
import {
  ENTITY_AUTONOMOUS_SYSTEM,
  ENTITY_BANK_ACCOUNT,
  ENTITY_CRYPTOGRAPHIC_WALLET,
  ENTITY_DIRECTORY,
  ENTITY_DOMAIN_NAME,
  ENTITY_EMAIL_ADDR,
  ENTITY_EMAIL_MESSAGE,
  ENTITY_EMAIL_MIME_PART_TYPE,
  ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE,
  ENTITY_HOSTNAME,
  ENTITY_IPV4_ADDR,
  ENTITY_IPV6_ADDR,
  ENTITY_MAC_ADDR,
  ENTITY_MEDIA_CONTENT,
  ENTITY_MUTEX,
  ENTITY_NETWORK_TRAFFIC,
  ENTITY_PAYMENT_CARD,
  ENTITY_PHONE_NUMBER,
  ENTITY_PROCESS,
  ENTITY_SOFTWARE,
  ENTITY_TEXT,
  ENTITY_URL,
  ENTITY_USER_ACCOUNT,
  ENTITY_WINDOWS_REGISTRY_KEY,
  ENTITY_WINDOWS_REGISTRY_VALUE_TYPE
} from '../schema/stixCyberObservable';
import type * as SRO from '../types/stix-sro';
import type * as SMO from '../types/stix-smo';
import type * as SDO from '../types/stix-sdo';
import type * as SCO from '../types/stix-sco';
import { getStixRepresentativeConverters } from '../database/stix-converter';

const DOC_URI = 'https://filigran.notion.site/OpenCTI-Public-Knowledge-Base-d411e5e477734c59887dad3649f20518';
const PUBLISHER_ENGINE_KEY = conf.get('publisher_manager:lock_key');
const STREAM_SCHEDULE_TIME = 10000;
const OUTCOME_TYPE_UI = 'UI';
const OUTCOME_TYPE_EMAIL = 'EMAIL';
const OUTCOME_TYPE_WEBHOOK = 'WEBHOOK';

const extractStixRepresentative = async (context: AuthContext, user: NotificationUser, stix: StixObject): Promise<string> => {
  const entityType = stix.extensions[STIX_EXT_OCTI].type;
  // region Modules
  const convertFn = getStixRepresentativeConverters(entityType);
  if (convertFn) {
    return convertFn(stix);
  }
  // endregion
  // region Sighting
  if (isStixSightingRelationship(entityType)) {
    const authUser = await findUser(context, SYSTEM_USER, user.user_id);
    const sighting = stix as SRO.StixSighting;
    const fromId = sighting.extensions[STIX_EXT_OCTI].sighting_of_ref;
    const toIds = sighting.extensions[STIX_EXT_OCTI].where_sighted_refs;
    const fromInstance = await findStixCoreObject(context, authUser, fromId);
    const toInstances = await Promise.all(toIds.map((toId) => findStixCoreObject(context, authUser, toId)));
    const fromValue = fromInstance ? sighting.extensions[STIX_EXT_OCTI].sighting_of_value : 'Restricted';
    const allTargetValues = sighting.extensions[STIX_EXT_OCTI].where_sighted_values;
    const targetValues = [];
    for (let index = 0; index < toInstances.length; index += 1) {
      targetValues.push(toInstances[index] ? allTargetValues[index] : 'Restricted');
    }
    return `${fromValue} sighted in/at ${targetValues.join(', ')}`;
  }
  // endregion
  // region Relationship
  if (isStixRelationship(entityType)) {
    const authUser = await findUser(context, SYSTEM_USER, user.user_id);
    const relation = stix as SRO.StixRelation;
    const fromInstance = await findStixCoreObject(context, authUser, relation.extensions[STIX_EXT_OCTI].source_ref);
    const toInstance = await findStixCoreObject(context, authUser, relation.extensions[STIX_EXT_OCTI].target_ref);
    const fromValue = fromInstance ? relation.extensions[STIX_EXT_OCTI].source_value : 'Restricted';
    const targetValue = toInstance ? relation.extensions[STIX_EXT_OCTI].target_value : 'Restricted';
    return `${fromValue} ${relation.relationship_type} ${targetValue}`;
  }
  // endregion
  // region Entities
  if (isStixDomainObjectIdentity(entityType)) {
    return (stix as SDO.StixIdentity).name;
  }
  if (isStixDomainObjectLocation(entityType)) {
    return (stix as SDO.StixLocation).name;
  }
  if (entityType === ENTITY_TYPE_CONTAINER_REPORT) {
    return (stix as SDO.StixReport).name;
  }
  if (entityType === ENTITY_TYPE_MALWARE) {
    return (stix as SDO.StixMalware).name;
  }
  if (entityType === ENTITY_TYPE_INFRASTRUCTURE) {
    return (stix as SDO.StixInfrastructure).name;
  }
  if (entityType === ENTITY_TYPE_ATTACK_PATTERN) {
    return (stix as SDO.StixAttackPattern).name;
  }
  if (entityType === ENTITY_TYPE_CAMPAIGN) {
    return (stix as SDO.StixCampaign).name;
  }
  if (entityType === ENTITY_TYPE_THREAT_ACTOR) {
    return (stix as SDO.StixThreatActor).name;
  }
  if (entityType === ENTITY_TYPE_CONTAINER_NOTE) {
    return (stix as SDO.StixNote).abstract;
  }
  if (entityType === ENTITY_TYPE_CONTAINER_OPINION) {
    return (stix as SDO.StixOpinion).opinion;
  }
  if (entityType === ENTITY_TYPE_CONTAINER_OBSERVED_DATA) {
    const observed = stix as SDO.StixObservedData;
    const from = observed.first_observed?.toISOString() ?? '-inf';
    const to = observed.last_observed?.toISOString() ?? '+inf';
    return `${from} - ${to}`;
  }
  if (entityType === ENTITY_TYPE_COURSE_OF_ACTION) {
    return (stix as SDO.StixCourseOfAction).name;
  }
  if (entityType === ENTITY_TYPE_INCIDENT) {
    return (stix as SDO.StixIncident).name;
  }
  if (entityType === ENTITY_TYPE_INDICATOR) {
    return (stix as SDO.StixIndicator).name;
  }
  if (entityType === ENTITY_TYPE_INTRUSION_SET) {
    return (stix as SDO.StixIntrusionSet).name;
  }
  if (entityType === ENTITY_TYPE_TOOL) {
    return (stix as SDO.StixTool).name;
  }
  if (entityType === ENTITY_TYPE_VULNERABILITY) {
    return (stix as SDO.StixVulnerability).name;
  }
  // endregion
  // region meta entities
  if (entityType === ENTITY_TYPE_MARKING_DEFINITION) {
    return (stix as SMO.StixMarkingDefinition).name;
  }
  if (entityType === ENTITY_TYPE_LABEL) {
    return (stix as SMO.StixLabel).value;
  }
  if (entityType === ENTITY_TYPE_EXTERNAL_REFERENCE) {
    const externalRef = stix as SMO.StixExternalReference;
    return `${externalRef.source_name}${externalRef.external_id ? ` (${externalRef.external_id})` : ''}`;
  }
  if (entityType === ENTITY_TYPE_KILL_CHAIN_PHASE) {
    return (stix as SMO.StixKillChainPhase).kill_chain_name;
  }
  // endregion
  // region Meta observable
  if (entityType === ENTITY_WINDOWS_REGISTRY_VALUE_TYPE) {
    const registry = stix as SCO.StixWindowsRegistryValueType;
    return registry.name ?? registry.data ?? 'Unknown';
  }
  if (entityType === ENTITY_EMAIL_MIME_PART_TYPE) {
    return (stix as SCO.StixEmailBodyMultipart).description;
  }
  // endregion
  // region Observables
  if (entityType === ENTITY_HASHED_OBSERVABLE_ARTIFACT) {
    const artifact = stix as SCO.StixArtifact;
    return hashValue(artifact) ?? artifact.payload_bin ?? artifact.url ?? 'Unknown';
  }
  if (entityType === ENTITY_AUTONOMOUS_SYSTEM) {
    const autonomous = stix as SCO.StixAutonomousSystem;
    return autonomous.name ?? autonomous.number ?? 'unknown';
  }
  if (entityType === ENTITY_BANK_ACCOUNT) {
    const bankAccount = stix as SCO.StixBankAccount;
    return bankAccount.iban ?? bankAccount.account_number ?? 'Unknown';
  }
  if (entityType === ENTITY_CRYPTOGRAPHIC_WALLET) {
    return (stix as SCO.StixCryptocurrencyWallet).value ?? 'Unknown';
  }
  if (entityType === ENTITY_DIRECTORY) {
    return (stix as SCO.StixDirectory).path ?? 'Unknown';
  }
  if (entityType === ENTITY_DOMAIN_NAME) {
    return (stix as SCO.StixDomainName).value ?? 'Unknown';
  }
  if (entityType === ENTITY_EMAIL_ADDR) {
    return (stix as SCO.StixEmailAddress).value ?? 'Unknown';
  }
  if (entityType === ENTITY_EMAIL_MESSAGE) {
    const email = stix as SCO.StixEmailMessage;
    return email.body ?? email.subject ?? 'Unknown';
  }
  if (entityType === ENTITY_HASHED_OBSERVABLE_STIX_FILE) {
    const file = stix as SCO.StixFile;
    return hashValue(file) ?? file.name ?? 'Unknown';
  }
  if (entityType === ENTITY_HOSTNAME) {
    return (stix as SCO.StixHostname).value ?? 'Unknown';
  }
  if (entityType === ENTITY_IPV4_ADDR) {
    return (stix as SCO.StixIPv4Address).value ?? 'Unknown';
  }
  if (entityType === ENTITY_IPV6_ADDR) {
    return (stix as SCO.StixIPv6Address).value ?? 'Unknown';
  }
  if (entityType === ENTITY_MAC_ADDR) {
    return (stix as SCO.StixMacAddress).value ?? 'Unknown';
  }
  if (entityType === ENTITY_MEDIA_CONTENT) {
    const media = stix as SCO.StixMediaContent;
    return media.content ?? media.title ?? media.url ?? 'Unknown';
  }
  if (entityType === ENTITY_MUTEX) {
    return (stix as SCO.StixMutex).name ?? 'Unknown';
  }
  if (entityType === ENTITY_NETWORK_TRAFFIC) {
    return String((stix as SCO.StixNetworkTraffic).dst_port ?? 'Unknown');
  }
  if (entityType === ENTITY_PROCESS) {
    const process = stix as SCO.StixProcess;
    return String(process.pid ?? process.command_line ?? 'Unknown');
  }
  if (entityType === ENTITY_SOFTWARE) {
    return (stix as SCO.StixSoftware).name ?? 'Unknown';
  }
  if (entityType === ENTITY_TEXT) {
    return (stix as SCO.StixText).value ?? 'Unknown';
  }
  if (entityType === ENTITY_PHONE_NUMBER) {
    return (stix as SCO.StixPhoneNumber).value ?? 'Unknown';
  }
  if (entityType === ENTITY_PAYMENT_CARD) {
    const paymentCard = stix as SCO.StixPaymentCard;
    return paymentCard.card_number ?? paymentCard.holder_name ?? 'Unknown';
  }
  if (entityType === ENTITY_URL) {
    return (stix as SCO.StixURL).value ?? 'Unknown';
  }
  if (entityType === ENTITY_USER_ACCOUNT) {
    const userAccount = stix as SCO.StixUserAccount;
    return userAccount.account_login ?? userAccount.user_id ?? 'Unknown';
  }
  if (entityType === ENTITY_WINDOWS_REGISTRY_KEY) {
    return (stix as SCO.StixWindowsRegistryKey).key ?? 'Unknown';
  }
  if (entityType === ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE) {
    const x509 = stix as SCO.StixX509Certificate;
    return hashValue(x509) ?? x509.subject ?? x509.issuer ?? 'Unknown';
  }
  // endregion
  throw UnsupportedError(`No representative extractor available for ${entityType}`);
};

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
  const userOutcomes = user.outcomes ?? []; // No outcome is possible for live trigger only targeting digest
  for (let outcomeIndex = 0; outcomeIndex < userOutcomes.length; outcomeIndex += 1) {
    const outcome = userOutcomes[outcomeIndex];
    const { outcome_type, configuration } = outcomeMap.get(outcome) ?? {};
    const generatedContent: Record<string, Array<NotificationContentEvent>> = {};
    for (let index = 0; index < data.length; index += 1) {
      const { notification_id, instance, type } = data[index];
      const instanceRepresentative = await extractStixRepresentative(context, user, instance);
      const event = { operation: type, message: `[${instance.type}] ${instanceRepresentative}`, instance_id: instance.id };
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
  let isSmtpActive = false;
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
      lock = await lockResource([PUBLISHER_ENGINE_KEY], { retryCount: 0 });
      logApp.info('[OPENCTI-MODULE] Running publisher manager');
      const opts = { withInternal: false, streamName: NOTIFICATION_STREAM_NAME };
      streamProcessor = createStreamProcessor(SYSTEM_USER, 'Publisher manager', publisherStreamHandler, opts);
      await streamProcessor.start('live');
      while (publisherListening) {
        await wait(WAIT_TIME_ACTION);
      }
    } catch (e: any) {
      if (e.name === TYPE_LOCK_ERROR) {
        logApp.debug('[OPENCTI-MODULE] Publisher manager already started by another API');
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
      isSmtpActive = await smtpIsAlive();
      streamScheduler = setIntervalAsync(() => notificationHandler(), STREAM_SCHEDULE_TIME);
    },
    status: () => {
      return {
        id: 'PUBLISHER_MANAGER',
        enable: booleanConf('publisher_manager:enabled', false),
        is_smtp_active: isSmtpActive,
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
