import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { KnowledgeNotificationEvent, NotificationUser } from '../../../src/manager/notificationManager';
import type * as PublisherManagerModule from '../../../src/manager/publisherManager';
import type { BasicStoreEntityTrigger } from '../../../src/modules/notification/notification-types';
import { NOTIFIER_CONNECTOR_EMAIL, NOTIFIER_CONNECTOR_UI } from '../../../src/modules/notifier/notifier-statics';
import type { BasicStoreEntityNotifier } from '../../../src/modules/notifier/notifier-types';
import type { StixObject } from '../../../src/types/stix-2-1-common';
import type { AuthContext, AuthUser } from '../../../src/types/user';

interface SentEmail {
  html: string;
}

interface EmailLimits {
  maxPerHour: number;
  maxPerTriggerRecipientPerHour: number;
}

interface EventBatch {
  publisher: typeof PublisherManagerModule;
  triggerKey: string;
  user: NotificationUser;
  count: number;
}

const mocks = vi.hoisted(() => ({
  sendMail: vi.fn<(email: SentEmail) => Promise<void>>(),
  addNotification: vi.fn<() => Promise<void>>(),
  getEntitiesListFromCache: vi.fn<() => Promise<BasicStoreEntityNotifier[]>>(),
  getEntitiesMapFromCache: vi.fn<() => Promise<Map<string, AuthUser>>>(),
}));

vi.mock('../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn(async () => ({})),
  getEntitiesListFromCache: mocks.getEntitiesListFromCache,
  getEntitiesMapFromCache: mocks.getEntitiesMapFromCache,
}));

vi.mock('../../../src/database/smtp', () => ({
  sendMail: mocks.sendMail,
  smtpComputeFrom: vi.fn(async () => 'OpenCTI <no-reply@opencti.io>'),
  smtpIsAlive: vi.fn(async () => true),
}));

vi.mock('../../../src/modules/notification/notification-domain', () => ({
  addNotification: mocks.addNotification,
}));

vi.mock('../../../src/manager/telemetryManager', () => ({
  addNotificationSentCount: vi.fn(),
}));

// Templates render in a worker pool, a plain serialisation keeps every send inside one event loop turn and exposes the email data.
vi.mock('../../../src/utils/safeEjs.client', () => ({
  safeRender: vi.fn(async (template: string, data: object) => JSON.stringify(data)),
}));

const MID_HOUR = Date.UTC(2026, 9, 30, 10, 30, 0);
const EMAIL_NOTIFIER_ID = 'email-notifier-id';
const UI_NOTIFIER_ID = 'ui-notifier-id';
const TRIGGER_A = 'trigger-a';
const TRIGGER_B = 'trigger-b';
const TRIGGER_C = 'trigger-c';
const TRIGGER_D = 'trigger-d';
const NATIVE_TRIGGER = 'default-trigger-user-u';
const DIGEST_TRIGGER = 'digest-trigger';
const PLAYBOOK_NODE = 'playbook-node-id';
const DELETED_TRIGGER = 'deleted-trigger';

const buildNotifier = (internalId: string, connectorId: string): BasicStoreEntityNotifier => ({
  internal_id: internalId,
  notifier_connector_id: connectorId,
  notifier_configuration: JSON.stringify({ title: 'A title', template: '<p>A body</p>' }),
} as BasicStoreEntityNotifier);

const buildUser = (userId: string): NotificationUser => ({
  user_id: userId,
  user_email: `${userId}@opencti.io`,
  notifiers: [EMAIL_NOTIFIER_ID],
  user_service_account: false,
});

const buildLiveTrigger = (internalId: string): BasicStoreEntityTrigger => ({
  internal_id: internalId,
  id: internalId,
  name: internalId,
  trigger_type: 'live',
} as BasicStoreEntityTrigger);

const USER_U = buildUser('user-u');
const USER_V = buildUser('user-v');

const buildBufferedEvent = (triggerKey: string, message: string): KnowledgeNotificationEvent => ({
  version: '4',
  type: 'live',
  notification_id: triggerKey,
  targets: [{ user: USER_U, type: 'create', message }],
  data: { id: `report--${triggerKey}` } as StixObject,
  origin: {},
});

const TRIGGER_MAP = new Map<string, BasicStoreEntityTrigger>([
  [TRIGGER_A, buildLiveTrigger(TRIGGER_A)],
  [TRIGGER_B, buildLiveTrigger(TRIGGER_B)],
  [TRIGGER_C, buildLiveTrigger(TRIGGER_C)],
  [TRIGGER_D, buildLiveTrigger(TRIGGER_D)],
  // Native per-user triggers carry an internal_id but no id.
  [NATIVE_TRIGGER, { internal_id: NATIVE_TRIGGER, name: 'Default trigger', trigger_type: 'live' } as BasicStoreEntityTrigger],
  [DIGEST_TRIGGER, { internal_id: DIGEST_TRIGGER, id: DIGEST_TRIGGER, name: 'My digest', trigger_type: 'digest' } as BasicStoreEntityTrigger],
  // The publisher adds this virtual trigger, without internal_id, for playbook notifier events.
  [PLAYBOOK_NODE, { name: 'My playbook', trigger_type: 'digest' } as BasicStoreEntityTrigger],
]);

const context = {} as AuthContext;

const settle = () => new Promise<void>((resolve) => {
  setImmediate(resolve);
});

const loadPublisher = async (limits: EmailLimits): Promise<typeof PublisherManagerModule> => {
  vi.resetModules();
  // The limits and the rate limiter state live at publisher module load, so conf is stubbed before each fresh import.
  const { default: conf } = await import('../../../src/config/conf');
  const confGet = conf.get.bind(conf);
  const limitByKey = new Map<string, number>([
    ['publisher_manager:email_max_per_hour', limits.maxPerHour],
    ['publisher_manager:email_max_per_trigger_recipient_per_hour', limits.maxPerTriggerRecipientPerHour],
  ]);
  vi.spyOn(conf, 'get').mockImplementation((key?: string) => (limitByKey.has(key ?? '') ? limitByKey.get(key ?? '') : confGet(key)));
  return import('../../../src/manager/publisherManager');
};

const sendEvents = async (batch: EventBatch) => {
  for (let i = 0; i < batch.count; i += 1) {
    await batch.publisher.processNotificationEvent(context, TRIGGER_MAP, batch.triggerKey, batch.user, [], new Map<string, AuthUser>());
  }
  await settle();
};

describe('Publisher manager notification email rate limit', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(MID_HOUR);
    mocks.sendMail.mockResolvedValue(undefined);
    mocks.addNotification.mockResolvedValue(undefined);
    mocks.getEntitiesListFromCache.mockResolvedValue([
      buildNotifier(EMAIL_NOTIFIER_ID, NOTIFIER_CONNECTOR_EMAIL),
      buildNotifier(UI_NOTIFIER_ID, NOTIFIER_CONNECTOR_UI),
    ]);
    mocks.getEntitiesMapFromCache.mockResolvedValue(new Map<string, AuthUser>([
      [USER_U.user_id, { id: USER_U.user_id, internal_id: USER_U.user_id, name: USER_U.user_id } as AuthUser],
    ]));
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('should stop emailing one recipient once a trigger reaches its hourly cap', async () => {
    const publisher = await loadPublisher({ maxPerHour: 0, maxPerTriggerRecipientPerHour: 5 });

    await sendEvents({ publisher, triggerKey: TRIGGER_A, user: USER_U, count: 8 });

    expect(mocks.sendMail).toHaveBeenCalledTimes(5);
  });

  it('should count each recipient of a trigger separately', async () => {
    const publisher = await loadPublisher({ maxPerHour: 0, maxPerTriggerRecipientPerHour: 5 });

    await sendEvents({ publisher, triggerKey: TRIGGER_A, user: USER_U, count: 5 });
    await sendEvents({ publisher, triggerKey: TRIGGER_A, user: USER_V, count: 5 });

    expect(mocks.sendMail).toHaveBeenCalledTimes(10);
  });

  it('should cap native triggers without id and keep writing their UI notifications', async () => {
    const publisher = await loadPublisher({ maxPerHour: 0, maxPerTriggerRecipientPerHour: 5 });
    const user = { ...USER_U, notifiers: [EMAIL_NOTIFIER_ID, UI_NOTIFIER_ID] };

    await sendEvents({ publisher, triggerKey: NATIVE_TRIGGER, user, count: 8 });

    expect(mocks.sendMail).toHaveBeenCalledTimes(5);
    expect(mocks.addNotification).toHaveBeenCalledTimes(8);
  });

  it('should not apply the trigger and recipient cap to stored digest triggers', async () => {
    const publisher = await loadPublisher({ maxPerHour: 0, maxPerTriggerRecipientPerHour: 1 });

    await sendEvents({ publisher, triggerKey: DIGEST_TRIGGER, user: USER_U, count: 3 });

    expect(mocks.sendMail).toHaveBeenCalledTimes(3);
  });

  it('should apply the trigger and recipient cap to playbook notifier digests', async () => {
    const publisher = await loadPublisher({ maxPerHour: 0, maxPerTriggerRecipientPerHour: 1 });

    await sendEvents({ publisher, triggerKey: PLAYBOOK_NODE, user: USER_U, count: 3 });

    expect(mocks.sendMail).toHaveBeenCalledTimes(1);
  });

  it('should leave capped triggers out of a buffered email and keep data of triggers missing from the map', async () => {
    const publisher = await loadPublisher({ maxPerHour: 0, maxPerTriggerRecipientPerHour: 1 });
    await sendEvents({ publisher, triggerKey: TRIGGER_A, user: USER_U, count: 1 });
    const bufferedEvents = [
      buildBufferedEvent(TRIGGER_A, 'message of trigger a'),
      buildBufferedEvent(TRIGGER_B, 'message of trigger b'),
      buildBufferedEvent(DELETED_TRIGGER, 'message of a deleted trigger'),
    ];

    await publisher.processBufferedEvents(context, TRIGGER_MAP, bufferedEvents);
    await settle();
    await sendEvents({ publisher, triggerKey: TRIGGER_B, user: USER_U, count: 1 });

    expect(mocks.sendMail, 'The buffered email charged the B pair, so the last B event is dropped.').toHaveBeenCalledTimes(2);
    const bufferedEmail = mocks.sendMail.mock.calls[1][0].html;
    expect(bufferedEmail).toContain('message of trigger b');
    expect(bufferedEmail).toContain('message of a deleted trigger');
    expect(bufferedEmail).not.toContain('message of trigger a');
  });

  it('should charge the platform cap only for emails actually sent', async () => {
    const publisher = await loadPublisher({ maxPerHour: 3, maxPerTriggerRecipientPerHour: 1 });

    await sendEvents({ publisher, triggerKey: TRIGGER_A, user: USER_U, count: 2 });
    await sendEvents({ publisher, triggerKey: TRIGGER_B, user: USER_U, count: 1 });
    await sendEvents({ publisher, triggerKey: TRIGGER_C, user: USER_U, count: 1 });
    await sendEvents({ publisher, triggerKey: TRIGGER_D, user: USER_U, count: 1 });

    expect(mocks.sendMail).toHaveBeenCalledTimes(3);
  });
});
