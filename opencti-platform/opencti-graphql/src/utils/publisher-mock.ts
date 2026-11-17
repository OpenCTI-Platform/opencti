import type { BasicStoreEntityTrigger } from '../modules/notification/notification-types';
import type { StixCoreObject, StixId, StixRelationshipObject } from '../types/stix-2-1-common';
import type { EditInput } from '../generated/graphql';

export interface NotificationData {
  notification_id: string;
  instance: (StixCoreObject | StixRelationshipObject | Partial<{ id: string | StixId | null }>) & { entity_type?: string; name?: string; input?: EditInput[] };
  type: string;
  message: string;
}

// All the data below is fake and only used by the notifier "Test" button.
// It does not rely on any entity existing in the platform, and every instance is a plain object
// (no `extensions`) so that its representative is computed from its `name`.
const DEFAULT_NOTIFICATION: NotificationData = {
  notification_id: 'default_notification_id',
  instance: {
    id: 'report--00000000-0000-4000-8000-000000000001',
    type: 'report',
    entity_type: 'Report',
    name: '[TEST] Sample report',
  },
  type: 'create',
  message: '[TEST] Creates a report with name : [TEST] Sample report',
};

const DEFAULT_DIGEST: NotificationData[] = [
  DEFAULT_NOTIFICATION,
  {
    notification_id: 'default_notification_id_2',
    instance: {
      id: 'malware--00000000-0000-4000-8000-000000000002',
      type: 'malware',
      entity_type: 'Malware',
      name: '[TEST] Sample malware',
    },
    type: 'update',
    message: '[TEST] Updates a malware with name : [TEST] Sample malware',
  },
];

const DEFAULT_ACTIVITY: NotificationData = {
  notification_id: 'default_activity_id',
  instance: {
    id: 'sync--00000000-0000-4000-8000-000000000003',
    type: 'sync',
    entity_type: 'Sync',
    name: '[TEST] Sample synchronizer',
    input: [
      {
        key: 'name',
        value: [
          '[TEST] Sample synchronizer',
        ],
      },
    ],
  },
  type: 'update',
  message: '`admin` updates `name` for synchronizer `[TEST] Sample synchronizer`',
};

export const MOCK_NOTIFICATIONS: Record<string, NotificationData[]> = {
  default_notification: [DEFAULT_NOTIFICATION],
  default_digest: DEFAULT_DIGEST,
  default_activity: [DEFAULT_ACTIVITY],
};

// The trigger a test notification claims to come from, keyed like MOCK_NOTIFICATIONS.
export const MOCK_TRIGGERS: Record<string, { name: string; trigger_type: 'live' | 'digest' }> = {
  default_notification: { name: '[TEST] Sample live trigger', trigger_type: 'live' },
  default_digest: { name: '[TEST] Sample digest trigger', trigger_type: 'digest' },
  default_activity: { name: '[TEST] Sample activity trigger', trigger_type: 'live' },
};

// The input testNotifier gives to the notification processing for a test id: the notifications, the fake trigger
// they are attached to (so templates and `$` variables see its name and type) and the notification map.
// Returns undefined when the id is not a known test notification.
export const buildMockNotificationInput = (testId: string) => {
  if (!Object.hasOwn(MOCK_TRIGGERS, testId) || !Object.hasOwn(MOCK_NOTIFICATIONS, testId)) {
    return undefined;
  }
  const mockTrigger = MOCK_TRIGGERS[testId];
  const notifications = MOCK_NOTIFICATIONS[testId];
  const notificationMap = new Map(
    notifications.map(({ notification_id }) => [notification_id, { name: mockTrigger.name } as BasicStoreEntityTrigger]),
  );
  const triggers = [{ created: (new Date()).toISOString(), ...mockTrigger }] as unknown as BasicStoreEntityTrigger[];
  return { notificationMap, triggers, notifications };
};
