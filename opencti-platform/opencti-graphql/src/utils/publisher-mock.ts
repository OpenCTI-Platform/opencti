import type { StixCoreObject, StixId, StixRelationshipObject } from '../types/stix-2-1-common';

export interface NotificationData {
  notification_id: string;
  instance: (StixCoreObject | StixRelationshipObject | Partial<{ id: string | StixId | null }>) & { entity_type?: string };
  type: string;
  message: string;
}

// All the data below is fake and only used by the notifier "Test" button.
// It does not rely on any entity existing in the platform, and every instance is a plain object
// (no `extensions`) so that its representative is computed from its `name`.
const DEFAULT_NOTIFICATION = {
  notification_id: 'default_notification_id',
  instance: {
    id: 'report--00000000-0000-4000-8000-000000000001',
    type: 'report',
    entity_type: 'Report',
    name: '[TEST] Sample report',
  },
  type: 'create',
  message: '[TEST] Creates a report with name : [TEST] Sample report',
} as NotificationData;

const DEFAULT_DIGEST = [
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
] as NotificationData[];

const DEFAULT_ACTIVITY = {
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
} as NotificationData;

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
