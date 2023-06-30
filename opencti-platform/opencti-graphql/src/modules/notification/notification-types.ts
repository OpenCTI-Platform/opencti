import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { AuthorizedMember } from '../../utils/access';

// Outcomes

// Triggers
export const ENTITY_TYPE_TRIGGER = 'Trigger';

export interface BasicStoreEntityTrigger extends BasicStoreEntity {
  name: string
  description: string
  trigger_type: string
  event_types: string[]
  outcomes: string[]
  user_ids: string[]
  group_ids: string[]
  organization_ids: string[]
  trigger_ids: string[]
  authorized_members: Array<AuthorizedMember>;
  instance_trigger: boolean
}

export interface BasicStoreEntityLiveTrigger extends BasicStoreEntityTrigger {
  trigger_type: 'live'
  filters: string
}

export interface BasicStoreEntityDigestTrigger extends BasicStoreEntityTrigger {
  trigger_type: 'digest'
  period: 'hour' | 'day' | 'week' | 'month'
  trigger_time?: string
  trigger_ids: string[]
}

export interface StoreEntityTrigger extends StoreEntity {
  name: string
  description: string
  trigger_type: string
  event_types: string[]
  outcomes: string[]
  user_ids: string[]
  group_ids: string[]
  organization_ids: string[]
  authorized_members: Array<AuthorizedMember>;
  instance_trigger: boolean
}

export interface StixTrigger extends StixObject {
  name: string
  description: string
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO
  }
}

// region Notifications
export const ENTITY_TYPE_NOTIFICATION = 'Notification';
export const NOTIFICATION_NUMBER = 'NotificationNumber';

export interface NotificationContentEvent {
  operation: string
  message: string
  instance_id: string
}

export interface NotificationAddInput {

  is_read: boolean
  name: string
  notification_type: string
  content: Array<{
    title: string,
    events: Array<NotificationContentEvent>
  }>
}

// region Database types
export interface BasicStoreEntityNotification extends BasicStoreEntity {
  messages: Array<string>
  is_read: boolean
  notification_id: string
  notification_uri: string
  user_id: string
}

export interface StoreEntityNotification extends StoreEntity {
  messages: Array<string>
  is_read: boolean
  notification_id: string
  notification_uri: string
}
// endregion

// Stix type
export interface StixNotification extends StixObject {
  messages: Array<string>
  is_read: boolean
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO
  }
}
// endregion
