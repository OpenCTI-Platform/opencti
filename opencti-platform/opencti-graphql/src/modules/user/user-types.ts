import type { StixObject } from '../../types/stix-2-1-common';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { UserApiToken } from '../../types/user';
import type { ConfidenceLevel, UserSession } from '../../generated/graphql';
import type { NestedObjectAttribute } from '../../schema/attribute-definition';

export const ENTITY_TYPE_USER = 'User';

export const apiTokens: NestedObjectAttribute = {
  name: 'api_tokens',
  label: 'API Tokens',
  type: 'object',
  format: 'nested',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  isFilterable: false,
  mappings: [
    { name: 'id', label: 'ID', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: false, upsert: true, isFilterable: false },
    { name: 'name', label: 'Name', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: false, upsert: true, isFilterable: false },
    { name: 'hash', label: 'Hash', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: false, upsert: true, isFilterable: false },
    { name: 'masked_token', label: 'Masked Token', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: false, upsert: true, isFilterable: false },
    { name: 'created_at', label: 'Created at', type: 'date', editDefault: false, mandatoryType: 'no', multiple: false, upsert: true, isFilterable: false },
    { name: 'expires_at', label: 'Expires at', type: 'date', editDefault: false, mandatoryType: 'no', multiple: false, upsert: true, isFilterable: false },
  ],
};

// region Database types
export interface UserBookmark {
  id: string;
  type: string;
}

export interface BasicStoreEntityUser extends BasicStoreEntity {
  user_email: string;
  personal_notifiers: Array<string>;
  password: string;
  name: string;
  description: string;
  firstname: string;
  lastname: string;
  theme: string;
  language: string;
  external: boolean;
  bookmarks: Array<UserBookmark>;
  api_tokens: Array<UserApiToken>;
  otp_secret: string;
  otp_qr: string;
  otp_activated: boolean;
  password_valid_until: Date | null;
  default_dashboard: string;
  draft_context: string;
  default_time_field: string;
  account_status: string;
  account_lock_after_date: Date;
  merged_into: string;
  administrated_organizations: string;
  unit_system: string;
  submenu_show_icons: boolean;
  submenu_auto_collapse: boolean;
  monochrome_labels: boolean;
  unsubscribed_news_feed_types: Array<string>;
  user_confidence_level: ConfidenceLevel | null;
  user_service_account: boolean;
}

export interface StoreEntityUser extends BasicStoreEntityUser, StoreEntity {}

export type BasicStoreMember = Pick<BasicStoreEntity, 'id' | 'name' | 'entity_type'>;

export interface StoreUserSession extends Omit<UserSession, 'user'> {
  user_id: string;
}
// endregion

// region Stix type
export interface StixUser extends StixObject {
  name: string;
}
// endregion
