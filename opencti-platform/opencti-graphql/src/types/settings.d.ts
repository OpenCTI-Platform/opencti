import type { BasicStoreEntity } from './store';
import type { XtmHubRegistrationStatus } from '../generated/graphql';

export interface BasicStoreSettingsMessage {
  id: string
  message: string
  activated: boolean
  updated_at: Date
  dismissible: boolean
  color: string
}

export interface BasicStoreSettings extends BasicStoreEntity {
  platform_email: string
  platform_organization: string
  platform_theme_dark_background: string
  platform_title?: string
  enterprise_license?: string
  valid_enterprise_edition?: boolean
  activity_listeners_ids?: string[]
  activity_listeners_users?: string[]
  messages?: BasicStoreSettingsMessage[]
  xtm_hub_token?: string
  xtm_hub_registration_status?: XtmHubRegistrationStatus
  xtm_hub_registration_user_id?: string
  xtm_hub_registration_user_name?: string
  xtm_hub_registration_date?: Date
}
