import type { BasicStoreEntity } from './store';
import type { XtmHubRegistrationStatus, CguStatus } from '../generated/graphql';

export interface BasicStoreSettingsMessage {
  id: string;
  message: string;
  activated: boolean;
  updated_at: Date;
  dismissible: boolean;
  color: string;
}

export interface BasicStoreSettings extends BasicStoreEntity {
  platform_url: string
  platform_email: string
  platform_organization: string
  platform_theme_dark_background: string
  platform_title?: string
  enterprise_license?: string
  valid_enterprise_edition?: boolean
  activity_listeners_ids?: string[]
  activity_listeners_users?: string[]
  messages?: BasicStoreSettingsMessage[]
  filigran_chatbot_ai_url?: string
  filigran_agentic_ai_url?: string
  xtm_hub_token?: string
  xtm_hub_registration_status?: XtmHubRegistrationStatus
  xtm_hub_registration_user_id?: string
  xtm_hub_registration_user_name?: string
  xtm_hub_registration_date?: Date
  xtm_hub_last_connectivity_check?: Date
  xtm_hub_should_send_connectivity_email?: boolean
  xtm_hub_backend_is_reachable?: boolean
  platform_ai_enabled: boolean
  filigran_chatbot_ai_cgu_status: CguStatus
  view_all_users: boolean
}
