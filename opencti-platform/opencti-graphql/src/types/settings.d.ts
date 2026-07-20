import type { BasicStoreEntity } from './store';
import type { XtmHubRegistrationStatus, CguStatus, SmtpAuthType } from '../generated/graphql';
import type { GroupsMapping, OrganizationsMapping, UserInfoMapping } from '../modules/authenticationProvider/authenticationProvider-types';

export interface BasicStoreSettingsMessage {
  id: string;
  message: string;
  activated: boolean;
  updated_at: Date;
  dismissible: boolean;
  color: string;
}

export type CertAuthConfig = {
  enabled: boolean;
  description: string;
  button_label_override: string;
  user_info_mapping: UserInfoMapping;
  groups_mapping: GroupsMapping;
  organizations_mapping: OrganizationsMapping;
};

export type LocalAuthConfig = {
  enabled: boolean;
  button_label_override: string;
};

export type HeadersAuthConfig = {
  enabled: boolean;
  description: string;
  button_label_override: string;
  user_info_mapping: UserInfoMapping;
  groups_mapping: GroupsMapping;
  organizations_mapping: OrganizationsMapping;
  headers_audit: string[];
  logout_uri?: string;
};

export type SmtpConfiguration = {
  smtp_enabled: boolean;
  use_db_config: boolean;
  forced_sender_email: boolean;
  sender_email_address: string;
  hostname: string;
  port: number;
  use_ssl: boolean;
  reject_unauthorized: boolean;
  auth_type?: SmtpAuthType;
  username: string;
  password_encrypted: string;
  oauth_user: string;
  oauth_client_id: string;
  oauth_client_secret_encrypted: string;
  oauth_issuer: string;
  oauth_refresh_token_encrypted: string;
  oauth_refresh_token_expires_at: Date;
};

export interface BasicStoreSettings extends BasicStoreEntity {
  platform_url: string;
  platform_email: string;
  platform_organization: string;
  platform_theme_dark_background: string;
  platform_title?: string;
  enterprise_license?: string;
  valid_enterprise_edition?: boolean;
  activity_listeners_ids?: string[];
  activity_listeners_users?: string[];
  messages?: BasicStoreSettingsMessage[];
  filigran_chatbot_ai_url?: string;
  filigran_agentic_ai_url?: string;
  xtm_hub_token?: string;
  xtm_hub_registration_status?: XtmHubRegistrationStatus;
  xtm_hub_registration_user_id?: string;
  xtm_hub_registration_user_name?: string;
  xtm_hub_registration_date?: Date;
  xtm_hub_last_connectivity_check?: Date;
  xtm_hub_should_send_connectivity_email?: boolean;
  xtm_hub_backend_is_reachable?: boolean;
  xtm_hub_available_news_feed_types?: string[];
  platform_ai_enabled: boolean;
  platform_notifier_auto_trigger_assignee?: boolean;
  filigran_chatbot_ai_cgu_status: CguStatus;
  view_all_users: boolean;
  platform_ip_whitelist?: string[];
  platform_ip_whitelist_enabled?: boolean;
  platform_ip_whitelist_exclusion_ids?: string[];
  auth_strategy_migrated: string[];
  local_auth?: LocalAuthConfig;
  cert_auth?: CertAuthConfig;
  headers_auth?: HeadersAuthConfig;
  password_policy_validity_days?: number;
  smtp_configuration?: SmtpConfiguration;
}
