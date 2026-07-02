import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { SmtpAuthType } from '../../generated/graphql';

export { SmtpAuthType };

export const ENTITY_TYPE_SMTP_CONFIGURATION = 'SmtpConfiguration';

export interface BasicStoreEntitySmtpConfiguration extends BasicStoreEntity {
  smtp_enabled: boolean;
  use_db_config: boolean;
  sender_email_address?: string;
  hostname?: string;
  port?: number;
  use_ssl?: boolean;
  reject_unauthorized?: boolean;
  auth_type?: SmtpAuthType;
  // Basic Auth
  username?: string;
  password?: string;
  // OAuth2
  oauth_user?: string;
  oauth_client_id?: string;
  oauth_client_secret?: string;
  oauth_issuer?: string;
  oauth_access_token?: string;
  oauth_refresh_token?: string;
}

export interface StoreEntitySmtpConfiguration extends StoreEntity {
  smtp_enabled: boolean;
  use_db_config: boolean;
  sender_email_address?: string;
  hostname?: string;
  port?: number;
  use_ssl?: boolean;
  reject_unauthorized?: boolean;
  auth_type?: SmtpAuthType;
  username?: string;
  password?: string;
  oauth_user?: string;
  oauth_client_id?: string;
  oauth_client_secret?: string;
  oauth_issuer?: string;
  oauth_access_token?: string;
  oauth_refresh_token?: string;
}

export interface StixSmtpConfiguration extends StixObject {
  smtp_enabled: boolean;
  use_db_config: boolean;
  sender_email_address?: string;
  hostname?: string;
  port?: number;
  use_ssl?: boolean;
  reject_unauthorized?: boolean;
  auth_type?: SmtpAuthType;
  username?: string;
  oauth_user?: string;
  oauth_client_id?: string;
  oauth_issuer?: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
