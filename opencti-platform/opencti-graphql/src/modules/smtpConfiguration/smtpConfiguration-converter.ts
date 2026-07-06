import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { buildStixObject } from '../../database/stix-2-1-converter';
import { cleanObject } from '../../database/stix-converter-utils';
import type { StixSmtpConfiguration, StoreEntitySmtpConfiguration } from './smtpConfiguration-types';

const convertSmtpConfigurationToStix = (instance: StoreEntitySmtpConfiguration): StixSmtpConfiguration => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    smtp_enabled: instance.smtp_enabled,
    use_db_config: instance.use_db_config,
    sender_email_address: instance.sender_email_address,
    hostname: instance.hostname,
    port: instance.port,
    use_ssl: instance.use_ssl,
    reject_unauthorized: instance.reject_unauthorized,
    auth_type: instance.auth_type,
    username: instance.username,
    oauth_user: instance.oauth_user,
    oauth_client_id: instance.oauth_client_id,
    oauth_issuer: instance.oauth_issuer,
    oauth_refresh_token_expires_at: instance.oauth_refresh_token_expires_at,
    // Secrets are intentionally excluded from the STIX representation
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export default convertSmtpConfigurationToStix;
