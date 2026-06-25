import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { ENTITY_TYPE_SMTP_CONFIGURATION, type StixSmtpConfiguration, type StoreEntitySmtpConfiguration } from './smtpConfiguration-types';
import convertSmtpConfigurationToStix from './smtpConfiguration-converter';

const SMTP_CONFIGURATION_DEFINITION: ModuleDefinition<StoreEntitySmtpConfiguration, StixSmtpConfiguration> = {
  type: {
    id: 'smtp-configuration',
    name: ENTITY_TYPE_SMTP_CONFIGURATION,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_SMTP_CONFIGURATION]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'smtp_enabled', label: 'SMTP enabled', type: 'boolean', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'use_db_config', label: 'Use DB configuration', type: 'boolean', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'sender_email_address', label: 'Sender email address', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'hostname', label: 'Hostname', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'port', label: 'Port', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'use_ssl', label: 'Use SSL', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'reject_unauthorized', label: 'Reject unauthorized', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'auth_type', label: 'Auth type', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'username', label: 'Username', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'password', label: 'Password', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'oauth_user', label: 'OAuth user', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'oauth_client_id', label: 'OAuth client ID', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'oauth_client_secret', label: 'OAuth client secret', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'oauth_issuer', label: 'OAuth issuer', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'oauth_access_token', label: 'OAuth access token', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'oauth_refresh_token', label: 'OAuth refresh token', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
  relations: [],
  representative: (_instance: StixSmtpConfiguration) => {
    return ENTITY_TYPE_SMTP_CONFIGURATION;
  },
  converter_2_1: convertSmtpConfigurationToStix,
};

registerDefinition(SMTP_CONFIGURATION_DEFINITION);
