import type { AuthContext, AuthUser } from '../../types/user';
import { createInternalObject, deleteInternalObject } from '../../domain/internalObject';
import { patchAttribute } from '../../database/middleware';
import { fullEntitiesList } from '../../database/middleware-loader';
import { FunctionalError } from '../../config/errors';
import { type BasicStoreEntitySmtpConfiguration, ENTITY_TYPE_SMTP_CONFIGURATION, type StoreEntitySmtpConfiguration } from './smtpConfiguration-types';
import { SmtpAuthType, type SmtpConfigurationAddInput, type SmtpConfigurationEditInput } from '../../generated/graphql';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { smtpTest } from '../../database/smtp';

const validateSmtpConfigurationInput = (input: SmtpConfigurationAddInput | SmtpConfigurationEditInput) => {
  if (input.port === 25) {
    throw FunctionalError('Port 25 is not allowed for SMTP configuration');
  }
  if (input.auth_type === SmtpAuthType.Basic && (!input.username || !input.password)) {
    throw FunctionalError('username and password are required for basic authentication');
  }
  if (input.auth_type === SmtpAuthType.Oauth2 && (!input.oauth_client_id || !input.oauth_client_secret || !input.oauth_issuer)) {
    throw FunctionalError('oauth_client_id, oauth_client_secret and oauth_issuer are required for OAuth2 authentication');
  }
};

export const smtpConfigurationAdd = async (
  context: AuthContext,
  user: AuthUser,
  input: SmtpConfigurationAddInput,
): Promise<BasicStoreEntitySmtpConfiguration> => {
  const existing = await getSmtpConfiguration(context, user);
  if (existing) {
    throw FunctionalError('An SMTP configuration already exists');
  }
  validateSmtpConfigurationInput(input);
  // TODO(Chunk 2): secrets will be encrypted before storage.
  return createInternalObject<StoreEntitySmtpConfiguration>(
    context,
    user,
    input,
    ENTITY_TYPE_SMTP_CONFIGURATION,
  );
};

export const getSmtpConfiguration = async (
  context: AuthContext,
  user: AuthUser,
): Promise<BasicStoreEntitySmtpConfiguration | null> => {
  const configurations = await fullEntitiesList<BasicStoreEntitySmtpConfiguration>(
    context,
    user,
    [ENTITY_TYPE_SMTP_CONFIGURATION],
  );
  if (configurations.length > 1) {
    throw FunctionalError('Multiple SMTP configurations found in database, only one is allowed');
  }
  return configurations[0] ?? null;
};

export const smtpConfigurationUpdate = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
  input: SmtpConfigurationEditInput,
): Promise<BasicStoreEntitySmtpConfiguration> => {
  validateSmtpConfigurationInput(input);
  const { element } = await patchAttribute<StoreEntitySmtpConfiguration>(
    context,
    user,
    id,
    ENTITY_TYPE_SMTP_CONFIGURATION,
    input,
  );
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: 'updates smtp configuration',
    // TODO(Chunk 2): secrets will be encrypted before storage — sanitize input here once done.
    context_data: { id, entity_type: ENTITY_TYPE_SMTP_CONFIGURATION, input },
  });
  // TODO(Chunk 2): secrets will be encrypted before storage — sanitize element before notify here once done.
  return notify(BUS_TOPICS[ENTITY_TYPE_SMTP_CONFIGURATION].EDIT_TOPIC, element, user);
};

// Implemented in Chunk 2 — delegates to smtp.js to use the effective config (DB or JSON).
export const smtpConfigurationTest = async (
  _context: AuthContext,
  _user: AuthUser,
  email: string,
): Promise<boolean> => {
  return smtpTest(email);
};

export const smtpConfigurationDelete = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
): Promise<string> => {
  // TODO(Chunk 2): secrets will be encrypted before storage — sanitize audit log context here once done.
  return deleteInternalObject(context, user, id, ENTITY_TYPE_SMTP_CONFIGURATION);
};
