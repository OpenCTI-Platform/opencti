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
import { getPlatformCrypto } from '../../utils/platformCrypto';
import { memoize } from '../../utils/memoize';

const getSmtpKeyPair = memoize(async () => {
  const factory = await getPlatformCrypto();
  return factory.deriveAesKey(['smtp', 'elastic'], 1);
});

const encryptSmtpSecret = async (value: string | undefined | null): Promise<string | undefined | null> => {
  if (!value) return value;
  const keyPair = await getSmtpKeyPair();
  const encryptedBuffer = await keyPair.encrypt(Buffer.from(value));
  return encryptedBuffer.toString('base64');
};

const SMTP_SECRET_FIELDS = ['password', 'oauth_client_secret', 'oauth_refresh_token'] as const;

const encryptSmtpInput = async (input: Record<string, unknown>): Promise<Record<string, unknown>> => {
  const result: Record<string, unknown> = { ...input };
  // oauth_access_token is ephemeral (obtained via refresh token) — never stored
  delete result.oauth_access_token;
  for (const field of SMTP_SECRET_FIELDS) {
    if (field in result) {
      result[`${field}_encrypted`] = await encryptSmtpSecret(result[field] as string | null | undefined);
      delete result[field];
    }
  }
  return result;
};

const sanitizeInputForAudit = (input: Record<string, unknown>): Record<string, unknown> => {
  const sanitized = { ...input };
  for (const field of SMTP_SECRET_FIELDS) {
    delete sanitized[field];
    delete sanitized[`${field}_encrypted`];
  }
  delete sanitized.oauth_access_token;
  return sanitized;
};

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
  const encryptedInput = await encryptSmtpInput(input as unknown as Record<string, unknown>);
  return createInternalObject<StoreEntitySmtpConfiguration>(
    context,
    user,
    encryptedInput as unknown as SmtpConfigurationAddInput,
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
  const encryptedInput = await encryptSmtpInput(input as unknown as Record<string, unknown>);
  const { element } = await patchAttribute<StoreEntitySmtpConfiguration>(
    context,
    user,
    id,
    ENTITY_TYPE_SMTP_CONFIGURATION,
    encryptedInput,
  );
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: 'updates smtp configuration',
    context_data: { id, entity_type: ENTITY_TYPE_SMTP_CONFIGURATION, input: sanitizeInputForAudit(input as unknown as Record<string, unknown>) },
  });
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
  return deleteInternalObject(context, user, id, ENTITY_TYPE_SMTP_CONFIGURATION);
};
