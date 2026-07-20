import type { AuthContext, AuthUser } from '../../types/user';
import { patchAttribute } from '../../database/middleware';
import { ForbiddenAccess, FunctionalError } from '../../config/errors';
import { SmtpAuthType, type SmtpConfigurationAddInput } from '../../generated/graphql';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS, isFeatureEnabled } from '../../config/conf';
import { smtpTest } from '../../database/smtp';
import { encryptSmtpSecret } from './smtpConfiguration-crypto';
import type { BasicStoreSettings, SmtpConfiguration } from '../../types/settings';
import { getEntityFromCache } from '../../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';

const SMTP_SECRET_FIELDS = ['password', 'oauth_client_secret', 'oauth_refresh_token'] as const;

const checkSmtpConfigurationFeatureEnabled = () => {
  if (!isFeatureEnabled('SMTP_CONFIGURATION')) {
    throw ForbiddenAccess('SMTP configuration feature is disabled');
  }
};

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

const validateSmtpConfigurationInput = (input: SmtpConfigurationAddInput) => {
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

// No feature-flag guard: also used internally by database/smtp.js and boot-time checks.
export const getSmtpConfiguration = async (
  context: AuthContext,
  user: AuthUser,
): Promise<SmtpConfiguration | null> => {
  const settings: BasicStoreSettings = await getEntityFromCache(context, user, ENTITY_TYPE_SETTINGS);
  return settings.smtp_configuration ?? null;
};

export const getSmtpConfigurationForAdmin = async (
  context: AuthContext,
  user: AuthUser,
): Promise<SmtpConfiguration | null> => {
  checkSmtpConfigurationFeatureEnabled();
  return getSmtpConfiguration(context, user);
};

export const smtpConfigurationEdit = async (
  context: AuthContext,
  user: AuthUser,
  input: SmtpConfigurationAddInput,
): Promise<SmtpConfiguration> => {
  checkSmtpConfigurationFeatureEnabled();
  validateSmtpConfigurationInput(input);
  const encryptedInput = await encryptSmtpInput(input as unknown as Record<string, unknown>);
  const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
  const patch = { smtp_configuration: encryptedInput };
  const { element } = await patchAttribute(context, user, settings.id, ENTITY_TYPE_SETTINGS, patch);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: 'updates smtp configuration',
    context_data: { id: settings.id, entity_type: ENTITY_TYPE_SETTINGS, input: sanitizeInputForAudit(input as unknown as Record<string, unknown>) },
  });
  await notify(BUS_TOPICS[ENTITY_TYPE_SETTINGS].EDIT_TOPIC, element, user);
  return (element as unknown as BasicStoreSettings).smtp_configuration!;
};

export const smtpConfigurationTest = async (
  _context: AuthContext,
  _user: AuthUser,
  email: string,
): Promise<boolean> => {
  checkSmtpConfigurationFeatureEnabled();
  return smtpTest(email);
};
