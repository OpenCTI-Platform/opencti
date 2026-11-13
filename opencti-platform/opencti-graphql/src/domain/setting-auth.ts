// -- Built-in authentication strategy settings --
// These mutations update the Settings entity AND trigger live re-registration
// of the corresponding authentication provider.

import { loadEntity, patchAttribute } from '../database/middleware';
import { publishUserAction } from '../listener/UserActionListener';
import { CERT_PROVIDER } from '../modules/authenticationProvider/provider-cert';
import { HEADERS_PROVIDER } from '../modules/authenticationProvider/provider-headers';
import { LOCAL_PROVIDER } from '../modules/authenticationProvider/provider-local';
import {
  AuthType,
  CERT_STRATEGY_IDENTIFIER,
  EnvStrategyType,
  HEADERS_STRATEGY_IDENTIFIER,
  isLocalAuthForcedEnabledFromEnv,
  LOCAL_STRATEGY_IDENTIFIER,
  PROVIDERS,
} from '../modules/authenticationProvider/providers-configuration';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import type { BasicStoreSettings } from '../types/settings';
import type { AuthContext, AuthUser } from '../types/user';
import { notify } from '../database/redis';
import { BUS_TOPICS, isFeatureEnabled, LOCAL_AUTH_LOCKOUT_FEATURE_FLAG } from '../config/conf';
import { FunctionalError } from '../config/errors';
import type { CertAuthConfigInput, HeadersAuthConfigInput, LocalAuthConfigInput } from '../generated/graphql';
import { getEntityFromCache } from '../database/cache';
import { SYSTEM_USER } from '../utils/access';
import { propagatePasswordValidityChange } from '../modules/user/user-domain';
import { isValidPasswordHistoryCount, PASSWORD_HISTORY_MAX_COUNT, readPasswordHistoryCount, trimAllUsersPasswordHistory } from '../modules/user/user-password-history';
import { LOCAL_AUTH_LOCKOUT_DEFAULTS, LOCAL_AUTH_LOCKOUT_KEYS, type LocalAuthLockoutKey } from './local-auth-lockout';

// The password history count sent with the local settings, once validated; undefined when it is not sent.
export const resolvePasswordHistoryCount = (input: Pick<LocalAuthConfigInput, 'password_policy_history_count'>): number | undefined => {
  const value = input.password_policy_history_count;
  if (value === undefined || value === null) {
    return undefined;
  }
  if (!isValidPasswordHistoryCount(value)) {
    throw FunctionalError(`Password history count must be an integer between 0 and ${PASSWORD_HISTORY_MAX_COUNT}`, { value });
  }
  return value;
};

export const buildAvailableProviders = async (platformSettings: BasicStoreSettings) => {
  const availableProviders = [...PROVIDERS];
  if (platformSettings.local_auth?.enabled || isLocalAuthForcedEnabledFromEnv()) {
    availableProviders.push({
      name: platformSettings.local_auth?.button_label_override || 'local',
      type: AuthType.AUTH_FORM,
      strategy: EnvStrategyType.STRATEGY_LOCAL,
      provider: LOCAL_PROVIDER?.provider ?? LOCAL_STRATEGY_IDENTIFIER,
    });
  }
  if (platformSettings.cert_auth?.enabled) {
    availableProviders.push({
      name: platformSettings.cert_auth?.button_label_override || 'cert',
      type: AuthType.AUTH_SSO,
      strategy: EnvStrategyType.STRATEGY_CERT,
      provider: CERT_PROVIDER?.provider ?? CERT_STRATEGY_IDENTIFIER,
    });
  }
  if (platformSettings.headers_auth?.enabled) {
    availableProviders.push({
      name: platformSettings.headers_auth?.button_label_override || 'headers',
      type: AuthType.AUTH_SSO,
      strategy: EnvStrategyType.STRATEGY_HEADER,
      provider: HEADERS_PROVIDER?.provider ?? HEADERS_STRATEGY_IDENTIFIER,
    });
  }
  return availableProviders;
};

// Upper bounds of the lockout policy, mirrored by the local strategy form
export const LOCAL_AUTH_LOCKOUT_MAX_ATTEMPTS_LIMIT = 100;
export const LOCAL_AUTH_LOCKOUT_WINDOW_LIMIT = 1440; // minutes, the window is capped to 24h by the specification
// minutes, the temporary lock is capped to 24h like the window, as it lasted a full window in the specification
export const LOCAL_AUTH_LOCKOUT_DURATION_LIMIT = 1440;

const buildLocalAuthLockoutPatch = async (context: AuthContext, input: LocalAuthConfigInput) => {
  if (!isFeatureEnabled(LOCAL_AUTH_LOCKOUT_FEATURE_FLAG)) {
    return {};
  }
  const patch: Partial<Pick<LocalAuthConfigInput, LocalAuthLockoutKey>> = Object.fromEntries(
    LOCAL_AUTH_LOCKOUT_KEYS.filter((key) => input[key] !== undefined).map((key) => [key, input[key]]),
  );
  // Leaving the values untouched or disabling the lockout never checks them, so stored values cannot block other local auth updates
  const changesValues = Object.keys(patch).some((key) => key !== 'local_auth_lockout_enabled');
  if (!changesValues && patch.local_auth_lockout_enabled !== true) {
    return patch;
  }
  // Validate the values the settings will hold once patched (a null input falls back to the default)
  // Stored values are read from the database, as the settings cache can lag behind a previous update
  const storedSettings = await loadEntity<BasicStoreSettings>(context, SYSTEM_USER, [ENTITY_TYPE_SETTINGS]);
  const effectiveValue = (key: Exclude<LocalAuthLockoutKey, 'local_auth_lockout_enabled' | 'local_auth_lockout_final_action'>): number => {
    const value = Object.hasOwn(patch, key) ? input[key] : storedSettings?.[key];
    return value ?? LOCAL_AUTH_LOCKOUT_DEFAULTS[key];
  };
  const maxAttempts = effectiveValue('local_auth_lockout_max_attempts');
  const adminMaxAttempts = effectiveValue('local_auth_lockout_admin_max_attempts');
  const lockoutWindow = effectiveValue('local_auth_lockout_window');
  const duration = effectiveValue('local_auth_lockout_duration');
  if (maxAttempts < 1) {
    throw FunctionalError('Lockout max attempts must be greater than or equal to 1', { local_auth_lockout_max_attempts: maxAttempts });
  }
  if (maxAttempts > LOCAL_AUTH_LOCKOUT_MAX_ATTEMPTS_LIMIT) {
    throw FunctionalError(`Lockout max attempts must be lower than or equal to ${LOCAL_AUTH_LOCKOUT_MAX_ATTEMPTS_LIMIT}`, { local_auth_lockout_max_attempts: maxAttempts });
  }
  if (adminMaxAttempts < 1) {
    throw FunctionalError('Lockout admin max attempts must be greater than or equal to 1', { local_auth_lockout_admin_max_attempts: adminMaxAttempts });
  }
  if (adminMaxAttempts > LOCAL_AUTH_LOCKOUT_MAX_ATTEMPTS_LIMIT) {
    throw FunctionalError(`Lockout admin max attempts must be lower than or equal to ${LOCAL_AUTH_LOCKOUT_MAX_ATTEMPTS_LIMIT}`, { local_auth_lockout_admin_max_attempts: adminMaxAttempts });
  }
  // A window of 0 removes its time limit
  if (lockoutWindow < 0) {
    throw FunctionalError('Lockout window must be greater than or equal to 0', { local_auth_lockout_window: lockoutWindow });
  }
  if (lockoutWindow > LOCAL_AUTH_LOCKOUT_WINDOW_LIMIT) {
    throw FunctionalError(`Lockout window must be lower than or equal to ${LOCAL_AUTH_LOCKOUT_WINDOW_LIMIT}`, { local_auth_lockout_window: lockoutWindow });
  }
  if (duration <= 0) {
    throw FunctionalError('Lockout duration must be greater than 0', { local_auth_lockout_duration: duration });
  }
  if (duration > LOCAL_AUTH_LOCKOUT_DURATION_LIMIT) {
    throw FunctionalError(`Lockout duration must be lower than or equal to ${LOCAL_AUTH_LOCKOUT_DURATION_LIMIT}`, { local_auth_lockout_duration: duration });
  }
  return patch;
};

export const updateLocalAuth = async (context: AuthContext, user: AuthUser, settingsId: string, input: LocalAuthConfigInput) => {
  // Read previous validity days before patching
  const currentSettings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const storedSettings = await loadEntity<BasicStoreSettings>(context, SYSTEM_USER, [ENTITY_TYPE_SETTINGS]);
  const oldValidityDays = Number(currentSettings.password_policy_validity_days ?? 0);
  const oldHistoryCount = readPasswordHistoryCount(storedSettings);
  const newHistoryCount = resolvePasswordHistoryCount(input);

  const patch = {
    local_auth: { enabled: input.enabled },
    ...(input.password_policy_min_length !== undefined && { password_policy_min_length: input.password_policy_min_length }),
    ...(input.password_policy_max_length !== undefined && { password_policy_max_length: input.password_policy_max_length }),
    ...(input.password_policy_min_symbols !== undefined && { password_policy_min_symbols: input.password_policy_min_symbols }),
    ...(input.password_policy_min_numbers !== undefined && { password_policy_min_numbers: input.password_policy_min_numbers }),
    ...(input.password_policy_min_words !== undefined && { password_policy_min_words: input.password_policy_min_words }),
    ...(input.password_policy_min_lowercase !== undefined && { password_policy_min_lowercase: input.password_policy_min_lowercase }),
    ...(input.password_policy_min_uppercase !== undefined && { password_policy_min_uppercase: input.password_policy_min_uppercase }),
    ...(input.password_policy_validity_days !== undefined && { password_policy_validity_days: input.password_policy_validity_days }),
    ...(newHistoryCount !== undefined && { password_policy_history_count: newHistoryCount }),
    ...(await buildLocalAuthLockoutPatch(context, input)),
  };
  const { element } = await patchAttribute(context, user, settingsId, ENTITY_TYPE_SETTINGS, patch);

  // A lower count drops the hashes no longer needed at once; 0 deletes every password history
  if (newHistoryCount !== undefined && newHistoryCount < oldHistoryCount) {
    await trimAllUsersPasswordHistory(newHistoryCount);
  }

  // Propagate password_valid_until changes to all internal users
  if (input.password_policy_validity_days !== undefined) {
    await propagatePasswordValidityChange(context, oldValidityDays, Number(input.password_policy_validity_days));
  }

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: 'updates `local authentication settings` for `platform settings`',
    context_data: { id: settingsId, entity_type: ENTITY_TYPE_SETTINGS, input: patch },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_SETTINGS].EDIT_TOPIC, element, user);
};

export const updateCertAuth = async (context: AuthContext, user: AuthUser, settingsId: string, input: CertAuthConfigInput) => {
  const patch = { cert_auth: input };
  const { element } = await patchAttribute(context, user, settingsId, ENTITY_TYPE_SETTINGS, patch);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: 'updates `cert authentication settings` for `platform settings`',
    context_data: { id: settingsId, entity_type: ENTITY_TYPE_SETTINGS, input: patch },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_SETTINGS].EDIT_TOPIC, element, user);
};

export const updateHeaderAuth = async (context: AuthContext, user: AuthUser, settingsId: string, input: HeadersAuthConfigInput) => {
  const patch = { headers_auth: input };
  const { element } = await patchAttribute(context, user, settingsId, ENTITY_TYPE_SETTINGS, patch);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: 'updates `header authentication settings` for `platform settings`',
    context_data: { id: settingsId, entity_type: ENTITY_TYPE_SETTINGS, input: patch },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_SETTINGS].EDIT_TOPIC, element, user);
};
