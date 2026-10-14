// -- Built-in authentication strategy settings --
// These mutations update the Settings entity AND trigger live re-registration
// of the corresponding authentication provider.

import { patchAttribute } from '../database/middleware';
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
import { clearAllUsersPasswordValidUntil, adjustAllUsersPasswordValidUntil } from '../modules/user/user-domain';

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

// Values returned for the local authentication lockout policy when the settings hold none
export const LOCAL_AUTH_LOCKOUT_DEFAULTS = {
  local_auth_lockout_enabled: false,
  local_auth_lockout_max_attempts: 5,
  local_auth_lockout_window: 1440, // minutes, 24h
  local_auth_lockout_duration: 15, // minutes
  local_auth_lockout_max_duration: 180, // minutes, 3h
};

// Upper bounds of the lockout policy, mirrored by the local strategy form
export const LOCAL_AUTH_LOCKOUT_MAX_ATTEMPTS_LIMIT = 100;
export const LOCAL_AUTH_LOCKOUT_WINDOW_LIMIT = 43200; // minutes, 30 days
// Locks are capped to 3h by the specification: the max duration can only be lowered
export const LOCAL_AUTH_LOCKOUT_MAX_DURATION_LIMIT = LOCAL_AUTH_LOCKOUT_DEFAULTS.local_auth_lockout_max_duration;

const buildLocalAuthLockoutPatch = (currentSettings: BasicStoreSettings, input: LocalAuthConfigInput) => {
  if (!isFeatureEnabled(LOCAL_AUTH_LOCKOUT_FEATURE_FLAG)) {
    return {};
  }
  const patch = {
    ...(input.local_auth_lockout_enabled !== undefined && { local_auth_lockout_enabled: input.local_auth_lockout_enabled }),
    ...(input.local_auth_lockout_max_attempts !== undefined && { local_auth_lockout_max_attempts: input.local_auth_lockout_max_attempts }),
    ...(input.local_auth_lockout_window !== undefined && { local_auth_lockout_window: input.local_auth_lockout_window }),
    ...(input.local_auth_lockout_duration !== undefined && { local_auth_lockout_duration: input.local_auth_lockout_duration }),
    ...(input.local_auth_lockout_max_duration !== undefined && { local_auth_lockout_max_duration: input.local_auth_lockout_max_duration }),
  };
  // Leaving the values untouched or disabling the lockout never checks them, so stored values cannot block other local auth updates
  const changesValues = Object.keys(patch).some((key) => key !== 'local_auth_lockout_enabled');
  if (!changesValues && patch.local_auth_lockout_enabled !== true) {
    return patch;
  }
  // Validate the values the settings will hold once patched (a null input falls back to the default)
  const effectiveValue = (key: 'local_auth_lockout_max_attempts' | 'local_auth_lockout_window' | 'local_auth_lockout_duration' | 'local_auth_lockout_max_duration') => {
    const value = key in patch ? input[key] : currentSettings[key];
    return value ?? LOCAL_AUTH_LOCKOUT_DEFAULTS[key];
  };
  const maxAttempts = effectiveValue('local_auth_lockout_max_attempts');
  const lockoutWindow = effectiveValue('local_auth_lockout_window');
  const duration = effectiveValue('local_auth_lockout_duration');
  const maxDuration = effectiveValue('local_auth_lockout_max_duration');
  if (maxAttempts < 1) {
    throw FunctionalError('Lockout max attempts must be greater or equal to 1', { local_auth_lockout_max_attempts: maxAttempts });
  }
  if (maxAttempts > LOCAL_AUTH_LOCKOUT_MAX_ATTEMPTS_LIMIT) {
    throw FunctionalError(`Lockout max attempts must be lower or equal to ${LOCAL_AUTH_LOCKOUT_MAX_ATTEMPTS_LIMIT}`, { local_auth_lockout_max_attempts: maxAttempts });
  }
  if (lockoutWindow <= 0) {
    throw FunctionalError('Lockout window must be greater than 0', { local_auth_lockout_window: lockoutWindow });
  }
  if (duration <= 0) {
    throw FunctionalError('Lockout duration must be greater than 0', { local_auth_lockout_duration: duration });
  }
  if (maxDuration <= 0) {
    throw FunctionalError('Lockout max duration must be greater than 0', { local_auth_lockout_max_duration: maxDuration });
  }
  if (lockoutWindow > LOCAL_AUTH_LOCKOUT_WINDOW_LIMIT) {
    throw FunctionalError(`Lockout window must be lower or equal to ${LOCAL_AUTH_LOCKOUT_WINDOW_LIMIT}`, { local_auth_lockout_window: lockoutWindow });
  }
  // The duration is capped too, as it cannot exceed the max duration
  if (maxDuration > LOCAL_AUTH_LOCKOUT_MAX_DURATION_LIMIT) {
    throw FunctionalError(`Lockout max duration must be lower or equal to ${LOCAL_AUTH_LOCKOUT_MAX_DURATION_LIMIT}`, { local_auth_lockout_max_duration: maxDuration });
  }
  if (duration > maxDuration) {
    throw FunctionalError('Lockout duration must be lower or equal to lockout max duration', {
      local_auth_lockout_duration: duration,
      local_auth_lockout_max_duration: maxDuration,
    });
  }
  return patch;
};

export const updateLocalAuth = async (context: AuthContext, user: AuthUser, settingsId: string, input: LocalAuthConfigInput) => {
  // Read previous validity days before patching
  const currentSettings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const oldValidityDays = Number(currentSettings.password_policy_validity_days ?? 0);

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
    ...buildLocalAuthLockoutPatch(currentSettings, input),
  };
  const { element } = await patchAttribute(context, user, settingsId, ENTITY_TYPE_SETTINGS, patch);

  // Propagate password_valid_until changes to all internal users
  if (input.password_policy_validity_days !== undefined) {
    const newValidityDays = Number(input.password_policy_validity_days);
    if (newValidityDays <= 0) {
      // Policy disabled: clear all users' expiration dates
      await clearAllUsersPasswordValidUntil(context);
    } else if (newValidityDays !== oldValidityDays) {
      // Policy duration changed: adjust all existing expiration dates
      await adjustAllUsersPasswordValidUntil(context, oldValidityDays, newValidityDays);
    }
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
