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
import { BUS_TOPICS } from '../config/conf';
import type { CertAuthConfigInput, HeadersAuthConfigInput, LocalAuthConfigInput } from '../generated/graphql';

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

export const updateLocalAuth = async (context: AuthContext, user: AuthUser, settingsId: string, input: LocalAuthConfigInput) => {
  const patch = {
    local_auth: { enabled: input.enabled },
    ...(input.password_policy_min_length !== undefined && { password_policy_min_length: input.password_policy_min_length }),
    ...(input.password_policy_max_length !== undefined && { password_policy_max_length: input.password_policy_max_length }),
    ...(input.password_policy_min_symbols !== undefined && { password_policy_min_symbols: input.password_policy_min_symbols }),
    ...(input.password_policy_min_numbers !== undefined && { password_policy_min_numbers: input.password_policy_min_numbers }),
    ...(input.password_policy_min_words !== undefined && { password_policy_min_words: input.password_policy_min_words }),
    ...(input.password_policy_min_lowercase !== undefined && { password_policy_min_lowercase: input.password_policy_min_lowercase }),
    ...(input.password_policy_min_uppercase !== undefined && { password_policy_min_uppercase: input.password_policy_min_uppercase }),
  };
  const { element } = await patchAttribute(context, user, settingsId, ENTITY_TYPE_SETTINGS, patch);
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
