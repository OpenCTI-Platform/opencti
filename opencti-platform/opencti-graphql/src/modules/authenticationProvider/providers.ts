import { AuthenticationProviderType } from '../../generated/graphql';
import { AuthenticationProviderError, type AuthenticationProviderLogger, createAuthLogger } from './providers-logger';
import type {
  BasicStoreEntityAuthenticationProvider,
  LdapStoreConfiguration,
  MappingConfiguration,
  OidcStoreConfiguration,
  SamlStoreConfiguration,
} from './authenticationProvider-types';
import { initializeEnvAuthenticationProviders, registerAuthenticationProvider, unregisterAuthenticationProvider } from './providers-env-deprecated';
import { createSAMLStrategy } from './provider-saml';
import { createLDAPStrategy } from './provider-ldap';
import { createOpenIdStrategy } from './provider-oidc';
import { IS_AUTHENTICATION_FORCE_LOCAL, isAuthenticationForcedFromEnv } from './providers-configuration';
import { PROVIDERS } from './providers-configuration';
import type { AuthContext, AuthUser } from '../../types/user';
import { findAllAuthenticationProvider, resolveProviderIdentifier } from './authenticationProvider-domain';
import { registerLocalStrategy } from './provider-local';
import { executionContext, SYSTEM_USER } from '../../utils/access';
import { registerHeadersStrategy } from './provider-headers';
import { loginFromProvider } from '../../domain/user';
import { addUserLoginCount } from '../../manager/telemetryManager';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';
import conf, { logApp } from '../../config/conf';
import { getSettings, updateLocalAuth } from '../../domain/settings';
import { getEnterpriseEditionInfo } from '../settings/licensing';
import type { BasicStoreSettings } from '../../types/settings';
import { runAuthenticationProviderMigration } from './authenticationProvider-migration';
import { registerCertStrategy } from './provider-cert';
import { elDeleteElements } from '../../database/engine';

export interface ProviderAuthInfo {
  userMapping: {
    email?: string;
    name?: string;
    firstname?: string;
    lastname?: string;
    provider_metadata?: unknown;
  };
  groupsMapping: {
    groups: string[];
    autoCreateGroup: boolean;
    preventDefaultGroups: boolean;
  };
  organizationsMapping: {
    organizations: string[];
    autoCreateOrganization: boolean;
  };
}

const context = executionContext('authentication_providers');
export const handleProviderLogin = async (logger: AuthenticationProviderLogger, info: ProviderAuthInfo) => {
  if (!info.userMapping.email) {
    throw new AuthenticationProviderError('No user email found, please verify provider configuration and server response', info);
  }
  logger.info('User info resolved', info);

  if (!await isEnterpriseEdition(context)) {
    throw new AuthenticationProviderError('This authentication strategy is not available, please contact your administrator');
  }

  const user = await loginFromProvider(
    info.userMapping,
    {
      providerGroups: info.groupsMapping.groups,
      autoCreateGroup: info.groupsMapping.autoCreateGroup,
      preventDefaultGroups: info.groupsMapping.preventDefaultGroups,
      providerOrganizations: info.organizationsMapping.organizations,
      autoCreateOrganization: info.organizationsMapping.autoCreateOrganization,
    },
  );
  addUserLoginCount();
  logger.success('User successfully logged', { userId: user.id, email: user.user_email });
  return user;
};

export const refreshStrategy = async (authenticationStrategy: BasicStoreEntityAuthenticationProvider) => {
  await unregisterStrategy(authenticationStrategy);

  if (authenticationStrategy.enabled) {
    await registerStrategy(authenticationStrategy);
  }
};

export const unregisterStrategy = async (authenticationStrategy: BasicStoreEntityAuthenticationProvider) => {
  // when changing a provider identifier, we need to find the old identifier value in order to unregister it correctly
  const identifierFromProviders = PROVIDERS.find((p) => p.internal_id === authenticationStrategy.internal_id)?.provider;
  const identifier = identifierFromProviders ?? resolveProviderIdentifier(authenticationStrategy);
  unregisterAuthenticationProvider(identifier);
};

export const registerStrategy = async (authenticationProvider: BasicStoreEntityAuthenticationProvider) => {
  const { type, name } = authenticationProvider;
  const identifier = resolveProviderIdentifier(authenticationProvider);
  const meta = { name, identifier };
  const logger = createAuthLogger(type, identifier);
  const { configuration } = authenticationProvider;
  const { user_info_mapping, groups_mapping, organizations_mapping } = configuration as MappingConfiguration;
  logger.info('Provider initialization', { user_info_mapping, groups_mapping, organizations_mapping });

  try {
    const createStrategy = async () => {
      switch (authenticationProvider.type) {
        case AuthenticationProviderType.Saml:
          return createSAMLStrategy(logger, meta, configuration as SamlStoreConfiguration);
        case AuthenticationProviderType.Oidc:
          return createOpenIdStrategy(logger, meta, configuration as OidcStoreConfiguration);
        case AuthenticationProviderType.Ldap:
          return createLDAPStrategy(logger, meta, configuration as LdapStoreConfiguration);
        default:
          return undefined;
      }
    };

    if (authenticationProvider.enabled) {
      const created = await createStrategy();
      if (!created) {
        logger.error('Provider type is not supported, skipping');
        return;
      }
      Object.assign(created.strategy, { logger });
      registerAuthenticationProvider(
        meta.identifier,
        created.strategy,
        {
          internal_id: authenticationProvider.internal_id,
          name: meta.name,
          type: created.auth_type,
          strategy: authenticationProvider.type,
          provider: meta.identifier,
          logout_remote: created.logout_remote,
        },
      );
    }
  } catch (e) {
    logger.error('Provider initialization error ', {}, e);
  }
};

/**
 * Called during platform initialization.
 * Read Authentication strategy in database and load them.
 * @param context
 * @param user
 */
export const initDatabaseAuthenticationProviders = async (context: AuthContext, user: AuthUser) => {
  const providersFromDatabase = await findAllAuthenticationProvider(context, user);
  for (let i = 0; i < providersFromDatabase.length; i++) {
    await registerStrategy(providersFromDatabase[i]);
  }
};

export const initializeAuthenticationProviders = async (context: AuthContext) => {
  // Singleton strategies: always register
  await registerLocalStrategy();
  await registerCertStrategy();
  await registerHeadersStrategy(context);
  // In force env
  // Settings must be aligned on env definition
  // AuthenticationProviders must be deleted from the database
  // Providers are only loaded from a config file.
  // Its a deprecated safeguard mode.
  if (isAuthenticationForcedFromEnv()) {
    // Cleanup providers from database
    const authenticators = await findAllAuthenticationProvider(context, SYSTEM_USER);
    await elDeleteElements(context, SYSTEM_USER, authenticators, { forceDelete: true, forceRefresh: true });
    // Init providers from env
    await initializeEnvAuthenticationProviders();
  } else {
    // Migration first (already created will be not replayed)
    await runAuthenticationProviderMigration(context, SYSTEM_USER);
    // In standard mode, init from providers in the database
    // Singleton already initialized
    await initDatabaseAuthenticationProviders(context, SYSTEM_USER);
  }
  // Safety net: force local_auth enabled when no other provider is available
  const finalSettings = await getSettings(context) as unknown as BasicStoreSettings;
  if (finalSettings.local_auth?.enabled === false) {
    const isHttpsEnabled = !!(conf.get('app:https_cert:key') && conf.get('app:https_cert:crt'));
    const eeActive = getEnterpriseEditionInfo(finalSettings).license_validated;
    const hasCert = finalSettings.cert_auth?.enabled === true && eeActive && isHttpsEnabled;
    const hasHeader = finalSettings.headers_auth?.enabled === true && eeActive;
    const dbProviders = await findAllAuthenticationProvider(context, SYSTEM_USER);
    const hasDbProvider = eeActive && dbProviders.some((p) => p.enabled);
    if (IS_AUTHENTICATION_FORCE_LOCAL || (!hasCert && !hasHeader && !hasDbProvider)) {
      logApp.warn('[MIGRATION-SAFETY] No other provider available, forcing local_auth to enabled');
      await updateLocalAuth(context, SYSTEM_USER, finalSettings.id, { enabled: true });
    }
  }
};
