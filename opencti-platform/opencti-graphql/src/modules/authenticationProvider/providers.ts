import { AuthenticationProviderType } from '../../generated/graphql';
import { type AuthenticationProviderLogger, createAuthLogger } from './providers-logger';
import type {
  BasicStoreEntityAuthenticationProvider,
  LdapStoreConfiguration,
  MappingConfiguration,
  OidcStoreConfiguration,
  SamlStoreConfiguration,
} from './authenticationProvider-types';
import { initializeEnvAuthenticationProviders, registerAuthenticationProvider, unregisterAuthenticationProvider } from './providers-initialization';
import { createSAMLStrategy } from './provider-saml';
import { createLDAPStrategy } from './provider-ldap';
import { GraphQLError } from 'graphql/index';
import { createOpenIdStrategy } from './provider-oidc';
import { AuthType, EnvStrategyType, HEADERS_STRATEGY_IDENTIFIER, isAuthenticationForcedFromEnv, type ProviderConfiguration } from './providers-configuration';
import type { AuthContext, AuthUser } from '../../types/user';
import { findAllAuthenticationProvider, resolveProviderIdentifier } from './authenticationProvider-domain';
import { registerLocalStrategy } from './provider-local';
import { executionContext, SYSTEM_USER } from '../../utils/access';
import { createHeadersLoginHandler } from './provider-headers';
import { loginFromProvider } from '../../domain/user';
import { addUserLoginCount } from '../../manager/telemetryManager';
import { ForbiddenAccess } from '../../config/errors';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';

export const CERT_PROVIDER_NAME = 'Cert';
export const HEADERS_PROVIDER_NAME = 'Headers';

export let HEADERS_PROVIDER: ProviderConfiguration | undefined = undefined;
export const registerHeadersStrategy = async (context: AuthContext) => {
  const logger = createAuthLogger(HEADERS_PROVIDER_NAME, HEADERS_PROVIDER_NAME);

  HEADERS_PROVIDER = {
    name: HEADERS_PROVIDER_NAME,
    reqLoginHandler: createHeadersLoginHandler(logger, context),
    type: AuthType.AUTH_REQ,
    strategy: EnvStrategyType.STRATEGY_HEADER,
    provider: HEADERS_STRATEGY_IDENTIFIER,
  };
};

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
  logger.info('User info resolved', info);
  if (!info.userMapping.email) {
    throw Error('No user email found, please verify provider configuration and server response');
  }

  if (!await isEnterpriseEdition(context)) {
    throw ForbiddenAccess('This authentication strategy is only available with a valid Enterprise Edition license');
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
  logger.info('User successfully logged', { userId: user.id });
  return user;
};

export const refreshStrategy = async (authenticationStrategy: BasicStoreEntityAuthenticationProvider) => {
  await unregisterStrategy(authenticationStrategy);

  if (authenticationStrategy.enabled) {
    await registerStrategy(authenticationStrategy);
  }
};

export const unregisterStrategy = async (authenticationStrategy: BasicStoreEntityAuthenticationProvider) => {
  const identifier = resolveProviderIdentifier(authenticationStrategy);
  unregisterAuthenticationProvider(identifier);
};

export const registerStrategy = async (authenticationProvider: BasicStoreEntityAuthenticationProvider) => {
  const { type, name } = authenticationProvider;
  const identifier = resolveProviderIdentifier(authenticationProvider);
  const meta = { name, identifier };
  const logger = createAuthLogger(type, identifier);
  const { configuration } = authenticationProvider;
  const { user_info_mapping, groups_mapping, organizations_mapping } = configuration as MappingConfiguration;
  logger.info('Configuring provider', { user_info_mapping, groups_mapping, organizations_mapping });

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

  try {
    if (authenticationProvider.enabled) {
      const created = await createStrategy();
      if (!created) {
        logger.error('Provider type is not supported, skipping');
        return;
      }
      registerAuthenticationProvider(
        meta.identifier,
        created.strategy,
        {
          name: meta.name,
          type: created.auth_type,
          strategy: authenticationProvider.type,
          provider: meta.identifier,
          logout_remote: created.logout_remote,
        },
      );
    }
  } catch (e) {
    if (e instanceof GraphQLError) {
      logger.error('Error when initializing provider', { message: e.message, data: e.extensions.data });
    } else {
      logger.error('Unknown error when initializing provider', {}, e);
    }
  }
};

/**
 * Called during platform initialization.
 * Read Authentication strategy in database and load them.
 * @param context
 * @param user
 */
export const initEnterpriseAuthenticationProviders = async (context: AuthContext, user: AuthUser) => {
  if (!isAuthenticationForcedFromEnv()) {
    const providersFromDatabase = await findAllAuthenticationProvider(context, user);
    for (let i = 0; i < providersFromDatabase.length; i++) {
      await registerStrategy(providersFromDatabase[i]);
    }
  }
};

export const initializeAuthenticationProviders = async (context: AuthContext) => {
  // Local strategy: always register passport strategy at startup
  await registerLocalStrategy();
  // Deprecated providers are env way (Google, Github, Facebook)
  // Also if force env is true, there is still providers with env (OpenId, LDAP, SAML)
  await initializeEnvAuthenticationProviders(context, SYSTEM_USER);
  // If not explicit forced, use database ones
  if (!isAuthenticationForcedFromEnv()) {
    // Headers strategy: register handler that reads headers_auth from Settings on each request
    await registerHeadersStrategy(context);
    // No need to do a specific registration for cert
    // Supported providers are in database (openid, ldap, saml, ....)
    await initEnterpriseAuthenticationProviders(context, SYSTEM_USER);
  }
};
