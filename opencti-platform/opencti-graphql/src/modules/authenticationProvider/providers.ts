import { AuthenticationProviderType } from '../../generated/graphql';
import { createAuthLogger } from './providers-logger';
import type { BasicStoreEntityAuthenticationProvider, LdapStoreConfiguration, OidcStoreConfiguration, SamlStoreConfiguration } from './authenticationProvider-types';
import { initializeEnvAuthenticationProviders, unregisterAuthenticationProvider } from './providers-initialization';
import { registerSAMLStrategy } from './provider-saml';
import { registerLDAPStrategy } from './provider-ldap';
import { GraphQLError } from 'graphql/index';
import { registerOpenIdStrategy } from './provider-oidc';
import { AuthType, EnvStrategyType, HEADER_STRATEGY_IDENTIFIER, isAuthenticationForcedFromEnv, type ProviderConfiguration } from './providers-configuration';
import type { AuthContext, AuthUser } from '../../types/user';
import { findAllAuthenticationProvider } from './authenticationProvider-domain';
import { registerLocalStrategy } from './provider-local';
import { SYSTEM_USER } from '../../utils/access';
import { createHeaderLoginHandler } from './provider-header';
import { resolveProviderIdentifier } from './authenticationProvider-types';

export const CERT_PROVIDER_NAME = 'Cert';
export const HEADER_PROVIDER_NAME = 'Headers';

export let HEADER_PROVIDER: ProviderConfiguration | undefined = undefined;
export const registerHeaderStrategy = async (context: AuthContext) => {
  const logger = createAuthLogger(HEADER_PROVIDER_NAME, HEADER_PROVIDER_NAME);
  logger.info('Configuring strategy');

  HEADER_PROVIDER = {
    name: HEADER_PROVIDER_NAME,
    reqLoginHandler: createHeaderLoginHandler(logger, context),
    type: AuthType.AUTH_REQ,
    strategy: EnvStrategyType.STRATEGY_HEADER,
    provider: HEADER_STRATEGY_IDENTIFIER,
  };
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
  const logger = createAuthLogger(type, identifier);
  logger.info('Configuring strategy');
  try {
    if (authenticationProvider.enabled) {
      const meta = { name, identifier };
      switch (type) {
        case AuthenticationProviderType.Saml:
          await registerSAMLStrategy(logger, meta, authenticationProvider.configuration as SamlStoreConfiguration);
          break;
        case AuthenticationProviderType.Oidc:
          await registerOpenIdStrategy(logger, meta, authenticationProvider.configuration as OidcStoreConfiguration);
          break;
        case AuthenticationProviderType.Ldap:
          await registerLDAPStrategy(logger, meta, authenticationProvider.configuration as LdapStoreConfiguration);
          break;

        default:
          logger.error('Unknown strategy should not be possible, skipping');
          break;
      }
    }
  } catch (e) {
    if (e instanceof GraphQLError) {
      logger.error(
        `Error when initializing an authentication provider (id: ${authenticationProvider?.id ?? 'no id'}, identifier: ${identifier ?? 'no identifier'}), cause: ${e.message}.`,
        { message: e.message, data: e.extensions.data },
      );
    } else {
      logger.error(
        `Unknown error when initializing an authentication provider (id: ${authenticationProvider?.id ?? 'no id'}, identifier: ${identifier ?? 'no identifier'})`,
        e,
      );
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
    // Header strategy: register handler that reads headers_auth from Settings on each request
    await registerHeaderStrategy(context);
    // No need to do a specific registration for cert
    // Supported providers are in database (openid, ldap, saml, ....)
    await initEnterpriseAuthenticationProviders(context, SYSTEM_USER);
  }
};
