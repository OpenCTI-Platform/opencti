import { AuthenticationProviderType } from '../../generated/graphql';
import { createAuthLogger } from './providers-logger';
import type { BasicStoreEntityAuthenticationProvider, LdapStoreConfiguration, OidcStoreConfiguration, SamlStoreConfiguration } from './authenticationProvider-types';
import { unregisterAuthenticationProvider } from './providers-initialization';
import { registerSAMLStrategy } from './provider-saml';
import { registerLDAPStrategy } from './provider-ldap';
import { GraphQLError } from 'graphql/index';
import { registerOpenIdStrategy } from './provider-oidc';

export const refreshStrategy = async (authenticationStrategy: BasicStoreEntityAuthenticationProvider) => {
  await unregisterStrategy(authenticationStrategy);

  if (authenticationStrategy.enabled) {
    await registerStrategy(authenticationStrategy);
  }
};

export const unregisterStrategy = async (authenticationStrategy: BasicStoreEntityAuthenticationProvider) => {
  const identifier = authenticationStrategy.identifier_override ?? authenticationStrategy.internal_id;
  unregisterAuthenticationProvider(identifier);
};

export const registerStrategy = async (authenticationProvider: BasicStoreEntityAuthenticationProvider) => {
  const { type, name, identifier_override } = authenticationProvider;
  const identifier = identifier_override ?? name; // TODO slug name
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
