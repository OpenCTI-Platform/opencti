import { AuthenticationProviderType } from '../../generated/graphql';
import { ldapStoreToProvider, oidcStoreToProvider, samlStoreToProvider } from './authenticationProvider-domain';
import { logAuthError, logAuthInfo } from './providers-logger';
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
  const { type, name, internal_id, identifier_override } = authenticationProvider;
  const identifier = identifier_override ?? internal_id;
  try {
    if (authenticationProvider.enabled) {
      switch (type) {
        case AuthenticationProviderType.Saml:
          logAuthInfo(`Configuring ${name} - ${identifier}`, AuthenticationProviderType.Saml);
          await registerSAMLStrategy(await samlStoreToProvider(authenticationProvider as BasicStoreEntityAuthenticationProvider<SamlStoreConfiguration>));
          break;
        case AuthenticationProviderType.Oidc:
          logAuthInfo(`Configuring ${name} - ${identifier}`, AuthenticationProviderType.Oidc);
          await registerOpenIdStrategy(await oidcStoreToProvider(authenticationProvider as BasicStoreEntityAuthenticationProvider<OidcStoreConfiguration>));
          break;
        case AuthenticationProviderType.Ldap:
          logAuthInfo(`Configuring ${name} - ${identifier}`, AuthenticationProviderType.Ldap);
          await registerLDAPStrategy(await ldapStoreToProvider(authenticationProvider as BasicStoreEntityAuthenticationProvider<LdapStoreConfiguration>));
          break;

        default:
          logAuthError('Unknown strategy should not be possible, skipping', undefined, { name, type });
          break;
      }
    }
  } catch (e) {
    if (e instanceof GraphQLError) {
      logAuthError(
        `Error when initializing an authentication provider (id: ${authenticationProvider?.id ?? 'no id'}, identifier: ${identifier ?? 'no identifier'}), cause: ${e.message}.`,
        undefined,
        { message: e.message, data: e.extensions.data },
      );
    } else {
      logAuthError(
        `Unknown error when initializing an authentication provider (id: ${authenticationProvider?.id ?? 'no id'}, identifier: ${identifier ?? 'no identifier'})`,
        undefined,
        e,
      );
    }
  }
};
