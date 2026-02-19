import type { LdapStoreConfiguration, ProviderMeta, SecretProvider } from './authenticationProvider-types';
import { flatExtraConf, retrieveSecrets } from './authenticationProvider-domain';
import { type AuthenticationProviderLogger } from './providers-logger';
import { AuthType } from './providers-configuration';
import LdapStrategy, { type VerifyCallback, type VerifyDoneCallback } from 'passport-ldapauth';
import { createMapper } from './mappings-utils';
import { handleProviderLogin } from './providers';
import { REDACTED_INFORMATION } from '../../database/utils';

const createLdapOptions = async (conf: LdapStoreConfiguration, secretsProvider: SecretProvider): Promise<LdapStrategy.Options> => ({
  server: {
    url: conf.url,
    bindDN: conf.bind_dn,
    bindCredentials: await secretsProvider.optional('bind_credentials'),
    searchBase: conf.search_base,
    searchFilter: conf.search_filter,
    searchAttributes: conf.search_attributes,
    groupSearchBase: conf.group_base,
    groupSearchFilter: conf.group_filter,
    groupSearchAttributes: conf.group_search_attributes,
    tlsOptions: {
      rejectUnauthorized: !(conf.allow_self_signed ?? false),
    },
    ...flatExtraConf(conf.extra_conf),
  },
  usernameField: conf.username_field,
  passwordField: conf.password_field,
});

export const createLDAPStrategy = async (logger: AuthenticationProviderLogger, meta: ProviderMeta, storeConf: LdapStoreConfiguration) => {
  const secretsProvider = await retrieveSecrets(meta.identifier, storeConf);
  const ldapOptions = await createLdapOptions(storeConf, secretsProvider);
  const mapper = createMapper(storeConf);

  const ldapLoginCallback: VerifyCallback = async (user: any, done: VerifyDoneCallback) => {
    try {
      const userRedacted = Object.fromEntries(
        Object.entries(user).map(([key, value]) => {
          if (key === ldapOptions.passwordField || key.toLowerCase().includes('password')) {
            return [key, REDACTED_INFORMATION];
          }
          return [key, value];
        }),
      );
      logger.info('Successfully logged on IdP', { user: userRedacted });
      const providerLoginInfo = await mapper(user, user._groups, user);
      const loggedUser = await handleProviderLogin(logger, providerLoginInfo);
      return done(null, loggedUser);
    } catch (e) {
      const err = e instanceof Error ? e : Error(String(e));
      return done(err);
    }
  };

  const ldapStrategy = new LdapStrategy(ldapOptions, ldapLoginCallback);

  return {
    strategy: ldapStrategy,
    auth_type: AuthType.AUTH_FORM,
    logout_remote: undefined,
  };
};
