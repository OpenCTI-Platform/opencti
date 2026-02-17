import type { LdapStoreConfiguration, ProviderMeta } from './authenticationProvider-types';
import { flatExtraConf, decryptAuthValue } from './authenticationProvider-domain';
import { type AuthenticationProviderLogger } from './providers-logger';
import { AuthType } from './providers-configuration';
import LdapStrategy, { type VerifyCallback, type VerifyDoneCallback } from 'passport-ldapauth';
import { createMapper } from './mappings-utils';
import { handleProviderLogin } from './providers';

const createLdapOptions = async (conf: LdapStoreConfiguration): Promise<LdapStrategy.Options> => ({
  server: {
    url: conf.url,
    bindDN: conf.bind_dn,
    bindCredentials: await decryptAuthValue(conf.bind_credentials_encrypted),
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

export const createLDAPStrategy = async (logger: AuthenticationProviderLogger, _meta: ProviderMeta, storeConf: LdapStoreConfiguration) => {
  const ldapOptions = await createLdapOptions(storeConf);
  const mapper = createMapper(storeConf);

  const ldapLoginCallback: VerifyCallback = async (user: any, done: VerifyDoneCallback) => {
    try {
      logger.info('Successfully logged on IdP', { user });
      const providerLoginInfo = await mapper(user, user._groups, user);
      const loggedUser = await handleProviderLogin(logger, providerLoginInfo);
      return done(null, loggedUser);
    } catch (e) {
      const err = e instanceof Error ? e : Error(String(e));
      logger.error(err.message, {}, err);
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
