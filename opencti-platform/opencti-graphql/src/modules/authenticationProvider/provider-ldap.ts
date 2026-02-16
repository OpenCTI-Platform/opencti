import type { LdapStoreConfiguration, ProviderMeta } from './authenticationProvider-types';
import { flatExtraConf, decryptAuthValue } from './authenticationProvider-domain';
import { type AuthenticationProviderLogger } from './providers-logger';
import { AuthType, providerLoginHandler } from './providers-configuration';
import LdapStrategy, { type VerifyCallback, type VerifyDoneCallback } from 'passport-ldapauth';
import { registerAuthenticationProvider } from './providers-initialization';
import { AuthenticationProviderType } from '../../generated/graphql';
import { createMappers, resolveDotPath } from './mappings-utils';

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

export const registerLDAPStrategy = async (logger: AuthenticationProviderLogger, meta: ProviderMeta, storeConf: LdapStoreConfiguration) => {
  const ldapOptions = await createLdapOptions(storeConf);
  const { resolveUserInfo, resolveGroups, resolveOrganizations } = createMappers(storeConf);

  const ldapLoginCallback: VerifyCallback = async (user: any, done: VerifyDoneCallback) => {
    logger.info('Successfully logged on IdP', { user });

    const userInfo = await resolveUserInfo((expr) => expr ? user[expr] : undefined);
    const groups = await resolveGroups((expr) => resolveDotPath(user._groups, expr));
    const organizations = await resolveOrganizations((expr) => resolveDotPath(user, expr));

    logger.info('User info resolved', { userInfo, groups, organizations });

    const opts = {
      strategy: AuthenticationProviderType.Ldap,
      name: meta.name,
      identifier: meta.identifier,
      providerGroups: groups,
      providerOrganizations: organizations,
      autoCreateGroup: storeConf.groups_mapping.auto_create_groups,
    };
    await providerLoginHandler(userInfo, done, opts);
  };

  const ldapStrategy = new LdapStrategy(ldapOptions, ldapLoginCallback);
  registerAuthenticationProvider(
    meta.identifier,
    ldapStrategy,
    {
      name: meta.name,
      type: AuthType.AUTH_FORM,
      strategy: AuthenticationProviderType.Ldap,
      provider: meta.identifier,
    },
  );
};
