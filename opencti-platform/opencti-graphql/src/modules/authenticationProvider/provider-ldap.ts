import type { LdapProviderConfiguration } from './authenticationProvider-types';
import { logAuthInfo, logAuthWarn } from './providers-logger';
import { AuthType, EnvStrategyType, type ProviderConfiguration, providerLoginHandler } from './providers-configuration';
import LdapStrategy, { type VerifyCallback, type VerifyDoneCallback } from 'passport-ldapauth';
import { addUserLoginCount } from '../../manager/telemetryManager';
import { registerAuthenticationProvider } from './providers-initialization';
import { AuthenticationProviderType } from '../../generated/graphql';
import { resolveGroups, resolveOrganizations, resolvePath, resolveUserInfo } from './mappings-utils';

// TODO default conf for LDAP user info mapping : email -> 'mail' & name -> 'givenName'
// TODO default conf for LDAP group mapping : ['_groups/cn'] or just ['cn'] ?
// TODO default conf for LDAP orga mapping : ['organizations'] ?

const convertConfiguration = (conf: LdapProviderConfiguration): LdapStrategy.Options => ({
  server: {
    url: conf.url,
    bindDN: conf.bind_dn,
    bindCredentials: conf.bind_credentials,
    searchBase: conf.search_base,
    searchFilter: conf.search_filter,
    groupSearchBase: conf.group_base,
    groupSearchFilter: conf.group_filter,
    tlsOptions: {
      rejectUnauthorized: !(conf.allow_self_signed ?? false),
    },
    ...conf.extra_conf,
  },
});

export const registerLDAPStrategy = async (conf: LdapProviderConfiguration) => {
  logAuthInfo('Configuring LDAP', AuthenticationProviderType.Ldap, { conf });

  const ldapOptions = convertConfiguration(conf);
  const ldapLoginCallback: VerifyCallback = async (user: any, done: VerifyDoneCallback) => {
    logAuthInfo('Successfully logged', AuthenticationProviderType.Ldap, { user });

    const userInfo = await resolveUserInfo(conf.user_info_mapping, (expr) => expr ? user[expr] : undefined);
    const groups = await resolveGroups(conf.groups_mapping, (expr) => resolvePath(user._groups, expr.split('.')));
    const organizations = await resolveOrganizations(conf.organizations_mapping, (expr) => resolvePath(user, expr.split('.')));

    if (!userInfo.email) {
      logAuthWarn('[ENV-PROVIDER]LDAP Configuration error, cannot map email', AuthenticationProviderType.Ldap, { userInfo });
      done({ message: 'Configuration error, ask your administrator' });
    } else if (groups.length > 0) {
      logAuthInfo(`[ENV-PROVIDER][LDAP] Connecting/creating account with ${userInfo.email} [name=${userInfo.name}]`, AuthenticationProviderType.Ldap);
      const opts = {
        providerGroups: groups,
        providerOrganizations: organizations,
        autoCreateGroup: conf.groups_mapping.auto_create_group,
      };
      addUserLoginCount();
      await providerLoginHandler(userInfo, done, opts);
    } else {
      logAuthWarn('[ENV-PROVIDER]LDAP Group or Org configuration error', AuthenticationProviderType.Ldap, { userInfo, groups, organizations });
      done({ message: 'Restricted access, ask your administrator' });
    }
  };

  const ldapStrategy = new LdapStrategy(ldapOptions, ldapLoginCallback);

  const providerConfig: ProviderConfiguration = { name: conf.name, type: AuthType.AUTH_FORM, strategy: AuthenticationProviderType.Ldap, provider: conf.identifier };
  registerAuthenticationProvider(conf.identifier, ldapStrategy, providerConfig);
};
