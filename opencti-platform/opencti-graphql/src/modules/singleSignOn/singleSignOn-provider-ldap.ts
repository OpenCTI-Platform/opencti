import type { BasicStoreEntitySingleSignOn } from './singleSignOn-types';
import { logAuthInfo, logAuthWarn } from './singleSignOn-domain';
import { AuthType, EnvStrategyType, genConfigMapper, type ProviderConfiguration, providerLoginHandler, type ProviderUserInfo } from './providers-configuration';
import { convertKeyValueToJsConfiguration } from './singleSignOn-providers';
import * as R from 'ramda';
import LdapStrategy, { type VerifyCallback, type VerifyDoneCallback } from 'passport-ldapauth';
import { addUserLoginCount } from '../../manager/telemetryManager';
import { isNotEmptyField } from '../../database/utils';
import { registerAuthenticationProvider } from './providers-initialization';

export const computeLdapUserInfo = (ssoConfiguration: any, ldapProfile: any) => {
  const userMail = ssoConfiguration.mail_attribute ? ldapProfile[ssoConfiguration.mail_attribute] : ldapProfile.mail;
  const userName = ssoConfiguration.account_attribute ? ldapProfile[ssoConfiguration.account_attribute] : ldapProfile.givenName;
  const firstname = ldapProfile[ssoConfiguration.firstname_attribute] || '';
  const lastname = ldapProfile[ssoConfiguration.lastname_attribute] || '';

  const userInfo: ProviderUserInfo = {
    email: userMail,
    name: userName,
    firstname: firstname,
    lastname: lastname,
  };
  logAuthInfo('User info from authentication', EnvStrategyType.STRATEGY_LDAP, { userInfo });
  return userInfo;
};

export const computeLdapGroups = (ssoEntity: BasicStoreEntitySingleSignOn, ldapProfile: any) => {
  const groupAttribute = ssoEntity.groups_management?.group_attribute || 'cn';
  const ldapGroups = ldapProfile._groups;
  logAuthInfo('Computing groups', EnvStrategyType.STRATEGY_LDAP, { groupManagement: ssoEntity.groups_management, ldapGroups, groupAttribute });

  const groupsMapping = ssoEntity.groups_management?.groups_mapping || [];
  const userGroups = (ldapGroups || [])
    .map((g: any) => g[groupAttribute])
    .filter((g: any) => isNotEmptyField(g));

  const groupsMapper = genConfigMapper(groupsMapping);
  logAuthInfo('Computing groups - groupsMapper', EnvStrategyType.STRATEGY_LDAP, { groupsMapper, userGroups });
  const groups: string[] = userGroups.map((a: any) => groupsMapper[a]).filter((r: any) => isNotEmptyField(r));
  return R.uniq(groups);
};

export const computeLdapOrganizations = (ssoEntity: BasicStoreEntitySingleSignOn, ldapProfile: any, defaultOrganizations: string[] | undefined) => {
  const orgaDefault = defaultOrganizations ?? [];
  const orgasMapping = ssoEntity.organizations_management?.organizations_mapping || [];
  const orgaPath = ssoEntity.organizations_management?.organizations_path || ['organizations'];

  const availableOrgas = R.flatten(
    orgaPath.map((path: any) => {
      const value = R.path(path.split('.'), ldapProfile) || [];
      return Array.isArray(value) ? value : [value];
    }),
  );
  const orgasMapper = genConfigMapper(orgasMapping);
  return [...orgaDefault, ...availableOrgas.map((a) => orgasMapper[a]).filter((r) => isNotEmptyField(r))];
};

export const registerLDAPStrategy = async (ssoEntity: BasicStoreEntitySingleSignOn) => {
  const providerRef = ssoEntity.identifier || 'ldapauth';

  logAuthInfo('Configuring LDAP', EnvStrategyType.STRATEGY_LDAP, { id: ssoEntity.id, identifier: ssoEntity.identifier, providerRef });

  const ssoConfiguration: any = await convertKeyValueToJsConfiguration(ssoEntity);
  const providerName = ssoConfiguration?.label || providerRef;

  const allowSelfSigned = ssoConfiguration.allow_self_signed || ssoConfiguration.allow_self_signed === 'true';

  const tlsConfig = R.assoc('tlsOptions', { rejectUnauthorized: !allowSelfSigned }, ssoConfiguration);
  const ldapOptions = { server: tlsConfig };

  const ldapLoginCallback: VerifyCallback = (user: any, done: VerifyDoneCallback) => {
    logAuthInfo('Successfully logged', EnvStrategyType.STRATEGY_LDAP, { user });

    const userInfo = computeLdapUserInfo(ssoConfiguration, user);
    const isGroupBaseAccess = (isNotEmptyField(ssoEntity.groups_management) && isNotEmptyField(ssoEntity.groups_management?.groups_mapping));
    const groupsToAssociate = computeLdapGroups(ssoEntity, user);

    const isOrgaMapping = isNotEmptyField(ssoConfiguration.organizations_default) || isNotEmptyField(ssoEntity.organizations_management);
    const organizationsToAssociate = isOrgaMapping ? computeLdapOrganizations(ssoEntity, user, ssoConfiguration.organizations_default) : [];

    if (!userInfo.email) {
      logAuthWarn('[ENV-PROVIDER]LDAP Configuration error, cant map mail and username', EnvStrategyType.STRATEGY_LDAP, { userInfo });
      done({ message: 'Configuration error, ask your administrator' });
    } else if (!isGroupBaseAccess || groupsToAssociate.length > 0) {
      logAuthInfo(`[ENV-PROVIDER][LDAP] Connecting/creating account with ${userInfo.email} [name=${userInfo.name}]`, EnvStrategyType.STRATEGY_LDAP);
      const opts = {
        providerGroups: groupsToAssociate,
        providerOrganizations: organizationsToAssociate,
        autoCreateGroup: ssoConfiguration.auto_create_group ?? false,
      };
      addUserLoginCount();
      providerLoginHandler(userInfo, done, opts);
    } else {
      logAuthWarn('[ENV-PROVIDER]LDAP Group or Org configuration error', EnvStrategyType.STRATEGY_LDAP, { userInfo, groupsToAssociate, organizationsToAssociate });
      done({ message: 'Restricted access, ask your administrator' });
    }
  };
  const ldapStrategy = new LdapStrategy(ldapOptions, ldapLoginCallback);

  const providerConfig: ProviderConfiguration = { name: providerName, type: AuthType.AUTH_FORM, strategy: EnvStrategyType.STRATEGY_LDAP, provider: providerRef };
  registerAuthenticationProvider(providerRef, ldapStrategy, providerConfig);
  logAuthInfo('Passport LDAP configured', EnvStrategyType.STRATEGY_LDAP, { id: ssoEntity.id, identifier: ssoEntity.identifier, providerRef });
};
