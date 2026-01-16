import type { BasicStoreEntitySingleSignOn } from './singleSignOn-types';
import { logAuthInfo } from './singleSignOn-domain';
import { AuthType, EnvStrategyType, type ProviderConfiguration } from './providers-configuration';
import { convertKeyValueToJsConfiguration, genConfigMapper, providerLoginHandler } from './singleSignOn-providers';
import * as R from 'ramda';
import LdapStrategy, { type VerifyCallback, type VerifyDoneCallback } from 'passport-ldapauth';
import { logApp } from '../../config/conf';
import { addUserLoginCount } from '../../manager/telemetryManager';
import { isNotEmptyField } from '../../database/utils';
import { registerAuthenticationProvider } from './providers-initialization';

export const registerLDAPStrategy = async (ssoEntity: BasicStoreEntitySingleSignOn) => {
  const providerRef = ssoEntity.identifier || 'ldapauth';

  logAuthInfo('Configuring LDAP', EnvStrategyType.STRATEGY_LDAP, { id: ssoEntity.id, identifier: ssoEntity.identifier, providerRef });

  const ssoConfiguration: any = convertKeyValueToJsConfiguration(ssoEntity);
  const providerName = ssoConfiguration?.label || providerRef;

  const allowSelfSigned = ssoConfiguration.allow_self_signed || ssoConfiguration.allow_self_signed === 'true';

  const tlsConfig = R.assoc('tlsOptions', { rejectUnauthorized: !allowSelfSigned }, ssoConfiguration);
  const ldapOptions = { server: tlsConfig };

  const ldapLoginCallback: VerifyCallback = (user: any, done: VerifyDoneCallback) => {
    logAuthInfo('Successfully logged', EnvStrategyType.STRATEGY_LDAP, { user });
    addUserLoginCount();
    const userMail = ssoConfiguration.mail_attribute ? user[ssoConfiguration.mail_attribute] : user.mail;
    const userName = ssoConfiguration.account_attribute ? user[ssoConfiguration.account_attribute] : user.givenName;
    const firstname = user[ssoConfiguration.firstname_attribute] || '';
    const lastname = user[ssoConfiguration.lastname_attribute] || '';
    const isGroupBaseAccess = (isNotEmptyField(ssoConfiguration.groups_management) && isNotEmptyField(ssoConfiguration.groups_management?.groups_mapping));
    // region groups mapping
    const computeGroupsMapping = () => {
      const groupsMapping = ssoConfiguration.groups_management?.groups_mapping || [];
      const userGroups = (user._groups || [])
        .map((g: any) => g[ssoConfiguration.groups_management?.group_attribute || 'cn'])
        .filter((g: any) => isNotEmptyField(g));
      const groupsMapper = genConfigMapper(groupsMapping);
      return userGroups.map((a: any) => groupsMapper[a]).filter((r: any) => isNotEmptyField(r));
    };
    const groupsToAssociate = R.uniq(computeGroupsMapping());
    // endregion
    // region organizations mapping
    const isOrgaMapping = isNotEmptyField(ssoConfiguration.organizations_default) || isNotEmptyField(ssoConfiguration.organizations_management);
    const computeOrganizationsMapping = () => {
      const orgaDefault = ssoConfiguration.organizations_default ?? [];
      const orgasMapping = ssoConfiguration.organizations_management?.organizations_mapping || [];
      const orgaPath = ssoConfiguration.organizations_management?.organizations_path || ['organizations'];

      const availableOrgas = R.flatten(
        orgaPath.map((path: any) => {
          const value = R.path(path.split('.'), user) || [];
          return Array.isArray(value) ? value : [value];
        }),
      );
      const orgasMapper = genConfigMapper(orgasMapping);
      return [...orgaDefault, ...availableOrgas.map((a) => orgasMapper[a]).filter((r) => isNotEmptyField(r))];
    };
    const organizationsToAssociate = isOrgaMapping ? computeOrganizationsMapping() : [];
    // endregion
    if (!userMail) {
      logApp.warn('[ENV-PROVIDER]LDAP Configuration error, cant map mail and username', {
        user,
        userMail,
        userName,
      });
      done({ message: 'Configuration error, ask your administrator' });
    } else if (!isGroupBaseAccess || groupsToAssociate.length > 0) {
      logApp.info(`[ENV-PROVIDER][LDAP] Connecting/creating account with ${userMail} [name=${userName}]`);
      const userInfo = { email: userMail, name: userName, firstname, lastname };
      const opts = {
        providerGroups: groupsToAssociate,
        providerOrganizations: organizationsToAssociate,
        autoCreateGroup: ssoConfiguration.auto_create_group ?? false,
      };
      providerLoginHandler(userInfo, done, opts);
    } else {
      done({ message: 'Restricted access, ask your administrator' });
    }
  };
  const ldapStrategy = new LdapStrategy(ldapOptions, ldapLoginCallback);

  const providerConfig: ProviderConfiguration = { name: providerName, type: AuthType.AUTH_FORM, strategy: EnvStrategyType.STRATEGY_LDAP, provider: providerRef };
  registerAuthenticationProvider(providerRef, ldapStrategy, providerConfig);
  logAuthInfo('Passport LDAP configured', EnvStrategyType.STRATEGY_LDAP, { id: ssoEntity.id, identifier: ssoEntity.identifier, providerRef });
};
