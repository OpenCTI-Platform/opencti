import type { BasicStoreEntitySingleSignOn } from './singleSignOn-types';
import { logAuthInfo } from './singleSignOn-domain';
import { AuthType, EnvStrategyType, type ProviderConfiguration } from './providers-configuration';
import { addUserLoginCount } from '../../manager/telemetryManager';
import { registerAuthenticationProvider } from './providers-initialization';
import { ConfigurationError } from '../../config/errors';
import type { PassportSamlConfig, VerifyWithoutRequest } from '@node-saml/passport-saml/lib/types';
import { isNotEmptyField } from '../../database/utils';
import type { GroupsManagement, OrganizationsManagement } from '../../generated/graphql';
import { convertKeyValueToJsConfiguration, genConfigMapper, parseValueAsType, providerLoginHandler, type ProviderUserInfo } from './singleSignOn-providers';
import { Strategy as SamlStrategy } from '@node-saml/passport-saml/lib/strategy';
import * as R from 'ramda';

export const buildSAMLOptions = async (ssoEntity: BasicStoreEntitySingleSignOn) => {
  if (ssoEntity.configuration) {
    // 1. Manage passport-saml mandatory fields
    const idpCertConfiguration = ssoEntity.configuration.find((configuration) => configuration.key === 'idpCert');
    if (!idpCertConfiguration) {
      throw ConfigurationError('idpCert is mandatory for SAML', { id: ssoEntity.id, name: ssoEntity.name });
    }

    const callbackUrlConfiguration = ssoEntity.configuration.find((configuration) => configuration.key === 'callbackUrl');
    if (!callbackUrlConfiguration) {
      throw ConfigurationError('callbackUrl is mandatory for SAML', { id: ssoEntity.id, name: ssoEntity.name });
    }

    const issuerConfiguration = ssoEntity.configuration.find((configuration) => configuration.key === 'issuer');
    if (!issuerConfiguration) {
      throw ConfigurationError('issuer is mandatory for SAML', { id: ssoEntity.id, name: ssoEntity.name });
    }

    const ssoOptions: PassportSamlConfig = {
      idpCert: idpCertConfiguration.value,
      callbackUrl: callbackUrlConfiguration.value,
      issuer: issuerConfiguration.value,
    };
    // 2. Manage passport-saml optionals fields
    const ssoOtherOptions: any = {};
    for (let i = 0; i < ssoEntity.configuration.length; i++) {
      const currentConfig = ssoEntity.configuration[i];
      if (isNotEmptyField(currentConfig.value)) {
        ssoOtherOptions[currentConfig.key] = parseValueAsType(currentConfig.value, currentConfig.type);
      }
    }
    return { ...ssoOptions, ...ssoOtherOptions } as PassportSamlConfig;
  } else {
    throw ConfigurationError('SSO configuration is empty', { id: ssoEntity.id, name: ssoEntity.name, strategy: ssoEntity.strategy });
  }
};

export const computeSamlGroupAndOrg = (ssoConfiguration: any, samlProfile: any, groupsManagement?: GroupsManagement, orgsManagement?: OrganizationsManagement) => {
  logAuthInfo('Groups management and organization management configuration', EnvStrategyType.STRATEGY_SAML, { groupsManagement, orgsManagement });

  const samlAttributes: any = samlProfile['attributes'] ? samlProfile['attributes'] : samlProfile;
  const groupAttributes = groupsManagement?.group_attributes || ['groups'];

  const isOrgaMapping = isNotEmptyField(ssoConfiguration.organizations_default) || isNotEmptyField(orgsManagement);
  const computeOrganizationsMapping = () => {
    const orgaDefault = ssoConfiguration.organizations_default ?? [];
    const orgasMapping = orgsManagement?.organizations_mapping || [];
    const orgaPath = orgsManagement?.organizations_path || ['organizations'];
    const samlOrgas = R.path(orgaPath, samlProfile) || [];
    const availableOrgas = Array.isArray(samlOrgas) ? samlOrgas : [samlOrgas];
    const orgasMapper = genConfigMapper(orgasMapping);
    return [...orgaDefault, ...availableOrgas.map((a) => orgasMapper[a]).filter((r) => isNotEmptyField(r))];
  };
  const organizationsToAssociate = isOrgaMapping ? computeOrganizationsMapping() : [];

  const computeGroupsMapping = () => {
    const attrGroups: any[][] = groupAttributes.map((a) => (Array.isArray(samlAttributes[a]) ? samlAttributes[a] : [samlAttributes[a]]));
    const samlGroups = R.flatten(attrGroups).filter((v) => isNotEmptyField(v));
    const groupsMapping = groupsManagement?.groups_mapping || [];
    const groupsMapper = genConfigMapper(groupsMapping);
    return samlGroups.map((a) => groupsMapper[a]).filter((r) => isNotEmptyField(r));
  };
  const groupsToAssociate = R.uniq(computeGroupsMapping());

  return {
    providerGroups: groupsToAssociate,
    providerOrganizations: organizationsToAssociate,
    autoCreateGroup: ssoConfiguration.auto_create_group ?? false,
  };
};

export const computeSamlUserInfo = (ssoConfiguration: any, samlProfile: any) => {
  const samlAttributes: any = samlProfile['attributes'] ? samlProfile['attributes'] : samlProfile;
  const userName = samlAttributes[ssoConfiguration.account_attribute] || '';
  const firstname = samlAttributes[ssoConfiguration.firstname_attribute] || '';
  const lastname = samlAttributes[ssoConfiguration.lastname_attribute] || '';
  const nameID = samlProfile['nameID'];
  const nameIDFormat = samlProfile['nameIDFormat'];
  const userEmail = samlAttributes[ssoConfiguration.mail_attribute] || nameID;
  if (ssoConfiguration.mail_attribute && !samlAttributes[ssoConfiguration.mail_attribute]) {
    logAuthInfo(`Custom mail_attribute "${ssoConfiguration.mail_attribute}" in configuration but the custom field is not present SAML server response.`, EnvStrategyType.STRATEGY_SAML);
  }

  if (!userEmail) {
    throw ConfigurationError('No userEmail found in SAML response, please verify SAML server and OpenCTI configuration', { profile: userEmail, openctiMailAttribute: ssoConfiguration.mail_attribute });
  }
  const userInfo: ProviderUserInfo = { email: userEmail, name: userName, firstname, lastname, provider_metadata: { nameID, nameIDFormat } };
  return userInfo;
};

export const registerSAMLStrategy = async (ssoEntity: BasicStoreEntitySingleSignOn) => {
  const providerRef = ssoEntity.identifier || 'saml';
  logAuthInfo('Configuring SAML', EnvStrategyType.STRATEGY_SAML, { id: ssoEntity.id, identifier: ssoEntity.identifier, providerRef });
  const providerName = ssoEntity?.label || ssoEntity?.identifier || ssoEntity.id;
  const samlOptions: PassportSamlConfig = await buildSAMLOptions(ssoEntity);

  const samlLoginCallback: VerifyWithoutRequest = (profile, done) => {
    const ssoConfiguration: any = convertKeyValueToJsConfiguration(ssoEntity);
    const groupsManagement = ssoEntity.groups_management;
    const orgsManagement = ssoEntity.organizations_management;

    if (!profile) {
      throw ConfigurationError('No profile in SAML response, please verify SAML server configuration');
    }
    logAuthInfo('Successfully logged from provider, computing groups and organizations', EnvStrategyType.STRATEGY_SAML, { profile, done });

    const isGroupBaseAccess = (isNotEmptyField(groupsManagement) && isNotEmptyField(groupsManagement?.groups_mapping));
    const opts = computeSamlGroupAndOrg(ssoConfiguration, profile, groupsManagement, orgsManagement);
    const groupsToAssociate = opts.providerGroups;

    if (!isGroupBaseAccess || groupsToAssociate.length > 0) {
      const opts = computeSamlGroupAndOrg(ssoConfiguration, profile, groupsManagement, orgsManagement);
      const userInfo: ProviderUserInfo = computeSamlUserInfo(ssoConfiguration, profile);
      addUserLoginCount();
      logAuthInfo('All configuration is fine, login user with', EnvStrategyType.STRATEGY_SAML, { opts, userInfo });
      providerLoginHandler(userInfo, done, opts);
    } else {
      logAuthInfo('Group configuration not found', EnvStrategyType.STRATEGY_SAML, { isGroupBaseAccess, groupsToAssociate, profile });
      done({ name: 'SAML error', message: 'Restricted access, ask your administrator' });
    }
  };

  const samlLogoutCallback: VerifyWithoutRequest = (profile) => {
    // SAML Logout function
    logAuthInfo(`Logout done for ${profile}`, EnvStrategyType.STRATEGY_SAML);
  };
  samlOptions.name = ssoEntity.identifier || 'saml';
  const samlStrategy = new SamlStrategy(samlOptions, samlLoginCallback, samlLogoutCallback);
  // TODO samlStrategy.logout_remote = samlOptions.logout_remote;
  const providerConfig: ProviderConfiguration = { name: providerName, type: AuthType.AUTH_SSO, strategy: EnvStrategyType.STRATEGY_SAML, provider: providerRef };
  registerAuthenticationProvider(providerRef, samlStrategy, providerConfig);
  logAuthInfo('Passport SAML configured', EnvStrategyType.STRATEGY_SAML, { id: ssoEntity.id, identifier: ssoEntity.identifier, providerRef });
};
