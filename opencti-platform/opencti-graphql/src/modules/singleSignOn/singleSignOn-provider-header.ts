import { convertKeyValueToJsConfiguration } from './singleSignOn-providers';
import { logAuthInfo } from './singleSignOn-domain';
import { AuthType, EnvStrategyType, genConfigMapper, providerLoginHandler, PROVIDERS, type ProviderUserInfo } from './providers-configuration';

import type { BasicStoreEntitySingleSignOn } from './singleSignOn-types';
import { logApp } from '../../config/conf';
import { isEmptyField, isNotEmptyField } from '../../database/utils';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-expect-error
import validator from 'validator';
import { addUserLoginCount } from '../../manager/telemetryManager';
import { HEADERS_AUTHENTICATORS } from '../../domain/user';

export const computeHeaderUserInfo = (ssoConfiguration: any, headerProfile: any) => {
  const userMail = ssoConfiguration.header_email ? headerProfile[ssoConfiguration.header_email] : headerProfile.email;
  const userName = ssoConfiguration.account_attribute ? headerProfile[ssoConfiguration.account_attribute] : headerProfile.name;
  const firstname = headerProfile[ssoConfiguration.header_firstname] || headerProfile.given_name;
  const lastname = headerProfile[ssoConfiguration.header_lastname] || headerProfile.family_name;

  const userInfo: ProviderUserInfo = {
    email: userMail,
    name: userName,
    firstname: firstname,
    lastname: lastname,
  };
  logAuthInfo('User info from authentication', EnvStrategyType.STRATEGY_HEADER, { userInfo });
  return userInfo;
};

export const computeGroupsMapping = (ssoEntity: BasicStoreEntitySingleSignOn, req: any) => {
  const groupsMapping = ssoEntity.groups_management?.groups_mapping || [];
  const groupsSplitter = ssoEntity.groups_management?.groups_splitter || ',';
  const availableGroups = (req.header(ssoEntity.groups_management?.groups_header) ?? '').split(groupsSplitter);
  const groupsMapper = genConfigMapper(groupsMapping);
  return availableGroups.map((a: any) => groupsMapper[a]).filter((r: any) => isNotEmptyField(r));
};

export const computeOrganizationsMapping = (ssoEntity: BasicStoreEntitySingleSignOn, orgaDefault: string[], req: any) => {
  const orgasMapping = ssoEntity.organizations_management?.organizations_mapping || [];
  const orgasSplitter = ssoEntity.organizations_management?.organizations_splitter || ',';
  const availableOrgas = (req.header(ssoEntity.organizations_management?.organizations_header) ?? '').split(orgasSplitter);
  const orgasMapper = genConfigMapper(orgasMapping);
  return [...orgaDefault, ...availableOrgas.map((a: any) => orgasMapper[a]).filter((r: any) => isNotEmptyField(r))];
};

export const registerHeadertrategy = async (ssoEntity: BasicStoreEntitySingleSignOn) => {
  const providerRef = ssoEntity.identifier || 'header';
  const ssoConfig = await convertKeyValueToJsConfiguration(ssoEntity);
  const providerName = ssoConfig?.label || providerRef;

  logAuthInfo('Configuring Header', EnvStrategyType.STRATEGY_HEADER, { id: ssoEntity.id, identifier: ssoEntity.identifier, providerRef });

  // This strategy is directly handled on the fly on graphql
  logApp.info(`[ENV-PROVIDER][HEADER] Strategy found in configuration providerRef:${providerRef}`);
  const reqLoginHandler = async (req: any) => {
    // Group computations
    const isGroupMapping = isNotEmptyField(ssoEntity.groups_management) && isNotEmptyField(ssoEntity.groups_management?.groups_mapping);

    const mappedGroups = isGroupMapping ? computeGroupsMapping(ssoEntity, req) : [];
    // Organization computations
    const isOrgaMapping = isNotEmptyField(ssoConfig.organizations_default) || isNotEmptyField(ssoEntity.organizations_management);
    const organizationsToAssociate = isOrgaMapping ? computeOrganizationsMapping(ssoEntity, ssoConfig.organizations_default ?? [], req) : [];
    // Build the user login
    const email = req.header(ssoConfig.header_email);
    if (isEmptyField(email) || !validator.isEmail(email)) {
      return null;
    }
    const name = req.header(ssoConfig.header_name);
    const firstname = req.header(ssoConfig.header_firstname);
    const lastname = req.header(ssoConfig.header_lastname);
    const opts = {
      providerGroups: mappedGroups,
      providerOrganizations: organizationsToAssociate,
      autoCreateGroup: ssoConfig.auto_create_group ?? false,
    };
    const provider_metadata = { headers_audit: ssoConfig.headers_audit };
    addUserLoginCount();
    return new Promise((resolve) => {
      providerLoginHandler({ email, name, firstname, provider_metadata, lastname }, (err: any, user: any) => {
        resolve(user);
      }, opts);
    });
  };
  const headerProvider = {
    name: providerName,
    reqLoginHandler,
    type: AuthType.AUTH_REQ,
    strategy: EnvStrategyType.STRATEGY_HEADER,
    logout_uri: ssoConfig.logout_uri,
    provider: providerRef,
  };
  PROVIDERS.push(headerProvider);
  HEADERS_AUTHENTICATORS.push(headerProvider);
};
