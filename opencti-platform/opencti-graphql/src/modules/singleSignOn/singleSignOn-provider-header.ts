import { logAuthInfo } from './singleSignOn-domain';
import {
  AuthType,
  EnvStrategyType,
  genConfigMapper,
  HEADER_STRATEGY_IDENTIFIER,
  type ProviderConfiguration,
  providerLoginHandler,
  type ProviderUserInfo,
} from './providers-configuration';
import { logApp } from '../../config/conf';
import { isEmptyField, isNotEmptyField } from '../../database/utils';
import validator from 'validator';
import { addUserLoginCount } from '../../manager/telemetryManager';
import type { BasicStoreSettings, HeadersAuthConfig } from '../../types/settings';
import type { AuthContext } from '../../types/user';
import { getSettings } from '../../domain/settings';

export let HEADER_PROVIDER: ProviderConfiguration | undefined = undefined;

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

// Settings-based group mapping (used by header strategy from Settings entity)
export const computeGroupsMappingFromSettings = (headerAuth: HeadersAuthConfig, req: any) => {
  const groupsMapping = headerAuth.groups_mapping ?? [];
  const groupsSplitter = headerAuth.groups_splitter ?? ',';
  const availableGroups = (req.header(headerAuth.groups_header) ?? '').split(groupsSplitter);
  const groupsMapper = genConfigMapper(groupsMapping);
  return availableGroups.map((a: any) => groupsMapper[a]).filter((r: any) => isNotEmptyField(r));
};

// Settings-based org mapping (used by header strategy from Settings entity)
export const computeOrganizationsMappingFromSettings = (headerAuth: HeadersAuthConfig, req: any) => {
  const orgaDefault = headerAuth.organizations_default ?? [];
  const orgasMapping = headerAuth.organizations_mapping ?? [];
  const orgasSplitter = headerAuth.organizations_splitter ?? ',';
  const availableOrgas = (req.header(headerAuth.organizations_header) ?? '').split(orgasSplitter);
  const orgasMapper = genConfigMapper(orgasMapping);
  return [...orgaDefault, ...availableOrgas.map((a: any) => orgasMapper[a]).filter((r: any) => isNotEmptyField(r))];
};

export const registerHeaderStrategy = async (context: AuthContext) => {
  const providerName = 'Headers strategy';
  logAuthInfo('Configuring Header', EnvStrategyType.STRATEGY_HEADER, { providerRef: HEADER_STRATEGY_IDENTIFIER });
  // This strategy is directly handled on the fly on graphql
  logApp.info(`[ENV-PROVIDER][HEADER] Strategy found in configuration providerRef:${HEADER_STRATEGY_IDENTIFIER}`);
  const reqLoginHandler = async (req: any) => {
    const settings = await getSettings(context) as unknown as BasicStoreSettings;
    const headerStrategy = settings.headers_auth;
    if (!headerStrategy) {
      return null;
    }
    // Group computations
    const isGroupMapping = isNotEmptyField(headerStrategy.groups_header) && isNotEmptyField(headerStrategy.groups_mapping);
    const mappedGroups = isGroupMapping ? computeGroupsMappingFromSettings(headerStrategy, req) : [];
    // Organization computations
    const isOrgaMapping = isNotEmptyField(headerStrategy.organizations_default) || isNotEmptyField(headerStrategy.organizations_header);
    const organizationsToAssociate = isOrgaMapping ? computeOrganizationsMappingFromSettings(headerStrategy, req) : [];
    // Build the user login
    const email = req.header(headerStrategy.header_email);
    if (isEmptyField(email) || !validator.isEmail(email)) {
      return null;
    }
    const name = req.header(headerStrategy.header_name);
    const firstname = req.header(headerStrategy.header_firstname);
    const lastname = req.header(headerStrategy.header_lastname);
    const opts = {
      providerGroups: mappedGroups,
      providerOrganizations: organizationsToAssociate,
      autoCreateGroup: headerStrategy.auto_create_group ?? false,
    };
    const provider_metadata = { headers_audit: headerStrategy.headers_audit };
    addUserLoginCount();
    return new Promise((resolve) => {
      const userInfo = { email, name, firstname, provider_metadata, lastname };
      const done = (_: any, user: any) => {
        resolve(user);
      };
      providerLoginHandler(userInfo, done, opts);
    });
  };
  HEADER_PROVIDER = {
    name: providerName,
    reqLoginHandler,
    type: AuthType.AUTH_REQ,
    strategy: EnvStrategyType.STRATEGY_HEADER,
    provider: HEADER_STRATEGY_IDENTIFIER,
  };
};
