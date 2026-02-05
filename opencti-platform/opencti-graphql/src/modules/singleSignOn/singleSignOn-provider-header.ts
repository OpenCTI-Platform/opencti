import { convertKeyValueToJsConfiguration } from './singleSignOn-providers';
import { logAuthInfo } from './singleSignOn-domain';
import { AuthType, EnvStrategyType, genConfigMapper, providerLoginHandler, PROVIDERS } from './providers-configuration';

import type { BasicStoreEntitySingleSignOn } from './singleSignOn-types';
import { logApp } from '../../config/conf';
import { isEmptyField, isNotEmptyField } from '../../database/utils';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-expect-error
import validator from 'validator';
import { addUserLoginCount } from '../../manager/telemetryManager';
import { HEADERS_AUTHENTICATORS } from '../../domain/user';

export const registerHeadertrategy = async (ssoEntity: BasicStoreEntitySingleSignOn) => {
  const providerRef = ssoEntity.identifier || 'header';
  const ssoConfig = convertKeyValueToJsConfiguration(ssoEntity);
  const providerName = ssoConfig?.label || providerRef;

  logAuthInfo('Configuring Header', EnvStrategyType.STRATEGY_HEADER, { id: ssoEntity.id, identifier: ssoEntity.identifier, providerRef });

  const ssoConfiguration: any = convertKeyValueToJsConfiguration(ssoEntity);

  // This strategy is directly handled on the fly on graphql
  logApp.info(`[ENV-PROVIDER][HEADER] Strategy found in configuration providerRef:${providerRef}`);
  const reqLoginHandler = async (req: any) => {
    // Group computations
    const isGroupMapping = isNotEmptyField(ssoEntity.groups_management) && isNotEmptyField(ssoEntity.groups_management?.groups_mapping);
    const computeGroupsMapping = () => {
      const groupsMapping = ssoEntity.groups_management?.groups_mapping || [];
      const groupsSplitter = ssoEntity.groups_management?.groups_splitter || ',';
      const availableGroups = (req.header(ssoEntity.groups_management?.groups_header) ?? '').split(groupsSplitter);
      const groupsMapper = genConfigMapper(groupsMapping);
      return availableGroups.map((a: any) => groupsMapper[a]).filter((r: any) => isNotEmptyField(r));
    };
    const mappedGroups = isGroupMapping ? computeGroupsMapping() : [];
    // Organization computations
    const isOrgaMapping = isNotEmptyField(ssoConfiguration.organizations_default) || isNotEmptyField(ssoEntity.organizations_management);
    const computeOrganizationsMapping = () => {
      const orgaDefault = ssoConfiguration.organizations_default ?? [];
      const orgasMapping = ssoEntity.organizations_management?.organizations_mapping || [];
      const orgasSplitter = ssoEntity.organizations_management?.organizations_splitter || ',';
      const availableOrgas = (req.header(ssoEntity.organizations_management?.organizations_header) ?? '').split(orgasSplitter);
      const orgasMapper = genConfigMapper(orgasMapping);
      return [...orgaDefault, ...availableOrgas.map((a: any) => orgasMapper[a]).filter((r: any) => isNotEmptyField(r))];
    };
    const organizationsToAssociate = isOrgaMapping ? computeOrganizationsMapping() : [];
    // Build the user login
    const email = req.header(ssoConfiguration.header_email);
    if (isEmptyField(email) || !validator.isEmail(email)) {
      return null;
    }
    const name = req.header(ssoConfiguration.header_name);
    const firstname = req.header(ssoConfiguration.header_firstname);
    const lastname = req.header(ssoConfiguration.header_lastname);
    const opts = {
      providerGroups: mappedGroups,
      providerOrganizations: organizationsToAssociate,
      autoCreateGroup: ssoConfiguration.auto_create_group ?? false,
    };
    const provider_metadata = { headers_audit: ssoConfiguration.headers_audit };
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
    logout_uri: ssoConfiguration.logout_uri,
    provider: providerRef,
  };
  PROVIDERS.push(headerProvider);
  HEADERS_AUTHENTICATORS.push(headerProvider);
};
