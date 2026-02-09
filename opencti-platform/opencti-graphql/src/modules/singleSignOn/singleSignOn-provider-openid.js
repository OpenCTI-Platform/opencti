import { ConfigurationError } from '../../config/errors';
import { getPlatformHttpProxyAgent, logApp } from '../../config/conf';
import { custom as OpenIDCustom, Issuer as OpenIDIssuer, Strategy as OpenIDStrategy } from 'openid-client';
import { enrichWithRemoteCredentials } from '../../config/credentials';
import * as R from 'ramda';
import { addUserLoginCount } from '../../manager/telemetryManager';
import { isNotEmptyField } from '../../database/utils';
import { jwtDecode } from 'jwt-decode';
import { convertKeyValueToJsConfiguration } from './singleSignOn-providers';
import { AuthType, EnvStrategyType, genConfigMapper, providerLoginHandler } from './providers-configuration';
import { logAuthInfo } from './singleSignOn-domain';
import { registerAuthenticationProvider } from './providers-initialization';

export const computeOpenIdUserInfo = (ssoConfig, user_attribute_obj) => {
  const nameAttribute = ssoConfig.name_attribute ?? 'name';
  const emailAttribute = ssoConfig.email_attribute ?? 'email';
  const firstnameAttribute = ssoConfig.firstname_attribute ?? 'given_name';
  const lastnameAttribute = ssoConfig.lastname_attribute ?? 'family_name';

  const name = user_attribute_obj[nameAttribute];
  const email = user_attribute_obj[emailAttribute];
  const firstname = user_attribute_obj[firstnameAttribute];
  const lastname = user_attribute_obj[lastnameAttribute];

  return { email, name, firstname, lastname };
};

export const computeOpenIdOrganizationsMapping = (orgsManagement, decodedUser, userinfo, orgaDefault) => {
  const readUserinfo = orgsManagement?.read_userinfo || false;
  const orgasMapping = orgsManagement?.organizations_mapping || [];
  const orgaPath = orgsManagement?.organizations_path || ['organizations'];
  const availableOrgas = R.flatten(orgaPath.map((path) => {
    const userClaims = (readUserinfo) ? userinfo : decodedUser;
    const value = R.path(path.split('.'), userClaims) || [];
    return Array.isArray(value) ? value : [value];
  }));
  const orgasMapper = genConfigMapper(orgasMapping);
  return [...orgaDefault, ...availableOrgas.map((a) => orgasMapper[a]).filter((r) => isNotEmptyField(r))];
};

export const computeOpenIdGroupsMapping = (groupManagement, decodedUser, userinfo) => {
  const readUserinfo = groupManagement?.read_userinfo || false;
  const groupsPath = groupManagement?.groups_path || ['groups'];
  const groupsMapping = groupManagement?.groups_mapping || [];

  if (!readUserinfo) {
    logAuthInfo('Groups mapping on decoded token', EnvStrategyType.STRATEGY_OPENID, { decoded: decodedUser });
  }
  logAuthInfo(`Groups mapping readUserinfo:${readUserinfo}`, EnvStrategyType.STRATEGY_OPENID, { decodedUser, userinfo, groupsPath, groupsMapping });
  const availableGroups = R.flatten(groupsPath.map((path) => {
    const userClaims = (readUserinfo) ? userinfo : decodedUser;
    const value = R.path(path.split('.'), userClaims) || [];
    return Array.isArray(value) ? value : [value];
  }));
  const groupsMapper = genConfigMapper(groupsMapping);
  return availableGroups.map((a) => groupsMapper[a]).filter((r) => isNotEmptyField(r));
};

// (ssoEntity: BasicStoreEntitySingleSignOn)
export const registerOpenIdStrategy = async (ssoEntity) => {
  const providerRef = ssoEntity.identifier || 'oic';
  const ssoConfig = await convertKeyValueToJsConfiguration(ssoEntity);
  const providerName = ssoEntity?.label || providerRef;
  const ssoConfigEnriched = await enrichWithRemoteCredentials(`providers:${providerRef}`, ssoConfig);

  logApp.debug(`OpenIDConnectStrategy enriched providerRef:${providerRef}`, EnvStrategyType.STRATEGY_OPENID, ssoConfigEnriched);

  // Check mandatory configurations
  if (!ssoConfigEnriched.redirect_uris) {
    throw ConfigurationError('redirect_uris is mandatory for OpenID', { id: ssoEntity.id, name: ssoEntity.name, identifier: ssoEntity.identifier });
  }

  if (!ssoConfigEnriched.client_id) {
    throw ConfigurationError('client_id is mandatory for OpenID', { id: ssoEntity.id, name: ssoEntity.name, identifier: ssoEntity.identifier });
  }

  if (!ssoConfigEnriched.issuer) {
    throw ConfigurationError('issuer is mandatory for OpenID', { id: ssoEntity.id, name: ssoEntity.name, identifier: ssoEntity.identifier });
  }
  const issuer = ssoConfigEnriched['issuer'];

  if (!ssoConfigEnriched.client_secret) {
    throw ConfigurationError('client_secret is mandatory for OpenID', { id: ssoEntity.id, name: ssoEntity.name, identifier: ssoEntity.identifier });
  }

  // Here we use directly the config and not the mapped one.
  // All config of openid lib use snake case.
  const openIdClient = ssoConfigEnriched.use_proxy ? getPlatformHttpProxyAgent(issuer) : undefined;
  OpenIDCustom.setHttpOptionsDefaults({ timeout: 0, agent: openIdClient });
  OpenIDIssuer.discover(issuer).then((issuer) => {
    const { Client } = issuer;
    const client = new Client(ssoConfigEnriched);
    // region scopes generation
    const defaultScopes = ssoConfigEnriched.default_scopes ?? ['openid', 'email', 'profile'];
    const openIdScopes = [...defaultScopes];
    const groupsScope = ssoConfigEnriched.groups_management?.groups_scope;
    if (groupsScope) {
      openIdScopes.push(groupsScope);
    }
    const organizationsScope = ssoConfigEnriched.organizations_management?.organizations_scope;
    if (organizationsScope) {
      openIdScopes.push(organizationsScope);
    }
    // endregion
    const openIdScope = R.uniq(openIdScopes).join(' ');
    const options = {
      client,
      passReqToCallback: true,
      params: {
        scope: openIdScope, ...(ssoConfigEnriched.audience && { audience: ssoConfigEnriched.audience }),
      },
    };
    const debugCallback = (message, meta) => logApp.info(message, meta);
    const openIDStrategy = new OpenIDStrategy(options, debugCallback, (_, tokenset, userinfo, done) => {
      logAuthInfo('Successfully logged', EnvStrategyType.STRATEGY_OPENID, { userinfo });

      const isGroupMapping = (isNotEmptyField(ssoEntity?.groups_management) && isNotEmptyField(ssoEntity?.groups_management.groups_mapping));
      logAuthInfo('Groups management configuration', EnvStrategyType.STRATEGY_OPENID, { groupsManagement: ssoEntity?.groups_management });
      const groupManagement = ssoEntity?.groups_management;
      // region groups mapping
      const token = groupManagement?.token_reference || 'access_token';
      const decodedUser = jwtDecode(tokenset[token]);
      const mappedGroups = isGroupMapping ? computeOpenIdGroupsMapping(groupManagement, decodedUser, userinfo) : [];
      const groupsToAssociate = R.uniq(mappedGroups);
      // endregion
      // region organizations mapping
      const isOrgaMapping = isNotEmptyField(ssoConfigEnriched.organizations_default) || isNotEmptyField(ssoEntity.organizations_management);
      const orgsManagement = ssoEntity.organizations_management;
      const orgaDefault = ssoConfigEnriched.organizations_default ?? [];
      const organizationsToAssociate = isOrgaMapping ? computeOpenIdOrganizationsMapping(orgsManagement, decodedUser, userinfo, orgaDefault) : [];
      // endregion
      if (!isGroupMapping || groupsToAssociate.length > 0) {
        const get_user_attributes_from_id_token = ssoConfigEnriched.get_user_attributes_from_id_token ?? false;
        const user_attribute_obj = get_user_attributes_from_id_token ? jwtDecode(tokenset.id_token) : userinfo;
        const userInfo = computeOpenIdUserInfo(ssoConfigEnriched, user_attribute_obj);

        const opts = {
          providerGroups: groupsToAssociate,
          providerOrganizations: organizationsToAssociate,
          autoCreateGroup: ssoConfigEnriched.auto_create_group ?? false,
        };
        addUserLoginCount();
        providerLoginHandler(userInfo, done, opts);
      } else {
        done({ message: 'Restricted access, ask your administrator' });
      }
    });
    logAuthInfo('logout remote options', EnvStrategyType.STRATEGY_OPENID, options);
    openIDStrategy.logout = (_, callback) => {
      const isSpecificUri = isNotEmptyField(ssoConfigEnriched.logout_callback_url);
      const endpointUri = issuer.end_session_endpoint ? issuer.end_session_endpoint : `${ssoConfigEnriched.issuer}/oidc/logout`;
      logAuthInfo(`logout configuration, isSpecificUri:${isSpecificUri}, issuer.end_session_endpoint:${issuer.end_session_endpoint}, final endpointUri: ${endpointUri}`, EnvStrategyType.STRATEGY_OPENID);
      if (isSpecificUri) {
        const logoutUri = `${endpointUri}?post_logout_redirect_uri=${ssoConfigEnriched.logout_callback_url}`;
        callback(null, logoutUri);
      } else {
        callback(null, endpointUri);
      }
    };
    const providerConfig = {
      name: providerName,
      type: AuthType.AUTH_SSO,
      strategy: EnvStrategyType.STRATEGY_OPENID,
      provider: providerRef,
      logout_remote: ssoConfigEnriched.logout_remote,
    };
    registerAuthenticationProvider(providerRef, openIDStrategy, providerConfig);
  }).catch((err) => {
    logApp.error('[SSO OPENID] Error initializing authentication provider', {
      cause: err,
      provider: providerRef,
    });
  });
};
