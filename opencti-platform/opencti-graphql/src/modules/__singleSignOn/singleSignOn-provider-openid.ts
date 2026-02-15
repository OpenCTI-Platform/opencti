import { ConfigurationError } from '../../config/errors';
import { getPlatformHttpProxyAgent, logApp } from '../../config/conf';
import { discovery as oidcDiscovery, fetchUserInfo, customFetch, buildEndSessionUrl, allowInsecureRequests } from 'openid-client';
import type { StrategyOptions, VerifyFunction } from 'openid-client/passport';
import { Strategy as OpenIDStrategy } from 'openid-client/passport';
import type { AuthenticateCallback } from 'passport';
import { enrichWithRemoteCredentials } from '../../config/credentials';
import * as R from 'ramda';
import { addUserLoginCount } from '../../manager/telemetryManager';
import { isNotEmptyField } from '../../database/utils';
import { jwtDecode } from 'jwt-decode';
import { convertKeyValueToJsConfiguration } from './singleSignOn-providers';
import { AuthType, EnvStrategyType, genConfigMapper, providerLoginHandler } from './providers-configuration';
import { logAuthInfo } from './singleSignOn-domain';
import { registerAuthenticationProvider } from './providers-initialization';
import type { BasicStoreEntitySingleSignOn, GroupsManagement, OrganizationsManagement } from './singleSignOn-types';

export const computeOpenIdUserInfo = (ssoConfig: any, user_attribute_obj: any) => {
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

export const computeOpenIdOrganizationsMapping = (
  orgsManagement: OrganizationsManagement | undefined, decodedUser: unknown, userinfo: unknown, orgaDefault: string[]) => {
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

export const computeOpenIdGroupsMapping = (groupManagement: GroupsManagement | undefined, decodedUser: unknown, userinfo: unknown) => {
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

const buildProxiedFetch = (issuerUrl: URL): typeof fetch => {
  const dispatcher = getPlatformHttpProxyAgent(issuerUrl.toString(), true);
  return (url, options) => fetch(url, { ...options, dispatcher });
};

export const registerOpenIdStrategy = async (ssoEntity: BasicStoreEntitySingleSignOn) => {
  const providerRef = ssoEntity.identifier || 'oic';
  const rawConfig = await convertKeyValueToJsConfiguration(ssoEntity);
  const ssoConfig = await enrichWithRemoteCredentials(`providers:${providerRef}`, rawConfig);
  logApp.debug('OpenIDConnectStrategy enriched configuration', { conf: ssoConfig, providerRef });

  // Check mandatory configurations
  const issuerUrl = Boolean(ssoConfig.issuer) && URL.parse(ssoConfig.issuer);
  if (!issuerUrl) {
    throw ConfigurationError('issuer is mandatory for OpenID', { id: ssoEntity.id, name: ssoEntity.name, identifier: ssoEntity.identifier });
  }

  const clientId: string | undefined = ssoConfig.client_id;
  if (!clientId) {
    throw ConfigurationError('client_id is mandatory for OpenID', { id: ssoEntity.id, name: ssoEntity.name, identifier: ssoEntity.identifier });
  }

  const clientSecret: string | undefined = ssoConfig.client_secret;
  if (!clientSecret) {
    throw ConfigurationError('client_secret is mandatory for OpenID', { id: ssoEntity.id, name: ssoEntity.name, identifier: ssoEntity.identifier });
  }

  const callbackURL: string | undefined = ssoConfig.redirect_uri;
  if (!callbackURL) {
    throw ConfigurationError('redirect_uri is mandatory for OpenID', { id: ssoEntity.id, name: ssoEntity.name, identifier: ssoEntity.identifier });
  }

  // Here we use directly the config and not the mapped one.
  // All config of openid lib use snake case.
  try {
    const customFetchImpl = ssoConfig.use_proxy ? buildProxiedFetch(issuerUrl) : undefined;

    const config = await oidcDiscovery(
      issuerUrl,
      clientId,
      {
        client_secret: clientSecret,
      },
      undefined,
      {
        [customFetch]: customFetchImpl,
        execute: [allowInsecureRequests],
      },
    );

    // region scopes generation
    const defaultScopes = ssoConfig.default_scopes ?? ['openid', 'email', 'profile'];
    const openIdScopes = [...defaultScopes];
    const groupsScope = ssoConfig.groups_management?.groups_scope;
    if (groupsScope) {
      openIdScopes.push(groupsScope);
    }
    const organizationsScope = ssoConfig.organizations_management?.organizations_scope;
    if (organizationsScope) {
      openIdScopes.push(organizationsScope);
    }
    // endregion
    const openIdScope = R.uniq(openIdScopes).join(' ');
    const options: StrategyOptions = {
      config,
      scope: openIdScope,
      callbackURL,
      passReqToCallback: false,
    };

    const verify: VerifyFunction = async (tokens, verified: AuthenticateCallback) => {
      const getUserAttributesFromIdToken = ssoConfig.get_user_attributes_from_id_token ?? false;
      const userinfo = getUserAttributesFromIdToken ? jwtDecode(tokens.id_token!) : await fetchUserInfo(config, tokens.access_token, tokens.claims()!.sub!);

      logAuthInfo('Successfully logged', EnvStrategyType.STRATEGY_OPENID, { userinfo });

      const groupsManagement = ssoEntity?.groups_management;
      const isGroupMapping = isNotEmptyField(groupsManagement) && isNotEmptyField(groupsManagement?.groups_mapping);
      logAuthInfo('Groups management configuration', EnvStrategyType.STRATEGY_OPENID, { groupsManagement });
      // region groups mapping
      const token = groupsManagement?.token_reference || 'access_token';
      const decodedUser = jwtDecode(tokens[token] as string);
      const mappedGroups = isGroupMapping ? computeOpenIdGroupsMapping(groupsManagement, decodedUser, userinfo) : [];
      const groupsToAssociate = R.uniq(mappedGroups);
      // endregion
      // region organizations mapping
      const orgsManagement = ssoEntity.organizations_management;
      const isOrgaMapping = isNotEmptyField(ssoConfig.organizations_default) || isNotEmptyField(orgsManagement);
      const orgaDefault = ssoConfig.organizations_default ?? [];
      const organizationsToAssociate = isOrgaMapping ? computeOpenIdOrganizationsMapping(orgsManagement, decodedUser, userinfo, orgaDefault) : [];
      // endregion
      if (!isGroupMapping || groupsToAssociate.length > 0) {
        const userInfo = computeOpenIdUserInfo(ssoConfig, userinfo);

        const opts = {
          providerGroups: groupsToAssociate,
          providerOrganizations: organizationsToAssociate,
          autoCreateGroup: ssoConfig.auto_create_group ?? false,
        };
        addUserLoginCount();
        providerLoginHandler(userInfo, verified, opts);
      } else {
        verified({ message: 'Restricted access, ask your administrator' });
      }
    };

    const openIDStrategy = new OpenIDStrategy(options, verify);
    if (ssoConfig.audience) {
      const original = openIDStrategy.authorizationRequestParams.bind(openIDStrategy);
      openIDStrategy.authorizationRequestParams = (req, options) => {
        const params = original(req, options) as URLSearchParams;
        params.set('audience', ssoConfig.audience);
        return params;
      };
    }

    logAuthInfo('logout remote options', EnvStrategyType.STRATEGY_OPENID, options);
    const logout = (_: Request, callback: (err: Error | null, uri: string) => void) => {
      const logoutCallbackUrl = isNotEmptyField(ssoConfig.logout_callback_url) ? ssoConfig.logout_callback_url : undefined;
      const endSessionEndpoint = config.serverMetadata().end_session_endpoint;
      if (endSessionEndpoint) {
        const params: Record<string, string> = {};
        if (logoutCallbackUrl) {
          params.post_logout_redirect_uri = logoutCallbackUrl;
        }

        const logoutUrl = buildEndSessionUrl(config, params);
        return callback(null, logoutUrl.href);
      }

      const endpointUri = `${ssoConfig.issuer}/oidc/logout`;
      const url = new URL(endpointUri);

      if (logoutCallbackUrl) {
        url.searchParams.set('post_logout_redirect_uri', logoutCallbackUrl);
      }
      return callback(null, url.href);
    };
    Object.assign(openIDStrategy, { logout });

    const providerName = ssoConfig?.label || providerRef;
    const providerConfig = {
      name: providerName,
      type: AuthType.AUTH_SSO,
      strategy: EnvStrategyType.STRATEGY_OPENID,
      provider: providerRef,
      logout_remote: ssoConfig.logout_remote,
    };

    registerAuthenticationProvider(providerRef, openIDStrategy, providerConfig);
  } catch (err) {
    logApp.error('[SSO OPENID] Error initializing authentication provider', {
      cause: err,
      provider: providerRef,
    });
  }
};
