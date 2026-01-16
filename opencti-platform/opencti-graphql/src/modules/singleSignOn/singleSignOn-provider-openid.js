import { ConfigurationError } from '../../config/errors';
import { getPlatformHttpProxyAgent, logApp } from '../../config/conf';
import { custom as OpenIDCustom, Issuer as OpenIDIssuer, Strategy as OpenIDStrategy } from 'openid-client';
import { enrichWithRemoteCredentials } from '../../config/credentials';
import * as R from 'ramda';
import { addUserLoginCount } from '../../manager/telemetryManager';
import { isNotEmptyField } from '../../database/utils';
import { jwtDecode } from 'jwt-decode';
import { convertKeyValueToJsConfiguration, genConfigMapper, providerLoginHandler } from './singleSignOn-providers';
import { AuthType, EnvStrategyType } from '../../config/providers-configuration';
import { logAuthInfo } from './singleSignOn-domain';
import { registerAuthenticationProvider } from '../../config/providers-initialization';

// (ssoEntity: BasicStoreEntitySingleSignOn)
export const registerOpenIdStrategy = async (ssoEntity) => {
  const providerRef = ssoEntity.identifier || 'oic';
  const ssoConfig = convertKeyValueToJsConfiguration(ssoEntity);
  const providerName = ssoConfig?.label || providerRef;

  if (ssoEntity.configuration) {
    // Check mandatory configurations
    const callBackURLConfiguration = ssoEntity.configuration.find((configuration) => configuration.key === 'redirect_uris');
    if (!callBackURLConfiguration) {
      throw ConfigurationError('redirect_uris is mandatory for OpenID', { id: ssoEntity.id, name: ssoEntity.name, identifier: ssoEntity.identifier });
    }

    const clientIdConfiguration = ssoEntity.configuration.find((configuration) => configuration.key === 'client_id');
    if (!clientIdConfiguration) {
      throw ConfigurationError('client_id is mandatory for OpenID', { id: ssoEntity.id, name: ssoEntity.name, identifier: ssoEntity.identifier });
    }

    const issuerConfiguration = ssoEntity.configuration.find((configuration) => configuration.key === 'issuer');
    if (!issuerConfiguration) {
      throw ConfigurationError('issuer is mandatory for OpenID', { id: ssoEntity.id, name: ssoEntity.name, identifier: ssoEntity.identifier });
    }
    const issuer = ssoConfig['issuer'];

    const clientSecretConfiguration = ssoEntity.configuration.find((configuration) => configuration.key === 'client_secret');
    if (!clientSecretConfiguration) {
      throw ConfigurationError('client_secret is mandatory for OpenID', { id: ssoEntity.id, name: ssoEntity.name, identifier: ssoEntity.identifier });
    }

    logAuthInfo(`OpenIDConnectStrategy found in database providerRef:${providerRef}`, EnvStrategyType.STRATEGY_OPENID);
    // Here we use directly the config and not the mapped one.
    // All config of openid lib use snake case.
    const openIdClient = ssoConfig.use_proxy ? getPlatformHttpProxyAgent(issuer) : undefined;
    OpenIDCustom.setHttpOptionsDefaults({ timeout: 0, agent: openIdClient });
    enrichWithRemoteCredentials(`providers:${providerRef}`, ssoConfig).then((clientConfig) => {
      OpenIDIssuer.discover(issuer).then((issuer) => {
        const { Client } = issuer;
        const client = new Client(clientConfig);
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
        const options = {
          logout_remote: ssoConfig.logout_remote, client, passReqToCallback: true,
          params: {
            scope: openIdScope, ...(ssoConfig.audience && { audience: ssoConfig.audience }),
          },
        };
        const debugCallback = (message, meta) => logApp.info(message, meta);
        const openIDStrategy = new OpenIDStrategy(options, debugCallback, (_, tokenset, userinfo, done) => {
          logAuthInfo('Successfully logged', EnvStrategyType.STRATEGY_OPENID, { userinfo });
          addUserLoginCount();
          const isGroupMapping = (isNotEmptyField(ssoConfig.groups_management) && isNotEmptyField(ssoConfig.groups_management?.groups_mapping));
          logAuthInfo('Groups management configuration', EnvStrategyType.STRATEGY_OPENID, { groupsManagement: ssoConfig.groups_management });
          // region groups mapping
          const computeGroupsMapping = () => {
            const readUserinfo = ssoConfig.groups_management?.read_userinfo || false;
            const token = ssoConfig.groups_management?.token_reference || 'access_token';
            const groupsPath = ssoConfig.groups_management?.groups_path || ['groups'];
            const groupsMapping = ssoConfig.groups_management?.groups_mapping || [];
            const decodedUser = jwtDecode(tokenset[token]);
            if (!readUserinfo) {
              logAuthInfo(`Groups mapping on decoded ${token}`, EnvStrategyType.STRATEGY_OPENID, { decoded: decodedUser });
            }
            const availableGroups = R.flatten(groupsPath.map((path) => {
              const userClaims = (readUserinfo) ? userinfo : decodedUser;
              const value = R.path(path.split('.'), userClaims) || [];
              return Array.isArray(value) ? value : [value];
            }));
            const groupsMapper = genConfigMapper(groupsMapping);
            return availableGroups.map((a) => groupsMapper[a]).filter((r) => isNotEmptyField(r));
          };
          const mappedGroups = isGroupMapping ? computeGroupsMapping() : [];
          const groupsToAssociate = R.uniq(mappedGroups);
          // endregion
          // region organizations mapping
          const isOrgaMapping = isNotEmptyField(ssoConfig.organizations_default) || isNotEmptyField(ssoConfig.organizations_management);
          const computeOrganizationsMapping = () => {
            const orgaDefault = ssoConfig.organizations_default ?? [];
            const readUserinfo = ssoConfig.organizations_management?.read_userinfo || false;
            const orgasMapping = ssoConfig.organizations_management?.organizations_mapping || [];
            const token = ssoConfig.organizations_management?.token_reference || 'access_token';
            const orgaPath = ssoConfig.organizations_management?.organizations_path || ['organizations'];
            const decodedUser = jwtDecode(tokenset[token]);
            const availableOrgas = R.flatten(orgaPath.map((path) => {
              const userClaims = (readUserinfo) ? userinfo : decodedUser;
              const value = R.path(path.split('.'), userClaims) || [];
              return Array.isArray(value) ? value : [value];
            }));
            const orgasMapper = genConfigMapper(orgasMapping);
            return [...orgaDefault, ...availableOrgas.map((a) => orgasMapper[a]).filter((r) => isNotEmptyField(r))];
          };
          const organizationsToAssociate = isOrgaMapping ? computeOrganizationsMapping() : [];
          // endregion
          if (!isGroupMapping || groupsToAssociate.length > 0) {
            const nameAttribute = ssoConfig.name_attribute ?? 'name';
            const emailAttribute = ssoConfig.email_attribute ?? 'email';
            const firstnameAttribute = ssoConfig.firstname_attribute ?? 'given_name';
            const lastnameAttribute = ssoConfig.lastname_attribute ?? 'family_name';
            const get_user_attributes_from_id_token = ssoConfig.get_user_attributes_from_id_token ?? false;

            const user_attribute_obj = get_user_attributes_from_id_token ? jwtDecode(tokenset.id_token) : userinfo;

            const name = user_attribute_obj[nameAttribute];
            const email = user_attribute_obj[emailAttribute];
            const firstname = user_attribute_obj[firstnameAttribute];
            const lastname = user_attribute_obj[lastnameAttribute];
            const opts = {
              providerGroups: groupsToAssociate,
              providerOrganizations: organizationsToAssociate,
              autoCreateGroup: ssoConfig.auto_create_group ?? false,
            };
            providerLoginHandler({ email, name, firstname, lastname }, done, opts);
          } else {
            done({ message: 'Restricted access, ask your administrator' });
          }
        });
        openIDStrategy.logout_remote = options.logout_remote;
        logAuthInfo('logout remote options', EnvStrategyType.STRATEGY_OPENID, options);
        openIDStrategy.logout = (_, callback) => {
          const isSpecificUri = isNotEmptyField(ssoConfig.logout_callback_url);
          const endpointUri = issuer.end_session_endpoint ? issuer.end_session_endpoint : `${ssoConfig.issuer}/oidc/logout`;
          logAuthInfo(`logout configuration, isSpecificUri:${isSpecificUri}, issuer.end_session_endpoint:${issuer.end_session_endpoint}, final endpointUri: ${endpointUri}`, EnvStrategyType.STRATEGY_OPENID);
          if (isSpecificUri) {
            const logoutUri = `${endpointUri}?post_logout_redirect_uri=${ssoConfig.logout_callback_url}`;
            callback(null, logoutUri);
          } else {
            callback(null, endpointUri);
          }
        };
        const providerConfig = { name: providerName, type: AuthType.AUTH_SSO, strategy: EnvStrategyType.STRATEGY_OPENID, provider: providerRef };
        registerAuthenticationProvider(providerRef, openIDStrategy, providerConfig);
      }).catch((err) => {
        logApp.error('[SSO OPENID] Error initializing authentication provider', {
          cause: err,
          provider: providerRef,
        });
      });
    }).catch((reason) => logApp.error('[SSO OPENID] Error when enrich with remote credentials', { cause: reason }));
  } else {
    throw ConfigurationError('SSO configuration is empty', { id: ssoEntity.id, name: ssoEntity.name, identifier: ssoEntity.identifier, strategy: ssoEntity.strategy });
  }
};
