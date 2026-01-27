import { ConfigurationError } from '../../config/errors';
import { logApp } from '../../config/conf';
import * as R from 'ramda';
import { addUserLoginCount } from '../../manager/telemetryManager';
import { jwtDecode } from 'jwt-decode';
import { convertKeyValueToJsConfiguration, genConfigMapper, providerLoginHandler } from './singleSignOn-providers';
import { AuthType, EnvStrategyType } from '../../config/providers-configuration';
import { logAuthInfo } from './singleSignOn-domain';
import { registerAuthenticationProvider } from '../../config/providers-initialization';
import type { BasicStoreEntitySingleSignOn } from './singleSignOn-types';
// @ts-expect-error no idea wht types are not visible
import { Strategy, type VerifyFunction, type StrategyOptions } from 'openid-client/passport';
import * as client from 'openid-client';
import type passport from 'passport';

// (ssoEntity: BasicStoreEntitySingleSignOn)
export const registerOpenIdStrategy = async (ssoEntity: BasicStoreEntitySingleSignOn) => {
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

    const clientSecretConfiguration = ssoEntity.configuration.find((configuration) => configuration.key === 'client_secret');
    if (!clientSecretConfiguration) {
      throw ConfigurationError('client_secret is mandatory for OpenID', { id: ssoEntity.id, name: ssoEntity.name, identifier: ssoEntity.identifier });
    }

    logAuthInfo(`OpenIDConnectStrategy found in database providerRef:${providerRef}`, EnvStrategyType.STRATEGY_OPENID);

    const callbackURL = URL.parse(ssoConfig.redirect_uris[0]);
    const server = URL.parse(ssoConfig.issuer); // Authorization server's Issuer Identifier URL

    if (server && callbackURL) {
      const clientId: string = ssoConfig.client_id;
      const clientSecret: string = ssoConfig.client_secret;

      const config = await client.discovery(server, clientId, { clientSecret });

      const defaultScopes = ssoConfig.default_scopes ?? ['openid', 'email', 'profile'];
      const openIdScopeList = [...defaultScopes];
      const groupsScope = ssoEntity.groups_management?.groups_scope;
      if (groupsScope) {
        openIdScopeList.push(groupsScope);
      }
      const organizationsScope = ssoEntity.organizations_management?.organizations_scope;
      if (organizationsScope) {
        openIdScopeList.push(organizationsScope);
      }
      const openIdScope = R.uniq(openIdScopeList).join(' ');

      const options: StrategyOptions = {
        config,
        scope: openIdScope,
        callbackURL,
        passReqToCallback: true,
      };

      const openidLoginCallback: VerifyFunction = (tokens: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers, verified: passport.AuthenticateCallback) => {
        const accessToken = tokens['access_token'];
        const idToken = tokens['id_token'];
        let decodedUser;
        if (idToken) {
          decodedUser = jwtDecode(idToken);
        }

        const claims = tokens.claims();
        logApp.info('OPENID 2: INFO', { claims, accessToken, tokens, dec: decodedUser });

        logAuthInfo('Successfully logged', EnvStrategyType.STRATEGY_OPENID, { userinfo: tokens.claims() });
        addUserLoginCount();
        providerLoginHandler({ email, name, firstname, lastname }, verified, {});
      };

      const openIdStrategy = new Strategy(options, openidLoginCallback);
      const providerConfig = { name: providerName, type: AuthType.AUTH_SSO, strategy: EnvStrategyType.STRATEGY_OPENID, provider: providerRef };
      registerAuthenticationProvider(providerRef, openIdStrategy, providerConfig);
    }
  } else {
    throw ConfigurationError('SSO configuration is empty', { id: ssoEntity.id, name: ssoEntity.name, identifier: ssoEntity.identifier, strategy: ssoEntity.strategy });
  }
};
