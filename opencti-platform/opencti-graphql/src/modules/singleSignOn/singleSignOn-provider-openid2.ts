import type { BasicStoreEntitySingleSignOn } from './singleSignOn-types';
import * as client from 'openid-client';
// @ts-expect-error no idea wht types are not visible
import { Strategy, type VerifyFunction, type StrategyOptions } from 'openid-client/passport';
import { registerAuthenticationProvider } from '../../config/providers-initialization';
import { AuthType, EnvStrategyType } from '../../config/providers-configuration';
import { logApp } from '../../config/conf';
import { logAuthInfo } from './singleSignOn-domain';
import { ConfigurationError } from '../../config/errors';
import { convertKeyValueToJsConfiguration, providerLoginHandler } from './singleSignOn-providers';
import { addUserLoginCount } from '../../manager/telemetryManager';
import type passport from 'passport';
import { jwtDecode } from 'jwt-decode';

// see https://github.com/panva/openid-client/blob/main/examples/passport.ts

export const registerOpenIdStrategy2 = async (ssoEntity: BasicStoreEntitySingleSignOn) => {
  const identifier = ssoEntity.identifier;
  const ssoConfig = convertKeyValueToJsConfiguration(ssoEntity);

  logAuthInfo(`OpenIDConnectStrategy found in database providerRef:${identifier}`, EnvStrategyType.STRATEGY_OPENID);
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

    logAuthInfo(`OpenIDConnectStrategy OpenID:${identifier}`, EnvStrategyType.STRATEGY_OPENID, { callbackURL: ssoConfig.redirect_uris[0], clientId: ssoConfig.client_id, clientSecret: ssoConfig.client_secret, issuer: ssoConfig.issuer });

    const callbackURL = URL.parse(ssoConfig.redirect_uris[0]);
    const clientId: string = ssoConfig.client_id;
    const clientSecret: string = ssoConfig.client_secret;
    const scope = 'openid email profile';
    const server = URL.parse(ssoConfig.issuer); // Authorization server's Issuer Identifier URL

    if (server && callbackURL) {
      const openidLoginCallback: VerifyFunction = (tokens: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers, verified: passport.AuthenticateCallback) => {
        const accessToken = tokens['access_token'];
        const idToken = tokens['id_token'];
        let decodedUser;
        if (idToken) {
          decodedUser = jwtDecode(idToken);
        }

        const claims = tokens.claims();
        logApp.info('OPENID 2: INFO', { claims, accessToken, tokens, dec: decodedUser });
        // verified(null, tokens.claims());

        const name = 'Angélique';
        const email = 'angelique.jard@gmail.com';
        const firstname = 'Angélique';
        const lastname = 'Jard';

        logAuthInfo('Successfully logged', EnvStrategyType.STRATEGY_OPENID, { userinfo: tokens.claims() });
        addUserLoginCount();
        providerLoginHandler({ email, name, firstname, lastname }, verified, {});
      };
      const config = await client.discovery(server, clientId, { clientSecret });
      const options: StrategyOptions = {
        config,
        scope,
        callbackURL,
      };

      const openIdStrategy = new Strategy(options, openidLoginCallback);
      const providerConfig = { name: 'openid2 CTA', type: AuthType.AUTH_SSO, strategy: EnvStrategyType.STRATEGY_OPENID, provider: identifier };
      registerAuthenticationProvider(identifier, openIdStrategy, providerConfig);
    }
  } else {
    throw ConfigurationError('SSO configuration is empty', { id: ssoEntity.id, name: ssoEntity.name, identifier: ssoEntity.identifier, strategy: ssoEntity.strategy });
  }
};
