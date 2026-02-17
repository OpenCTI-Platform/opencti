import { getBaseUrl, getPlatformHttpProxyAgent } from '../../config/conf';
import { allowInsecureRequests, buildEndSessionUrl, customFetch, discovery as oidcDiscovery, fetchUserInfo } from 'openid-client';
import type { StrategyOptions, VerifyFunction } from 'openid-client/passport';
import { Strategy as OpenIDStrategy } from 'openid-client/passport';
import type { AuthenticateCallback } from 'passport';
import * as R from 'ramda';
import { jwtDecode } from 'jwt-decode';
import { AuthType } from './providers-configuration';
import type { OidcStoreConfiguration, ProviderMeta } from './authenticationProvider-types';
import { type AuthenticationProviderLogger } from './providers-logger';
import { memoize } from '../../utils/memoize';
import { createMapper } from './mappings-utils';
import { flatExtraConf, decryptAuthValue } from './authenticationProvider-domain';
import { handleProviderLogin } from './providers';

const buildProxiedFetch = (issuerUrl: URL): typeof fetch => {
  const dispatcher = getPlatformHttpProxyAgent(issuerUrl.toString(), true);
  return (url, options) => fetch(url, { ...options, dispatcher });
};

export const createOpenIdStrategy = async (logger: AuthenticationProviderLogger, meta: ProviderMeta, conf: OidcStoreConfiguration) => {
  const client_secret = await decryptAuthValue(conf.client_secret_encrypted);
  const callbackURL = conf.callback_url || `${getBaseUrl()}/auth/${meta.identifier}/callback`;
  const extraConf = flatExtraConf(conf.extra_conf);
  const mapper = createMapper(conf);

  const issuer = new URL(conf.issuer);
  const customFetchImpl = conf.use_proxy ? buildProxiedFetch(issuer) : undefined;

  const config = await oidcDiscovery(
    issuer,
    conf.client_id,
    {
      ...extraConf,
      client_secret,
    },
    undefined,
    {
      [customFetch]: customFetchImpl,
      execute: [allowInsecureRequests],
    },
  );

  const options: StrategyOptions = {
    config,
    scope: R.uniq(conf.scopes ?? ['openid', 'email', 'profile']).join(' '),
    callbackURL,
    passReqToCallback: false,
    ...extraConf,
  };

  const verify: VerifyFunction = async (tokens, verified: AuthenticateCallback) => {
    try {
      logger.info('Successfully logged on IdP');

      const user_info = memoize(async () => {
        const sub = tokens.claims()?.sub;
        const userInfo = sub ? await fetchUserInfo(config, tokens.access_token, sub) : undefined;
        logger.info('User info fetched', { sub: sub ?? null, userInfo: userInfo ?? null });
        return userInfo;
      });

      const context = {
        tokens: (name: string) => typeof tokens[name] === 'string' ? jwtDecode(tokens[name]) : undefined,
        user_info,
      };

      const providerLoginInfo = await mapper(context);
      const user = await handleProviderLogin(logger, providerLoginInfo);
      return verified(null, user);
    } catch (e) {
      const err = e instanceof Error ? e : Error(String(e));
      logger.error(err.message, err);
      return verified(err);
    }
  };

  const openIDStrategy = new OpenIDStrategy(options, verify);

  const { audience } = conf;
  if (audience) {
    const original = openIDStrategy.authorizationRequestParams.bind(openIDStrategy);
    openIDStrategy.authorizationRequestParams = (req, options) => {
      const params = original(req, options) as URLSearchParams;
      params.set('audience', audience);
      return params;
    };
  }

  const logout = (_: Request, callback: (err: Error | null, uri: string) => void) => {
    const logoutCallbackUrl = conf.logout_callback_url;
    const endSessionEndpoint = config.serverMetadata().end_session_endpoint;
    if (endSessionEndpoint) {
      const params: Record<string, string> = {};
      if (logoutCallbackUrl) {
        params.post_logout_redirect_uri = logoutCallbackUrl;
      }

      const logoutUrl = buildEndSessionUrl(config, params);
      return callback(null, logoutUrl.href);
    }

    const endpointUri = `${conf.issuer}/oidc/logout`;
    const url = new URL(endpointUri);

    if (logoutCallbackUrl) {
      url.searchParams.set('post_logout_redirect_uri', logoutCallbackUrl);
    }
    return callback(null, url.href);
  };
  Object.assign(openIDStrategy, { logout });

  return {
    strategy: openIDStrategy,
    auth_type: AuthType.AUTH_SSO,
    logout_remote: conf.logout_remote,
  };
};
