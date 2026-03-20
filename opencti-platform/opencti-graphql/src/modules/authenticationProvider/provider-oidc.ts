import { getBaseUrl, getPlatformHttpProxyAgent } from '../../config/conf';
import type { Request } from 'express';
import { allowInsecureRequests, buildEndSessionUrl, customFetch, discovery as oidcDiscovery, fetchUserInfo } from 'openid-client';
import type { AuthenticateOptions, StrategyOptionsWithRequest, VerifyFunctionWithRequest } from 'openid-client/passport';
import { Strategy as OpenIDStrategy } from 'openid-client/passport';
import type { AuthenticateCallback } from 'passport';
import * as R from 'ramda';
import { jwtDecode } from 'jwt-decode';
import { AuthType } from './providers-configuration';
import type { OidcStoreConfiguration, ProviderMeta } from './authenticationProvider-types';
import { type AuthenticationProviderLogger } from './providers-logger';
import { memoize } from '../../utils/memoize';
import { createMapper } from './mappings-utils';
import { flatExtraConf, retrieveSecrets } from './authenticationProvider-domain';
import { handleProviderLogin } from './providers';
import { skipSubjectCheck } from 'oauth4webapi';
import { decodeOidcState, encodeOidcState } from '../../http/httpUtils';

const buildProxiedFetch = (issuerUrl: URL): typeof fetch => {
  const dispatcher = getPlatformHttpProxyAgent(issuerUrl.toString(), true);
  return (url, options) => fetch(url, { ...options, dispatcher });
};

export const createOpenIdStrategy = async (logger: AuthenticationProviderLogger, meta: ProviderMeta, conf: OidcStoreConfiguration) => {
  const secretsProvider = await retrieveSecrets(conf);
  const client_secret = await secretsProvider.mandatory('client_secret');
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

  const options: StrategyOptionsWithRequest = {
    config,
    scope: R.uniq(conf.scopes.length > 0 ? conf.scopes : ['openid', 'email', 'profile']).join(' '),
    callbackURL,
    passReqToCallback: true,
    ...extraConf,
  };

  const tryJwtDecode = (token: string | undefined) => {
    if (token) {
      try {
        return jwtDecode(token);
      } catch {
        return { error: 'Token is not a valid JWT' };
      }
    }
    return undefined;
  };

  const verify: VerifyFunctionWithRequest = async (req: Request, tokens, verified: AuthenticateCallback) => {
    logger.info('Successfully logged on IdP', {
      tokens: {
        access_token: tryJwtDecode(tokens.access_token),
        id_token: tryJwtDecode(tokens.id_token),
        refresh_token: tryJwtDecode(tokens.refresh_token),
      },
      scope: tokens.scope,
    });

    const sessionNonce = req.session?.nonce;
    const state = decodeOidcState(req.query?.state as string);
    if (sessionNonce !== state?.nonce) {
      logger.info('Nonce mismatch in OIDC state parameter', { sessionNonce, stateNonce: state?.nonce });
      return verified(new Error('Invalid state parameter'));
    }

    try {
      const user_info = memoize(async () => {
        const userInfo = await fetchUserInfo(config, tokens.access_token, skipSubjectCheck);
        logger.info('User info fetched', userInfo);
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
      return verified(err);
    }
  };

  const openIDStrategy = new OpenIDStrategy(options, verify);

  const { audience } = conf;

  // Always override authorizationRequestParams to relay application state (referer)
  // through the OIDC state parameter, similar to how SAML uses RelayState.
  // With openid-client v6, the state parameter is no longer always generated
  // (PKCE is used instead), so we must set it explicitly to relay the referer.
  const originalParams = openIDStrategy.authorizationRequestParams.bind(openIDStrategy);
  openIDStrategy.authorizationRequestParams = (req: Request, options: AuthenticateOptions) => {
    const params = originalParams(req, options) as URLSearchParams;
    if (audience) {
      params.set('audience', audience);
    }

    const session = req.session;
    if (session) {
      const referer = session.referer ?? '';
      const { nonce, state } = encodeOidcState(referer);
      session.nonce = nonce;
      params.set('state', state);
    }
    return params;
  };

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
