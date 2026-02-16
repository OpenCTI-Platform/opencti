import { getPlatformHttpProxyAgent } from '../../config/conf';
import { allowInsecureRequests, buildEndSessionUrl, customFetch, discovery as oidcDiscovery, fetchUserInfo } from 'openid-client';
import type { StrategyOptions, VerifyFunction } from 'openid-client/passport';
import { Strategy as OpenIDStrategy } from 'openid-client/passport';
import type { AuthenticateCallback } from 'passport';
import * as R from 'ramda';
import { jwtDecode } from 'jwt-decode';
import { AuthType, providerLoginHandler } from './providers-configuration';
import { registerAuthenticationProvider } from './providers-initialization';
import type { OidcProviderConfiguration } from './authenticationProvider-types';
import { createAuthLogger } from './providers-logger';
import { memoize } from '../../utils/memoize';
import { resolveGroups, resolveOrganizations, resolvePath, resolveUserInfo } from './mappings-utils';
import { AuthenticationProviderType } from '../../generated/graphql';

const buildProxiedFetch = (issuerUrl: URL): typeof fetch => {
  const dispatcher = getPlatformHttpProxyAgent(issuerUrl.toString(), true);
  return (url, options) => fetch(url, { ...options, dispatcher });
};

export const registerOpenIdStrategy = async (conf: OidcProviderConfiguration) => {
  const log = createAuthLogger(AuthenticationProviderType.Oidc, conf.identifier);
  log.info('Configuring strategy', { conf });

  const issuer = new URL(conf.issuer);
  const customFetchImpl = conf.use_proxy ? buildProxiedFetch(issuer) : undefined;

  const config = await oidcDiscovery(
    issuer,
    conf.client_id,
    {
      client_secret: conf.client_secret,
      ...conf.extra_conf,
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
    callbackURL: conf.callback_url,
    passReqToCallback: false,
    ...conf.extra_conf,
  };

  const verify: VerifyFunction = async (tokens, verified: AuthenticateCallback) => {
    log.info('Successfully logged on IdP', { tokens });

    const user_info = memoize(async () => {
      const sub = tokens.claims()?.sub;
      const userInfo = sub ? await fetchUserInfo(config, tokens.access_token, sub) : undefined;
      log.info('User info fetched', { sub: sub ?? null, userInfo: userInfo ?? null });
      return userInfo;
    });

    const context = {
      tokens: (name: string) => typeof tokens[name] === 'string' ? jwtDecode(tokens[name]) : undefined,
      user_info,
    };
    const resolveExpr = (expr: string) => resolvePath<string>(context, expr.split('.'));

    const userInfo = await resolveUserInfo(conf.user_info_mapping, resolveExpr);
    const groups = await resolveGroups(conf.groups_mapping, resolveExpr);
    const organizations = await resolveOrganizations(conf.organizations_mapping, resolveExpr);

    log.info('User info resolved', { userInfo, groups, organizations });

    const opts = {
      strategy: AuthenticationProviderType.Oidc,
      name: conf.name,
      identifier: conf.identifier,
      providerGroups: groups,
      providerOrganizations: organizations,
      autoCreateGroup: conf.groups_mapping.auto_create_groups,
    };
    await providerLoginHandler(userInfo, verified, opts);
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

  registerAuthenticationProvider(
    conf.identifier,
    openIDStrategy,
    {
      name: conf.name,
      type: AuthType.AUTH_SSO,
      strategy: AuthenticationProviderType.Oidc,
      provider: conf.identifier,
      logout_remote: conf.logout_remote,
    },
  );
};
