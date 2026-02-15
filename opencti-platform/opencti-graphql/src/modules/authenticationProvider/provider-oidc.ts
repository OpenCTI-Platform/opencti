import { getPlatformHttpProxyAgent, logApp } from '../../config/conf';
import { allowInsecureRequests, buildEndSessionUrl, customFetch, discovery as oidcDiscovery, fetchUserInfo } from 'openid-client';
import type { StrategyOptions, VerifyFunction } from 'openid-client/passport';
import { Strategy as OpenIDStrategy } from 'openid-client/passport';
import type { AuthenticateCallback } from 'passport';
import * as R from 'ramda';
import { addUserLoginCount } from '../../manager/telemetryManager';
import { jwtDecode } from 'jwt-decode';
import { AuthType, providerLoginHandler } from './providers-configuration';
import { registerAuthenticationProvider } from './providers-initialization';
import type { OidcProviderConfiguration } from './authenticationProvider-types';
import { logAuthInfo } from './providers-logger';
import { memoize } from '../../utils/memoize';
import { resolveGroups, resolveOrganizations, resolvePath, resolveUserInfo } from './mappings-utils';
import { AuthenticationProviderType } from '../../generated/graphql';

const buildProxiedFetch = (issuerUrl: URL): typeof fetch => {
  const dispatcher = getPlatformHttpProxyAgent(issuerUrl.toString(), true);
  return (url, options) => fetch(url, { ...options, dispatcher });
};

export const registerOpenIdStrategy = async (conf: OidcProviderConfiguration) => {
  logAuthInfo('Configuring OpenID strategy', AuthenticationProviderType.Ldap, { conf });

  // Here we use directly the config and not the mapped one.
  // All config of openid lib use snake case.
  try {
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

    const openIdScope = R.uniq(conf.scopes ?? ['openid', 'email', 'profile']).join(' ');
    const options: StrategyOptions = {
      config,
      scope: openIdScope,
      callbackURL: conf.callback_url,
      passReqToCallback: false,
      ...conf.extra_conf,
    };

    const verify: VerifyFunction = async (tokens, verified: AuthenticateCallback) => {
      const user_info = memoize(async () => {
        const sub = tokens.claims()?.sub;
        const userInfo = sub ? await fetchUserInfo(config, tokens.access_token, sub) : undefined;
        logAuthInfo('User info fetched', AuthenticationProviderType.Oidc, { sub, userInfo });
        return userInfo;
      });

      const context = {
        tokens: (name: string) => typeof tokens[name] === 'string' ? jwtDecode(tokens[name]) : undefined,
        user_info,
      };
      const resolveExpr = (expr: string) => resolvePath<string>(context, expr.split('.'));

      logAuthInfo('Successfully logged', AuthenticationProviderType.Oidc);

      const groups = await resolveGroups(conf.groups_mapping, resolveExpr);
      if (groups.length > 0) { // TODO to be handled in providerLoginHandler ?
        const userInfo = await resolveUserInfo(conf.user_info_mapping, resolveExpr);
        const organizations = await resolveOrganizations(conf.organizations_mapping, resolveExpr);

        const opts = {
          providerGroups: groups,
          providerOrganizations: organizations,
          autoCreateGroup: conf.groups_mapping.auto_create_group ?? false,
        };
        addUserLoginCount();
        await providerLoginHandler(userInfo, verified, opts);
      } else {
        verified({ message: 'Restricted access, ask your administrator' });
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

    logAuthInfo('logout remote options', AuthenticationProviderType.Oidc, options);
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

    const providerConfig = {
      name: conf.name,
      type: AuthType.AUTH_SSO,
      strategy: AuthenticationProviderType.Oidc,
      provider: conf.identifier,
      logout_remote: conf.logout_remote,
    };

    registerAuthenticationProvider(conf.identifier, openIDStrategy, providerConfig);
  } catch (err) {
    logApp.error('[SSO OPENID] Error initializing authentication provider', {
      cause: err,
      provider: conf.identifier,
    });
  }
};
