import qs from 'qs';
import axios from 'axios';
import jwtDecode from 'jwt-decode';
import { logApp } from './conf';
import { AuthenticationFailure } from './errors';

let oidcRefreshAxios = null;
let oidcIssuer = null;

export const oidcRefresh = async (refreshToken) => {
  if (oidcRefreshAxios === null) throw new Error('Unable to refresh token, OIDC not configured.');
  try {
    logApp.info(`[OIDC] Token refresh: ${refreshToken?.substring(0, 20) ?? 'missing refresh token'}`);
    const { data } = await oidcRefreshAxios.post(
      '/protocol/openid-connect/token',
      qs.stringify({
        ...oidcRefreshAxios.defaults.data,
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      }
    );
    return {
      refreshToken: data.refresh_token,
      accessToken: data.access_token,
    };
  } catch (e) {
    logApp.error(
      `[OIDC] Failed to refresh token`,
      e.response && {
        status: e.response.status,
        data: e.response.data,
      }
    );
    throw AuthenticationFailure(e.response.data.error_description, e.response.data);
  }
};

export const configureOidcRefresh = (config) => {
  oidcIssuer = config.issuer;
  oidcRefreshAxios = axios.create({
    baseURL: oidcIssuer,
    data: {
      client_id: config.client_id,
      client_secret: config.client_secret,
    },
  });
  logApp.info(`[OIDC] Setting refresh default values`, {
    client_id: oidcRefreshAxios.defaults.data['client-id'],
    client_secret: oidcRefreshAxios.defaults.data['client-id'],
    baseUrl: oidcRefreshAxios.defaults.baseURL,
  });
};

export const tokenExpired = (token) => {
  const decoded = jwtDecode(token);
  const expires = (decoded.exp - 60) * 1000;
  const epochSec = Date.now();
  return epochSec >= expires;
};
