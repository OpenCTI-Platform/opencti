import qs from 'qs';
import axios from 'axios';
import jwtDecode from 'jwt-decode';
import { logApp } from './conf';

let oidcRefreshAxios = null;
let oidcIssuer = null;

export const oidcRefresh = async (refreshToken) => {
  if (oidcRefreshAxios === null) throw new Error('Unable to refresh token, OIDC not configured.');
  try {
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
    logApp.error(`[OIDC] Failed to refresh token`, e.data);
    throw e;
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
};

export const tokenExpired = (token) => {
  const decoded = jwtDecode(token);
  const expires = decoded.exp;
  const nowTime = new Date();
  const epochSec = Math.round(nowTime.getTime() / 1000) + nowTime.getTimezoneOffset() * 60;
  return epochSec < expires + 60;
};
