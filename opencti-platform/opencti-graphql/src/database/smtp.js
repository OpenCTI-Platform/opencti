import nodemailer from 'nodemailer';
import { discovery as oidcDiscovery, refreshTokenGrant } from 'openid-client';
import conf, { booleanConf, logApp } from '../config/conf';
import { meterManager } from '../config/tracing';
import { getEntityFromCache } from './cache';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { isEmptyField } from './utils';

const SMTP_FORCED_EMAIL = conf.get('smtp:forced_sender_email');
export const ALLOW_EMAIL_REWRITE = isEmptyField(SMTP_FORCED_EMAIL);
const USE_SSL = booleanConf('smtp:use_ssl', false);
const REJECT_UNAUTHORIZED = booleanConf('smtp:reject_unauthorized', false);
const SMTP_ENABLE = booleanConf('smtp:enabled', true);

const baseSmtpOptions = {
  host: conf.get('smtp:hostname') || 'localhost',
  port: conf.get('smtp:port') || 25,
  secure: USE_SSL,
  tls: {
    rejectUnauthorized: REJECT_UNAUTHORIZED,
    maxVersion: conf.get('smtp:tls_max_version'),
    minVersion: conf.get('smtp:tls_min_version'),
    ciphers: conf.get('smtp:tls_ciphers'),
  },
};

const refreshSmtpAccessToken = async ({ oauthClientId, oauthClientSecret, oauthIssuer, oauthRefreshToken }) => {
  let tokens;
  try {
    const issuerUrl = new URL(oauthIssuer);
    const config = await oidcDiscovery(issuerUrl, oauthClientId, { client_secret: oauthClientSecret });
    tokens = await refreshTokenGrant(config, oauthRefreshToken);
  } catch (err) {
    throw new Error(`Unable to refresh SMTP OAuth2 access token: ${err.message}`, { cause: err });
  }
  if (!tokens?.access_token) {
    throw new Error('Unable to refresh SMTP OAuth2 access token: refresh token grant did not return an access_token');
  }
  return tokens.access_token;
};

export const buildSmtpAuth = async (authType, {
  username,
  password,
  oauthUser,
  oauthClientId,
  oauthClientSecret,
  oauthIssuer,
  oauthRefreshToken,
} = {}) => {
  if (authType === 'oauth2') {
    if (!oauthUser || !oauthClientId || !oauthClientSecret || !oauthIssuer || !oauthRefreshToken) {
      throw new Error('SMTP OAuth2 configuration is incomplete: oauth_user, oauth_client_id, oauth_client_secret, oauth_issuer and oauth_refresh_token are all required.');
    }
    const freshAccessToken = await refreshSmtpAccessToken({
      oauthClientId,
      oauthClientSecret,
      oauthIssuer,
      oauthRefreshToken,
    });
    return {
      type: 'OAuth2',
      user: oauthUser,
      clientId: oauthClientId,
      clientSecret: oauthClientSecret,
      accessToken: freshAccessToken,
    };
  }
  if (username?.length > 0) {
    return {
      user: username,
      pass: password || '',
    };
  }
  return undefined;
};

const authType = conf.get('smtp:auth_type') || 'basic';

const getSmtpAuthParams = () => ({
  username: conf.get('smtp:username'),
  password: conf.get('smtp:password'),
  oauthUser: conf.get('smtp:oauth_user'),
  oauthClientId: conf.get('smtp:oauth_client_id'),
  oauthClientSecret: conf.get('smtp:oauth_client_secret'),
  oauthIssuer: conf.get('smtp:oauth_issuer'),
  oauthRefreshToken: conf.get('smtp:oauth_refresh_token'),
});

/**
 * Build a fresh nodemailer transporter. For OAuth2 the access token is
 * refreshed at call time so that long-running instances do not fail once the
 * initial token has expired (Microsoft tokens typically live for ~1h).
 */
const createSmtpTransporter = async () => {
  const options = { ...baseSmtpOptions, tls: { ...baseSmtpOptions.tls } };
  const smtpAuth = await buildSmtpAuth(authType, getSmtpAuthParams());
  if (smtpAuth) {
    options.auth = smtpAuth;
  }
  return nodemailer.createTransport(options);
};

export const smtpConfiguredEmail = (settings) => {
  return ALLOW_EMAIL_REWRITE ? settings.platform_email : SMTP_FORCED_EMAIL;
};

export const smtpComputeFrom = async (from) => {
  const context = executionContext('smtp');
  const settings = await getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const smtp_from = from ?? settings.platform_title;
  const stmp_email = smtpConfiguredEmail(settings);
  return `${smtp_from} <${stmp_email}>`;
};

export const smtpIsAlive = async () => {
  logApp.info('[CHECK] Checking if SMTP is available');
  if (SMTP_ENABLE) {
    try {
      const transporter = await createSmtpTransporter();
      await transporter.verify();
      logApp.info('[CHECK] SMTP is alive');
    } catch {
      logApp.warn('SMTP seems down, email notification may not work');
    }
  } else {
    logApp.info('[CHECK] SMTP disabled by configuration');
  }
  return true;
};

export const sendMail = async (args, meterMetadata) => {
  if (SMTP_ENABLE) {
    const { from, to, bcc, subject, html, attachments } = args;
    // For OAuth2 the transporter is recreated so that the access token is
    // refreshed before each send (avoids failures once the token has expired).
    const transporter = await createSmtpTransporter();
    await transporter.sendMail({ from, to, bcc, subject, html, attachments });
    meterManager.emailSent(meterMetadata);
  }
};
