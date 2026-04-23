import nodemailer from 'nodemailer';
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

const smtpOptions = {
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

export const buildSmtpAuth = (authType, { username, password, oauthUser, oauthClientId, oauthClientSecret, oauthAccessToken }) => {
  if (authType === 'oauth2') {
    if (!oauthUser || !oauthClientId || !oauthClientSecret || !oauthAccessToken) {
      throw new Error('SMTP OAuth2 configuration is incomplete: oauth_user, oauth_client_id, oauth_client_secret and oauth_access_token are all required.');
    }
    return {
      type: 'OAuth2',
      user: oauthUser,
      clientId: oauthClientId,
      clientSecret: oauthClientSecret,
      accessToken: oauthAccessToken,
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
const smtpAuth = buildSmtpAuth(authType, {
  username: conf.get('smtp:username'),
  password: conf.get('smtp:password'),
  oauthUser: conf.get('smtp:oauth_user'),
  oauthClientId: conf.get('smtp:oauth_client_id'),
  oauthClientSecret: conf.get('smtp:oauth_client_secret'),
  oauthAccessToken: conf.get('smtp:oauth_access_token'),
});
if (smtpAuth) {
  smtpOptions.auth = smtpAuth;
}

export const transporter = nodemailer.createTransport(smtpOptions);

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
  if (SMTP_ENABLE) {
    try {
      await transporter.verify();
    } catch {
      logApp.warn('SMTP seems down, email notification may not work');
    }
  }
  return true;
};

export const sendMail = async (args, meterMetadata) => {
  if (SMTP_ENABLE) {
    const { from, to, bcc, subject, html, attachments } = args;
    await transporter.sendMail({ from, to, bcc, subject, html, attachments });
    meterManager.emailSent(meterMetadata);
  }
};
