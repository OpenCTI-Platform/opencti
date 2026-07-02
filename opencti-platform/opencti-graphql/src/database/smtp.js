import nodemailer from 'nodemailer';
import { discovery as oidcDiscovery, refreshTokenGrant } from 'openid-client';
import conf, { booleanConf, logApp } from '../config/conf';
import { meterManager } from '../config/tracing';
import { getEntityFromCache } from './cache';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { isEmptyField } from './utils';
import { getSmtpConfiguration } from '../modules/smtpConfiguration/smtpConfiguration-domain';
import { decryptSmtpSecret } from '../modules/smtpConfiguration/smtpConfiguration-crypto';

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

// OAuth2 caches:
let cachedDiscoveryConfig;
let cachedAccessToken;
let cachedAccessTokenExpiresAt = 0;
let inFlightRefresh; // concurrent refresh attempts are coalesced via an in-flight Promise

const ACCESS_TOKEN_REFRESH_MARGIN_MS = 5 * 60 * 1000; // Refresh the token a bit before it actually expires

const refreshSmtpAccessToken = async ({ oauthClientId, oauthClientSecret, oauthIssuer, oauthRefreshToken }) => {
  if (cachedAccessToken && Date.now() < cachedAccessTokenExpiresAt - ACCESS_TOKEN_REFRESH_MARGIN_MS) {
    return cachedAccessToken;
  }
  if (inFlightRefresh) {
    return inFlightRefresh;
  }
  inFlightRefresh = (async () => {
    let tokens;
    try {
      if (!cachedDiscoveryConfig) {
        const issuerUrl = new URL(oauthIssuer);
        cachedDiscoveryConfig = await oidcDiscovery(issuerUrl, oauthClientId, { client_secret: oauthClientSecret });
      }
      tokens = await refreshTokenGrant(cachedDiscoveryConfig, oauthRefreshToken);
    } catch (err) {
      throw new Error(`Unable to refresh SMTP OAuth2 access token: ${err.message}`, { cause: err });
    }
    if (!tokens?.access_token) {
      throw new Error('Unable to refresh SMTP OAuth2 access token: refresh token grant did not return an access_token');
    }
    cachedAccessToken = tokens.access_token;
    const expiresInSeconds = typeof tokens.expires_in === 'number' ? tokens.expires_in : 3600;
    cachedAccessTokenExpiresAt = Date.now() + expiresInSeconds * 1000;
    return cachedAccessToken;
  })();
  try {
    return await inFlightRefresh;
  } finally {
    inFlightRefresh = null;
  }
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

const getConfAuthParams = () => ({
  username: conf.get('smtp:username'),
  password: conf.get('smtp:password'),
  oauthUser: conf.get('smtp:oauth_user'),
  oauthClientId: conf.get('smtp:oauth_client_id'),
  oauthClientSecret: conf.get('smtp:oauth_client_secret'),
  oauthIssuer: conf.get('smtp:oauth_issuer'),
  oauthRefreshToken: conf.get('smtp:oauth_refresh_token'),
});

// --- DB config helpers ---

const getEffectiveDbConfig = async () => {
  const context = executionContext('smtp');
  const dbConfig = await getSmtpConfiguration(context, SYSTEM_USER);
  return dbConfig?.use_db_config ? dbConfig : null;
};

const buildSmtpOptionsFromDb = (dbConfig) => ({
  host: dbConfig.hostname || 'localhost',
  port: dbConfig.port || 587,
  secure: dbConfig.use_ssl ?? false,
  tls: {
    rejectUnauthorized: dbConfig.reject_unauthorized ?? false,
  },
});

const getDbAuthParams = async (dbConfig) => ({
  username: dbConfig.username,
  password: await decryptSmtpSecret(dbConfig.password_encrypted),
  oauthUser: dbConfig.oauth_user,
  oauthClientId: dbConfig.oauth_client_id,
  oauthClientSecret: await decryptSmtpSecret(dbConfig.oauth_client_secret_encrypted),
  oauthIssuer: dbConfig.oauth_issuer,
  oauthRefreshToken: await decryptSmtpSecret(dbConfig.oauth_refresh_token_encrypted),
});

// Build a nodemailer transporter from the effective SMTP configuration.
// TODO: should we cache the transporter here? Without connection pooling

const createSmtpTransporter = async () => {
  const dbConfig = await getEffectiveDbConfig();
  const useDb = dbConfig !== null;

  const smtpOptions = useDb
    ? buildSmtpOptionsFromDb(dbConfig)
    : { ...baseSmtpOptions, tls: { ...baseSmtpOptions.tls } };

  const effectiveAuthType = useDb ? (dbConfig.auth_type ?? 'basic') : authType;
  const authParams = useDb ? await getDbAuthParams(dbConfig) : getConfAuthParams();

  const smtpAuth = await buildSmtpAuth(effectiveAuthType, authParams);
  if (smtpAuth) {
    smtpOptions.auth = smtpAuth;
  }
  return nodemailer.createTransport(smtpOptions);
};

/**
 * Test-only helper. Resets all module-level caches (OIDC discovery, OAuth2
 * access token, in-flight refresh) so unit tests can run independently of
 * each other. Not meant to be called from production code.
 * @internal
 */
export const __resetSmtpCachesForTests = () => {
  cachedDiscoveryConfig = undefined;
  cachedAccessToken = undefined;
  cachedAccessTokenExpiresAt = 0;
  inFlightRefresh = null;
};

/**
 * Returns whether the sender email address can be rewritten per-notification.
 *
 * When DB config is active and a `sender_email_address` is set, the sender is
 * fixed and cannot be overridden. Otherwise falls back to the JSON/env-var
 * `ALLOW_EMAIL_REWRITE` flag.
 */
export const isEmailRewriteAllowed = async () => {
  const dbConfig = await getEffectiveDbConfig();
  if (dbConfig) {
    return !dbConfig.sender_email_address;
  }
  return ALLOW_EMAIL_REWRITE;
};

/**
 * Returns the effective sender email for the given settings entity.
 *
 * Priority:
 *   1. DB forced sender (`sender_email_address` when `use_db_config` is true)
 *   2. JSON/env-var forced sender (`smtp:forced_sender_email`)
 *   3. Platform email from Settings (when rewrite is allowed)
 */
export const smtpConfiguredEmail = async (settings) => {
  const dbConfig = await getEffectiveDbConfig();
  if (dbConfig?.sender_email_address) {
    return dbConfig.sender_email_address;
  }
  return ALLOW_EMAIL_REWRITE ? settings.platform_email : SMTP_FORCED_EMAIL;
};

export const smtpComputeFrom = async (from) => {
  const context = executionContext('smtp');
  const settings = await getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const smtp_from = from ?? settings.platform_title;
  const stmp_email = await smtpConfiguredEmail(settings);
  return `${smtp_from} <${stmp_email}>`;
};

const isSmtpEnabled = async () => {
  const dbConfig = await getEffectiveDbConfig();
  if (dbConfig !== null) {
    return dbConfig.smtp_enabled ?? true;
  }
  return SMTP_ENABLE;
};

export const smtpIsAlive = async () => {
  logApp.info('[CHECK] Checking if SMTP is available');
  const smtpEnabled = await isSmtpEnabled();
  if (smtpEnabled) {
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
  const smtpEnabled = await isSmtpEnabled();
  if (smtpEnabled) {
    const { from, to, bcc, subject, html, attachments } = args;
    // For OAuth2 the transporter is recreated so that the access token is
    // refreshed before each send (avoids failures once the token has expired).
    const transporter = await createSmtpTransporter();
    await transporter.sendMail({ from, to, bcc, subject, html, attachments });
    meterManager.emailSent(meterMetadata);
  }
};

/**
 * Sends a test email using the current effective SMTP configuration.
 * Used by the `smtpConfigurationTest` GraphQL mutation.
 */
export const smtpTest = async (to) => {
  const transporter = await createSmtpTransporter();
  const from = await smtpComputeFrom();
  await transporter.sendMail({
    from,
    to,
    subject: 'OpenCTI SMTP Test',
    html: '<p>This is a test email from OpenCTI. If you received it, your SMTP configuration is working correctly.</p>',
  });
  return true;
};
