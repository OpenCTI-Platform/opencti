import passport from 'passport/lib';
import FacebookStrategy from 'passport-facebook';
import GithubStrategy from 'passport-github';
import LocalStrategy from 'passport-local';
import LdapStrategy from 'passport-ldapauth';
import Auth0Strategy from 'passport-auth0';
import { Strategy as OpenIDStrategy, Issuer as OpenIDIssuer } from 'openid-client';
import { OAuth2Strategy as GoogleStrategy } from 'passport-google-oauth';
import { assoc, head, anyPass, isNil, isEmpty } from 'ramda';
import validator from 'validator';
import { initAdmin, login, loginFromProvider } from '../domain/user';
import conf, { logger } from './conf';

// Admin user initialization
export const initializeAdminUser = async () => {
  const empty = anyPass([isNil, isEmpty]);
  const DEFAULT_CONF_VALUE = 'ChangeMe';
  const adminEmail = conf.get('app:admin:email');
  const adminPassword = conf.get('app:admin:password');
  const adminToken = conf.get('app:admin:token');
  if (
    empty(adminEmail) ||
    empty(adminPassword) ||
    empty(adminToken) ||
    adminPassword === DEFAULT_CONF_VALUE ||
    adminToken === DEFAULT_CONF_VALUE
  ) {
    throw new Error('[ADMIN_SETUP] You need to configure the environment vars');
  } else {
    // Check fields
    if (!validator.isEmail(adminEmail)) throw new Error('[ADMIN_SETUP] > email must be a valid email address');
    if (!validator.isUUID(adminToken)) throw new Error('[ADMIN_SETUP] > Token must be a valid UUID');
    // Initialize the admin account
    // noinspection JSIgnoredPromiseFromCall
    await initAdmin(adminEmail, adminPassword, adminToken);
    logger.info(`[ADMIN_SETUP] admin user initialized`);
  }
};

// Map every configuration that required camelCase
// This is due to env variables that doesnt not support case
const configurationMapping = {
  // Generic for google / facebook / github and auth0
  client_id: 'clientID',
  client_secret: 'clientSecret',
  callback_url: 'callbackURL',
  // LDAP
  bind_dn: 'bindDN',
  bind_credentials: 'bindCredentials',
  search_base: 'searchBase',
  search_filter: 'searchFilter',
  search_attributes: 'searchAttributes',
  username_field: 'usernameField',
  password_field: 'passwordField',
  credentials_lookup: 'credentialsLookup',
  // OpenID Client - everything is already in snake case
};
const configRemapping = (config) => {
  if (!config) return config;
  if (typeof config === 'object') {
    const n = {};
    Object.keys(config).forEach((key) => {
      const remapKey = configurationMapping[key] ? configurationMapping[key] : key;
      n[remapKey] = configRemapping(config[key]);
    });
    return n;
  }
  return config;
};

// Providers definition
const AUTH_SSO = 'SSO';
const AUTH_FORM = 'FORM';

const providers = [];
const confProviders = conf.get('providers');
const providerKeys = Object.keys(confProviders);
for (let i = 0; i < providerKeys.length; i += 1) {
  const providerIdent = providerKeys[i];
  const provider = confProviders[providerIdent];
  const { strategy, config } = provider;
  let mappedConfig = configRemapping(config);
  if (strategy === 'LocalStrategy') {
    const localStrategy = new LocalStrategy((username, password, done) => {
      return login(username, password)
        .then((token) => {
          return done(null, token);
        })
        .catch(() => done(null, false));
    });
    passport.use('local', localStrategy);
    providers.push({ name: providerIdent, type: AUTH_FORM, provider: 'local' });
  }
  if (strategy === 'LdapStrategy') {
    // eslint-disable-next-line
    const allowSelfSigned = mappedConfig.allow_self_signed || mappedConfig.allow_self_signed === 'true';
    mappedConfig = assoc('tlsOptions', { rejectUnauthorized: !allowSelfSigned }, mappedConfig);
    const ldapOptions = { server: mappedConfig };
    const ldapStrategy = new LdapStrategy(ldapOptions, (user, done) => {
      const userMail = mappedConfig.mail_attribute ? user[mappedConfig.mail_attribute] : user.mail;
      const userName = mappedConfig.account_attribute ? user[mappedConfig.account_attribute] : user.givenName;
      logger.debug(`[LDAP_AUTH] Successfully logged with ${userMail} and ${userName}`);
      loginFromProvider(userMail, userName || userMail)
        .then((token) => {
          done(null, token);
        })
        .catch((err) => {
          done(err);
        });
    });
    passport.use('ldapauth', ldapStrategy);
    providers.push({ name: providerIdent, type: AUTH_FORM, provider: 'ldapauth' });
  }
  if (strategy === 'OpenIDConnectStrategy') {
    // Here we use directly the config and not the mapped one.
    // All config of openid lib use snake case.
    OpenIDIssuer.discover(config.issuer).then((issuer) => {
      const { Client } = issuer;
      const client = new Client(config);
      const options = { client, params: { scope: 'openid email profile' } };
      const openIDStrategy = new OpenIDStrategy(options, (tokenset, userinfo, done) => {
        const { email, name } = userinfo;
        loginFromProvider(email, name || email)
          .then((token) => {
            done(null, token);
          })
          .catch((err) => {
            done(err);
          });
      });
      passport.use('oic', openIDStrategy);
      providers.push({ name: providerIdent, type: AUTH_SSO, provider: 'oic' });
    });
  }
  if (strategy === 'FacebookStrategy') {
    const specificConfig = { profileFields: ['id', 'emails', 'name'], scope: 'email' };
    const facebookOptions = { ...mappedConfig, ...specificConfig };
    const facebookStrategy = new FacebookStrategy(facebookOptions, (accessToken, refreshToken, profile, done) => {
      // eslint-disable-next-line no-underscore-dangle
      const data = profile._json;
      const name = `${data.last_name} ${data.first_name}`;
      const { email } = data;
      loginFromProvider(email, data.first_name && data.last_name ? name : email)
        .then((token) => {
          done(null, token);
        })
        .catch((err) => {
          done(err);
        });
    });
    passport.use('facebook', facebookStrategy);
    providers.push({ name: providerIdent, type: AUTH_SSO, provider: 'facebook' });
  }
  if (strategy === 'GoogleStrategy') {
    const specificConfig = { scope: 'email' };
    const googleOptions = { ...mappedConfig, ...specificConfig };
    const googleStrategy = new GoogleStrategy(googleOptions, (token, tokenSecret, profile, done) => {
      const email = head(profile.emails).value;
      const name = profile.displayNamel;
      // let picture = head(profile.photos).value;
      loginFromProvider(email, name || email)
        .then((loggedToken) => {
          done(null, loggedToken);
        })
        .catch((err) => {
          done(err);
        });
    });
    passport.use(googleStrategy);
    providers.push({ name: providerIdent, type: AUTH_SSO, provider: 'google' });
  }
  if (strategy === 'GithubStrategy') {
    const specificConfig = { scope: 'user:email' };
    const githubOptions = { ...mappedConfig, ...specificConfig };
    const githubStrategy = new GithubStrategy(githubOptions, (token, tokenSecret, profile, done) => {
      const { displayName } = profile;
      const email = head(profile.emails).value;
      // let picture = profile.avatar_url;
      loginFromProvider(email, displayName || email)
        .then((loggedToken) => {
          done(null, loggedToken);
        })
        .catch((err) => {
          done(err);
        });
    });
    passport.use('github', githubStrategy);
    providers.push({ name: providerIdent, type: AUTH_SSO, provider: 'github' });
  }
  if (strategy === 'Auth0Strategy') {
    const auth0Strategy = new Auth0Strategy(mappedConfig, (accessToken, refreshToken, extraParams, profile, done) => {
      const userName = profile.displayName;
      const email = head(profile.emails).value;
      loginFromProvider(email, userName || email)
        .then((token) => {
          done(null, token);
        })
        .catch((err) => {
          done(err);
        });
    });
    passport.use('auth0', auth0Strategy);
    providers.push({ name: providerIdent, type: AUTH_SSO, provider: 'auth0' });
  }
}

export const PROVIDERS = providers;
export default passport;
