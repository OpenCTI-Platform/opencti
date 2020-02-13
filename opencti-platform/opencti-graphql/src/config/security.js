import passport from 'passport/lib';
import FacebookStrategy from 'passport-facebook';
import GithubStrategy from 'passport-github';
import LocalStrategy from 'passport-local';
import LdapStrategy from 'passport-ldapauth';
import Auth0Strategy from 'passport-auth0';
import { Strategy as OpenIDStrategy, Issuer as OpenIDIssuer } from 'openid-client';
import { OAuth2Strategy as GoogleStrategy } from 'passport-google-oauth';
import { head, anyPass, isNil, isEmpty } from 'ramda';
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

// Providers definition
const AUTH_SSO = 'SSO';
const AUTH_FORM = 'FORM';

const providers = [];
const confProviders = conf.get('providers');
const providerKeys = Object.keys(confProviders);
for (let i = 0; i < providerKeys.length; i += 1) {
  const provider = confProviders[providerKeys[i]];
  const { strategy, config } = provider;
  if (strategy === 'LocalStrategy') {
    const localStrategy = new LocalStrategy((username, password, done) => {
      return login(username, password)
        .then(token => {
          return done(null, token);
        })
        .catch(() => done(null, false));
    });
    passport.use('local', localStrategy);
    providers.push({ name: providerKeys[i], type: AUTH_FORM, provider: 'local' });
  }
  if (strategy === 'LdapStrategy') {
    const ldapOptions = {
      server: {
        url: conf.get('providers:ldap:config:url'),
        bindDN: conf.get('providers:ldap:config:bind_dn'),
        bindCredentials: conf.get('providers:ldap:config:bind_credentials'),
        searchBase: conf.get('providers:ldap:config:search_base'),
        searchFilter: conf.get('providers:ldap:config:search_filter')
      }
    };
    const ldapStrategy = new LdapStrategy(ldapOptions, (user, done) => {
      const userMail = config.email_attribute ? user[config.email_attribute] : user.mail;
      const userName = config.account_attribute ? user[config.account_attribute] : user.givenName;
      loginFromProvider(userMail, userName)
        .then(token => {
          done(null, token);
        })
        .catch(err => {
          done(err);
        });
    });
    passport.use('ldapauth', ldapStrategy);
    providers.push({ name: providerKeys[i], type: AUTH_FORM, provider: 'ldapauth' });
  }
  if (strategy === 'OpenIDConnectStrategy') {
    OpenIDIssuer.discover(config.issuer).then(issuer => {
      const openIdOptions = {
        clientID: conf.get('providers:openid:config:client_id'),
        clientSecret: conf.get('providers:openid:config:client_secret'),
        callbackURL: conf.get('providers:openid:config:callback_url')
      };
      const { Client } = issuer;
      const client = new Client(openIdOptions);
      const options = { client, params: { scope: 'openid email profile' } };
      const openIDStrategy = new OpenIDStrategy(options, (tokenset, userinfo, done) => {
        const { email, name } = userinfo;
        loginFromProvider(email, name)
          .then(token => {
            done(null, token);
          })
          .catch(err => {
            done(err);
          });
      });
      passport.use('oic', openIDStrategy);
      providers.push({ name: providerKeys[i], type: AUTH_SSO, provider: 'oic' });
    });
  }
  if (strategy === 'FacebookStrategy') {
    const facebookOptions = {
      clientID: conf.get('providers:facebook:config:client_id'),
      clientSecret: conf.get('providers:facebook:config:client_secret'),
      callbackURL: conf.get('providers:facebook:config:callback_url'),
      profileFields: ['id', 'emails', 'name'],
      scope: 'email'
    };
    const facebookStrategy = new FacebookStrategy(facebookOptions, (accessToken, refreshToken, profile, done) => {
      // eslint-disable-next-line no-underscore-dangle
      const data = profile._json;
      const name = `${data.last_name} ${data.first_name}`;
      const { email } = data;
      loginFromProvider(email, name)
        .then(token => {
          done(null, token);
        })
        .catch(err => {
          done(err);
        });
    });
    passport.use('facebook', facebookStrategy);
    providers.push({ name: providerKeys[i], type: AUTH_SSO, provider: 'facebook' });
  }
  if (strategy === 'GoogleStrategy') {
    const googleOptions = {
      clientID: conf.get('providers:google:config:client_id'),
      clientSecret: conf.get('providers:google:config:client_secret'),
      callbackURL: conf.get('providers:google:config:callback_url'),
      scope: 'email'
    };
    const googleStrategy = new GoogleStrategy(googleOptions, (token, tokenSecret, profile, done) => {
      const email = head(profile.emails).value;
      const name = profile.displayName || email;
      // let picture = head(profile.photos).value;
      loginFromProvider(email, name)
        .then(loggedToken => {
          done(null, loggedToken);
        })
        .catch(err => {
          done(err);
        });
    });
    passport.use(googleStrategy);
    providers.push({ name: providerKeys[i], type: AUTH_SSO, provider: 'google' });
  }
  if (strategy === 'GithubStrategy') {
    const githubOptions = {
      clientID: conf.get('providers:github:config:client_id'),
      clientSecret: conf.get('providers:github:config:client_secret'),
      callbackURL: conf.get('providers:github:config:callback_url'),
      scope: 'user:email'
    };
    const githubStrategy = new GithubStrategy(githubOptions, (token, tokenSecret, profile, done) => {
      const { displayName } = profile;
      const email = head(profile.emails).value;
      // let picture = profile.avatar_url;
      loginFromProvider(email, displayName)
        .then(loggedToken => {
          done(null, loggedToken);
        })
        .catch(err => {
          done(err);
        });
    });
    passport.use('github', githubStrategy);
    providers.push({ name: providerKeys[i], type: AUTH_SSO, provider: 'github' });
  }
  if (strategy === 'Auth0Strategy') {
    const auth0Options = {
      clientID: conf.get('providers:auth0:config:client_id'),
      clientSecret: conf.get('providers:auth0:config:client_secret'),
      callbackURL: conf.get('providers:auth0:config:callback_url'),
      scope: 'email'
    };
    const auth0Strategy = new Auth0Strategy(auth0Options, (accessToken, refreshToken, extraParams, profile, done) => {
      const userName = profile.displayName;
      const email = head(profile.emails).value;
      loginFromProvider(email, userName)
        .then(token => {
          done(null, token);
        })
        .catch(err => {
          done(err);
        });
    });
    passport.use('auth0', auth0Strategy);
    providers.push({ name: providerKeys[i], type: AUTH_SSO, provider: 'auth0' });
  }
}

export const PROVIDERS = providers;
export default passport;
