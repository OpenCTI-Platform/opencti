import passport from 'passport/lib';
import FacebookStrategy from 'passport-facebook';
import GithubStrategy from 'passport-github';
import LocalStrategy from 'passport-local';
import LdapStrategy from 'passport-ldapauth';
import { OAuth2Strategy as GoogleStrategy } from 'passport-google-oauth';
import { join, head, anyPass, isNil, isEmpty } from 'ramda';
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
const providers = [];
const formProviders = [];
const confProviders = conf.get('providers');
const providerKeys = Object.keys(confProviders);
for (let i = 0; i < providerKeys.length; i += 1) {
  const { active, strategy, config } = confProviders[providerKeys[i]];
  if (active === true) {
    if (strategy === 'LocalStrategy') {
      const localStrategy = new LocalStrategy((username, password, done) => {
        return login(username, password)
          .then(token => {
            return done(null, token);
          })
          .catch(() => done(null, false));
      });
      passport.use(localStrategy);
      if (!providers.includes('local')) providers.push('local');
      formProviders.push('local');
    }
    if (strategy === 'LdapStrategy') {
      const specificConfig = { searchFilter: '(mail={{username}})' };
      const ldapConfig = { ...config, ...specificConfig };
      const ldapOptions = { server: ldapConfig };
      const ldapStrategy = new LdapStrategy(ldapOptions, (user, done) => {
        loginFromProvider(user.mail, user.givenName)
          .then(token => {
            done(null, token);
          })
          .catch(err => {
            done(err);
          });
      });
      passport.use(ldapStrategy);
      if (!providers.includes('local')) providers.push('local');
      formProviders.push('ldapauth');
    }
    if (strategy === 'FacebookStrategy') {
      const specificConfig = { profileFields: ['id', 'emails', 'name'], scope: 'email' };
      const facebookOptions = { ...config, ...specificConfig };
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
      passport.use(facebookStrategy);
      providers.push('facebook');
    }
    if (strategy === 'GoogleStrategy') {
      const specificConfig = { scope: 'email' };
      const googleOptions = { ...config, ...specificConfig };
      const googleStrategy = new GoogleStrategy(googleOptions, (token, tokenSecret, profile, done) => {
        const name = profile.displayName;
        const email = head(profile.emails).value;
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
      providers.push('google');
    }
    if (strategy === 'GithubStrategy') {
      const specificConfig = { scope: 'user:email' };
      const githubOptions = { ...config, ...specificConfig };
      const githubStrategy = new GithubStrategy(githubOptions, (token, tokenSecret, profile, done) => {
        const { name } = profile;
        const email = head(profile.emails).value;
        // let picture = profile.avatar_url;
        loginFromProvider(email, name)
          .then(loggedToken => {
            done(null, loggedToken);
          })
          .catch(err => {
            done(err);
          });
      });
      passport.use(githubStrategy);
      providers.push('github');
    }
  }
}

export const FORM_PROVIDERS = formProviders;
export const ACCESS_PROVIDERS = join(',', providers);
export default passport;
