import * as R from 'ramda';
import passport from 'passport/lib';
import GitHub from 'github-api';
import jwtDecode from 'jwt-decode';
import FacebookStrategy from 'passport-facebook';
import GithubStrategy from 'passport-github';
import LocalStrategy from 'passport-local';
import LdapStrategy from 'passport-ldapauth';
import Auth0Strategy from 'passport-auth0';
import { Strategy as SamlStrategy } from 'passport-saml';
import { custom as OpenIDCustom, Issuer as OpenIDIssuer, Strategy as OpenIDStrategy } from 'openid-client';
import { OAuth2Strategy as GoogleStrategy } from 'passport-google-oauth';
import validator from 'validator';
import { initAdmin, login, loginFromProvider } from '../domain/user';
import conf, { logApp } from './conf';
import { ConfigurationError } from './errors';
import { isNotEmptyField } from '../database/utils';

export const empty = R.anyPass([R.isNil, R.isEmpty]);

// Admin user initialization
export const initializeAdminUser = async (context) => {
  const DEFAULT_CONF_VALUE = 'ChangeMe';
  const adminEmail = conf.get('app:admin:email');
  const adminPassword = conf.get('app:admin:password');
  const adminToken = conf.get('app:admin:token');
  if (
    empty(adminEmail)
    || empty(adminPassword)
    || empty(adminToken)
    || adminPassword === DEFAULT_CONF_VALUE
    || adminToken === DEFAULT_CONF_VALUE
  ) {
    throw ConfigurationError('You need to configure the environment vars');
  } else {
    // Check fields
    if (!validator.isEmail(adminEmail)) {
      throw ConfigurationError('Email must be a valid email address');
    }
    if (!validator.isUUID(adminToken)) {
      throw ConfigurationError('Token must be a valid UUID');
    }
    // Initialize the admin account
    // noinspection JSIgnoredPromiseFromCall
    await initAdmin(context, adminEmail, adminPassword, adminToken);
    logApp.info('[INIT] admin user initialized');
  }
};

// Map every configuration that required camelCase
// This is due to env variables that does not not support case
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
  group_search_base: 'groupSearchBase',
  group_search_filter: 'groupSearchFilter',
  group_search_attributes: 'groupSearchAttributes',
  // SAML
  saml_callback_url: 'callbackUrl',
  identifier_format: 'identifierFormat',
  entry_point: 'entryPoint',
  private_key: 'privateKey',
  signing_cert: 'signingCert',
  signature_algorithm: 'signatureAlgorithm',
  digest_algorithm: 'digestAlgorithm',
  want_assertions_signed: 'wantAssertionsSigned',
  authn_context: 'authnContext',
  disable_requested_authn_context: 'disableRequestedAuthnContext',
  force_authn: 'forceAuthn',
  disable_request_acs_url: 'disableRequestAcsUrl',
  // OpenID Client - everything is already in snake case
};
const configRemapping = (config) => {
  if (!config) return config;
  if (typeof config === 'object' && !Array.isArray(config)) {
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
const STRATEGY_LOCAL = 'LocalStrategy';
export const STRATEGY_CERT = 'ClientCertStrategy';
const STRATEGY_LDAP = 'LdapStrategy';
const STRATEGY_OPENID = 'OpenIDConnectStrategy';
const STRATEGY_FACEBOOK = 'FacebookStrategy';
const STRATEGY_SAML = 'SamlStrategy';
const STRATEGY_GOOGLE = 'GoogleStrategy';
const STRATEGY_GITHUB = 'GithubStrategy';
const STRATEGY_AUTH0 = 'Auth0Strategy';
const AUTH_SSO = 'SSO';
const AUTH_FORM = 'FORM';

const providers = [];
const providerLoginHandler = (userInfo, done, opts = {}) => {
  loginFromProvider(userInfo, opts)
    .then((user) => {
      done(null, user);
    })
    .catch((err) => {
      done(err);
    });
};
const genConfigMapper = (elements) => {
  return R.mergeAll(
    elements.map((r) => {
      const data = r.split(':');
      if (data.length !== 2) return {};
      const [remote, octi] = data;
      return { [remote]: octi };
    })
  );
};

const confProviders = conf.get('providers');
const providerKeys = Object.keys(confProviders);
for (let i = 0; i < providerKeys.length; i += 1) {
  const providerIdent = providerKeys[i];
  const provider = confProviders[providerIdent];
  const { identifier, strategy, config } = provider;
  let mappedConfig = configRemapping(config);
  if (config === undefined || !config.disabled) {
    const providerName = config?.label || providerIdent;
    // FORM Strategies
    if (strategy === STRATEGY_LOCAL) {
      const localStrategy = new LocalStrategy({}, (username, password, done) => {
        logApp.debug('[LOCAL] Successfully logged', { username });
        return login(username, password)
          .then((info) => {
            return done(null, info);
          })
          .catch((err) => {
            done(err);
          });
      });
      passport.use('local', localStrategy);
      providers.push({ name: providerName, type: AUTH_FORM, strategy, provider: 'local' });
    }
    if (strategy === STRATEGY_LDAP) {
      const providerRef = identifier || 'ldapauth';
      const allowSelfSigned = mappedConfig.allow_self_signed || mappedConfig.allow_self_signed === 'true';
      mappedConfig = R.assoc('tlsOptions', { rejectUnauthorized: !allowSelfSigned }, mappedConfig);
      const ldapOptions = { server: mappedConfig };
      const ldapStrategy = new LdapStrategy(ldapOptions, (user, done) => {
        logApp.debug('[LDAP] Successfully logged', { user });
        const userMail = mappedConfig.mail_attribute ? user[mappedConfig.mail_attribute] : user.mail;
        const userName = mappedConfig.account_attribute ? user[mappedConfig.account_attribute] : user.givenName;
        const firstname = user[mappedConfig.firstname_attribute] || '';
        const lastname = user[mappedConfig.lastname_attribute] || '';
        // region roles mapping
        const isRoleBaseAccess = isNotEmptyField(mappedConfig.roles_management);
        const computeRolesMapping = () => {
          const rolesGroupsMapping = mappedConfig.roles_management?.groups_mapping || [];
          const userRolesGroups = (user._groups || [])
            .map((g) => g[mappedConfig.roles_management?.group_attribute || 'cn'])
            .filter((g) => isNotEmptyField(g));
          const rolesMapper = genConfigMapper(rolesGroupsMapping);
          return userRolesGroups.map((a) => rolesMapper[a]).filter((r) => isNotEmptyField(r));
        };
        const rolesToAssociate = computeRolesMapping();
        // endregion
        // region groups mapping
        const computeGroupsMapping = () => {
          const groupsMapping = mappedConfig.groups_management?.groups_mapping || [];
          const userGroups = (user._groups || [])
            .map((g) => g[mappedConfig.groups_management?.group_attribute || 'cn'])
            .filter((g) => isNotEmptyField(g));
          const groupsMapper = genConfigMapper(groupsMapping);
          return userGroups.map((a) => groupsMapper[a]).filter((r) => isNotEmptyField(r));
        };
        const groupsToAssociate = computeGroupsMapping();
        // endregion
        // region organizations mapping
        const isOrgaMapping = isNotEmptyField(mappedConfig.organizations_default) || isNotEmptyField(mappedConfig.organizations_management);
        const computeOrganizationsMapping = () => {
          const orgaDefault = mappedConfig.organizations_default ?? [];
          const orgasMapping = mappedConfig.organizations_management?.organizations_mapping || [];
          const orgaPath = mappedConfig.organizations_management?.organizations_path || ['organizations'];
          const availableOrgas = R.flatten(orgaPath.map((path) => R.path(path.split('.'), user) || []));
          const orgasMapper = genConfigMapper(orgasMapping);
          return [...orgaDefault, ...availableOrgas.map((a) => orgasMapper[a]).filter((r) => isNotEmptyField(r))];
        };
        const organizationsToAssociate = isOrgaMapping ? computeOrganizationsMapping() : [];
        // endregion
        if (!userMail) {
          logApp.warn('[LDAP] Configuration error, cant map mail and username', { user, userMail, userName });
          done({ message: 'Configuration error, ask your administrator' });
        } else if (!isRoleBaseAccess || rolesToAssociate.length > 0) {
          logApp.debug(`[LDAP] Connecting/creating account with ${userMail} [name=${userName}]`);
          const userInfo = { email: userMail, name: userName, firstname, lastname };
          const opts = { providerRoles: rolesToAssociate, providerGroups: groupsToAssociate, providerOrganizations: organizationsToAssociate };
          providerLoginHandler(userInfo, done, opts);
        } else {
          done({ message: 'Restricted access, ask your administrator' });
        }
      });
      passport.use(providerRef, ldapStrategy);
      providers.push({ name: providerName, type: AUTH_FORM, strategy, provider: providerRef });
    }
    // SSO Strategies
    if (strategy === STRATEGY_SAML) {
      const providerRef = identifier || 'saml';
      const samlOptions = { ...mappedConfig };
      const samlStrategy = new SamlStrategy(samlOptions, (profile, done) => {
        logApp.debug('[SAML] Successfully logged', { profile });
        const roleAttributes = mappedConfig.roles_management?.role_attributes || ['Role'];
        const userName = profile[mappedConfig.account_attribute] || '';
        const firstname = profile[mappedConfig.firstname_attribute] || '';
        const lastname = profile[mappedConfig.lastname_attribute] || '';
        // region roles mapping
        const isRoleBaseAccess = isNotEmptyField(mappedConfig.roles_management);
        const computeRolesMapping = () => {
          const attrRoles = roleAttributes.map((a) => (Array.isArray(profile[a]) ? profile[a] : [profile[a]]));
          const samlRoles = R.flatten(attrRoles).filter((v) => isNotEmptyField(v));
          const rolesMapping = mappedConfig.roles_management?.roles_mapping || [];
          const rolesMapper = genConfigMapper(rolesMapping);
          return samlRoles.map((a) => rolesMapper[a]).filter((r) => isNotEmptyField(r));
        };
        const rolesToAssociate = computeRolesMapping();
        // endregion
        // region organizations mapping
        const isOrgaMapping = isNotEmptyField(mappedConfig.organizations_default) || isNotEmptyField(mappedConfig.organizations_management);
        const computeOrganizationsMapping = () => {
          const orgaDefault = mappedConfig.organizations_default ?? [];
          const orgasMapping = mappedConfig.organizations_management?.organizations_mapping || [];
          const orgaPath = mappedConfig.organizations_management?.organizations_path || ['organizations'];
          const availableOrgas = R.flatten(orgaPath.map((path) => R.path(path.split('.'), profile) || []));
          const orgasMapper = genConfigMapper(orgasMapping);
          return [...orgaDefault, ...availableOrgas.map((a) => orgasMapper[a]).filter((r) => isNotEmptyField(r))];
        };
        const organizationsToAssociate = isOrgaMapping ? computeOrganizationsMapping() : [];
        // endregion
        if (!isRoleBaseAccess || rolesToAssociate.length > 0) {
          const { nameID: email } = profile;
          const opts = { providerRoles: rolesToAssociate, providerOrganizations: organizationsToAssociate };
          providerLoginHandler({ email, name: userName, firstname, lastname }, done, opts);
        } else {
          done({ message: 'Restricted access, ask your administrator' });
        }
      });
      passport.use(providerRef, samlStrategy);
      providers.push({ name: providerName, type: AUTH_SSO, strategy, provider: providerRef });
    }
    if (strategy === STRATEGY_OPENID) {
      const providerRef = identifier || 'oic';
      // Here we use directly the config and not the mapped one.
      // All config of openid lib use snake case.
      OpenIDCustom.setHttpOptionsDefaults({ timeout: 0 });
      OpenIDIssuer.discover(config.issuer).then((issuer) => {
        const { Client } = issuer;
        const client = new Client(config);
        // region scopes generation
        const defaultScopes = mappedConfig.default_scopes ?? ['openid', 'email', 'profile'];
        const openIdScopes = [...defaultScopes];
        const rolesScope = mappedConfig.roles_management?.roles_scope;
        if (rolesScope) {
          openIdScopes.push(rolesScope);
        }
        const groupsScope = mappedConfig.groups_management?.groups_scope;
        if (groupsScope) {
          openIdScopes.push(groupsScope);
        }
        // endregion
        const openIdScope = R.uniq(openIdScopes).join(' ');
        const options = { client, passReqToCallback: true, params: { scope: openIdScope } };
        const openIDStrategy = new OpenIDStrategy(options, (req, tokenset, userinfo, done) => {
          logApp.debug('[OPENID] Successfully logged', { userinfo });
          // region roles mapping
          const isRoleBaseAccess = isNotEmptyField(mappedConfig.roles_management);
          const computeRolesMapping = () => {
            const token = mappedConfig.roles_management?.token_reference || 'access_token';
            const rolesPath = mappedConfig.roles_management?.roles_path || ['roles'];
            const rolesMapping = mappedConfig.roles_management?.roles_mapping || [];
            const decodedUser = jwtDecode(tokenset[token]);
            logApp.debug(`[OPENID] Roles mapping on decoded ${token}`, { decoded: decodedUser });
            const availableRoles = R.flatten(rolesPath.map((path) => R.path(path.split('.'), decodedUser) || []));
            const rolesMapper = genConfigMapper(rolesMapping);
            return availableRoles.map((a) => rolesMapper[a]).filter((r) => isNotEmptyField(r));
          };
          const rolesToAssociate = isRoleBaseAccess ? computeRolesMapping() : [];
          // endregion
          // region groups mapping
          const isGroupMapping = isNotEmptyField(mappedConfig.groups_management);
          const computeGroupsMapping = () => {
            const token = mappedConfig.groups_management?.token_reference || 'access_token';
            const groupsPath = mappedConfig.groups_management?.groups_path || ['groups'];
            const groupsMapping = mappedConfig.groups_management?.groups_mapping || [];
            const decodedUser = jwtDecode(tokenset[token]);
            logApp.debug(`[OPENID] Groups mapping on decoded ${token}`, { decoded: decodedUser });
            const availableGroups = R.flatten(groupsPath.map((path) => R.path(path.split('.'), decodedUser) || []));
            const groupsMapper = genConfigMapper(groupsMapping);
            return availableGroups.map((a) => groupsMapper[a]).filter((r) => isNotEmptyField(r));
          };
          const groupsToAssociate = isGroupMapping ? computeGroupsMapping() : [];
          // endregion
          // region organizations mapping
          const isOrgaMapping = isNotEmptyField(mappedConfig.organizations_default) || isNotEmptyField(mappedConfig.organizations_management);
          const computeOrganizationsMapping = () => {
            const orgaDefault = mappedConfig.organizations_default ?? [];
            const orgasMapping = mappedConfig.organizations_management?.organizations_mapping || [];
            const token = mappedConfig.organizations_management?.token_reference || 'access_token';
            const orgaPath = mappedConfig.organizations_management?.organizations_path || ['organizations'];
            const decodedUser = jwtDecode(tokenset[token]);
            const availableOrgas = R.flatten(orgaPath.map((path) => R.path(path.split('.'), decodedUser) || []));
            const orgasMapper = genConfigMapper(orgasMapping);
            return [...orgaDefault, ...availableOrgas.map((a) => orgasMapper[a]).filter((r) => isNotEmptyField(r))];
          };
          const organizationsToAssociate = isOrgaMapping ? computeOrganizationsMapping() : [];
          // endregion
          if (!isRoleBaseAccess || rolesToAssociate.length > 0) {
            const nameAttribute = mappedConfig.name_attribute ?? 'name';
            const emailAttribute = mappedConfig.email_attribute ?? 'email';
            const firstnameAttribute = mappedConfig.firstname_attribute ?? 'given_name';
            const lastnameAttribute = mappedConfig.lastname_attribute ?? 'family_name';
            const name = userinfo[nameAttribute];
            const email = userinfo[emailAttribute];
            const firstname = userinfo[firstnameAttribute];
            const lastname = userinfo[lastnameAttribute];
            const opts = {
              providerRoles: rolesToAssociate,
              providerGroups: groupsToAssociate,
              providerOrganizations: organizationsToAssociate
            };
            providerLoginHandler({ email, name, firstname, lastname }, done, opts);
          } else {
            done({ message: 'Restricted access, ask your administrator' });
          }
        });
        passport.use(providerRef, openIDStrategy);
        providers.push({ name: providerName, type: AUTH_SSO, strategy, provider: providerRef });
      }).catch((err) => {
        logApp.error(`[OPENID] ${providerRef} fail to initialize, provider will be disable`, { error: err });
      });
    }
    if (strategy === STRATEGY_FACEBOOK) {
      const providerRef = identifier || 'facebook';
      const specificConfig = { profileFields: ['id', 'emails', 'name'], scope: 'email' };
      const facebookOptions = { passReqToCallback: true, ...mappedConfig, ...specificConfig };
      const facebookStrategy = new FacebookStrategy(
        facebookOptions,
        (req, accessToken, refreshToken, profile, done) => {
          const data = profile._json;
          logApp.debug('[FACEBOOK] Successfully logged', { profile: data });
          const { email } = data;
          providerLoginHandler({ email, name: data.first_name }, done);
        }
      );
      passport.use(providerRef, facebookStrategy);
      providers.push({ name: providerName, type: AUTH_SSO, strategy, provider: providerRef });
    }
    if (strategy === STRATEGY_GOOGLE) {
      const providerRef = identifier || 'google';
      const domains = mappedConfig.domains || [];
      const specificConfig = { scope: ['email', 'profile'] };
      const googleOptions = { passReqToCallback: true, ...mappedConfig, ...specificConfig };
      const googleStrategy = new GoogleStrategy(googleOptions, (req, token, tokenSecret, profile, done) => {
        logApp.debug('[GOOGLE] Successfully logged', { profile });
        const email = R.head(profile.emails).value;
        const name = profile.displayName;
        let authorized = true;
        if (domains.length > 0) {
          const [, domain] = email.split('@');
          authorized = domains.includes(domain);
        }
        if (authorized) {
          providerLoginHandler({ email, name }, done);
        } else {
          done({ message: 'Restricted access, ask your administrator' });
        }
      });
      passport.use(providerRef, googleStrategy);
      providers.push({ name: providerName, type: AUTH_SSO, strategy, provider: providerRef });
    }
    if (strategy === STRATEGY_GITHUB) {
      const providerRef = identifier || 'github';
      const organizations = mappedConfig.organizations || [];
      const scope = organizations.length > 0 ? 'user:email,read:org' : 'user:email';
      const githubOptions = { passReqToCallback: true, ...mappedConfig, scope };
      const githubStrategy = new GithubStrategy(githubOptions, async (req, token, tokenSecret, profile, done) => {
        logApp.debug('[GITHUB] Successfully logged', { profile });
        let authorized = true;
        if (organizations.length > 0) {
          const github = new GitHub({ token });
          const me = github.getUser();
          const { data: orgs } = await me.listOrgs();
          const githubOrgs = orgs.map((o) => o.login);
          authorized = organizations.some((o) => githubOrgs.includes(o));
        }
        if (authorized) {
          const { displayName } = profile;
          if (!profile.emails || profile.emails.length === 0) {
            done({ message: 'You need a public email in your github account' });
          } else {
            const email = R.head(profile.emails).value;
            providerLoginHandler({ email, name: displayName }, done);
          }
        } else {
          done({ message: 'Restricted access, ask your administrator' });
        }
      });
      passport.use(providerRef, githubStrategy);
      providers.push({ name: providerName, type: AUTH_SSO, strategy, provider: providerRef });
    }
    if (strategy === STRATEGY_AUTH0) {
      const providerRef = identifier || 'auth0';
      const auth0Options = { passReqToCallback: true, ...mappedConfig };
      const auth0Strategy = new Auth0Strategy(
        auth0Options,
        (req, accessToken, refreshToken, extraParams, profile, done) => {
          logApp.debug('[AUTH0] Successfully logged', { profile });
          const email = R.head(profile.emails).value;
          const name = profile.displayName;
          providerLoginHandler({ email, name }, done);
        }
      );
      passport.use(providerRef, auth0Strategy);
      providers.push({ name: providerName, type: AUTH_SSO, strategy, provider: providerRef });
    }
    // CERT Strategies
    if (strategy === STRATEGY_CERT) {
      const providerRef = identifier || 'cert';
      // This strategy is directly handled by express
      providers.push({ name: providerName, type: AUTH_SSO, strategy, provider: providerRef });
    }
  }
}

export const PROVIDERS = providers;
export const isStrategyActivated = (strategy) => providers.map((p) => p.strategy).includes(strategy);

export default passport;
