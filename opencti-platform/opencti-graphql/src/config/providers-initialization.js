import * as R from 'ramda';
import passport from 'passport/lib';
import GitHub from 'github-api';
import { jwtDecode } from 'jwt-decode';
import FacebookStrategy from 'passport-facebook';
import GithubStrategy from 'passport-github';
import LocalStrategy from 'passport-local';
import LdapStrategy from 'passport-ldapauth';
import { Strategy as SamlStrategy } from '@node-saml/passport-saml';
import { custom as OpenIDCustom, Issuer as OpenIDIssuer, Strategy as OpenIDStrategy } from 'openid-client';
import { OAuth2Strategy as GoogleStrategy } from 'passport-google-oauth';
import validator from 'validator';
import { findById, HEADERS_AUTHENTICATORS, initAdmin, login, loginFromProvider, userDelete } from '../domain/user';
import conf, { getPlatformHttpProxyAgent, logApp } from './conf';
import { AuthenticationFailure, ConfigurationError } from './errors';
import { isEmptyField, isNotEmptyField } from '../database/utils';
import { DEFAULT_INVALID_CONF_VALUE, SYSTEM_USER } from '../utils/access';
import { enrichWithRemoteCredentials } from './credentials';
import { OPENCTI_ADMIN_UUID } from '../schema/general';
import { addUserLoginCount } from '../manager/telemetryManager';
import { AuthType, INTERNAL_SECURITY_PROVIDER, PROVIDERS, StrategyType } from './providers-configuration';

// Admin user initialization
export const initializeAdminUser = async (context) => {
  const isExternallyManaged = conf.get('app:admin:externally_managed') === true;
  if (isExternallyManaged) {
    logApp.info('[INIT] admin user initialization disabled by configuration');
    const existingAdmin = await findById(context, SYSTEM_USER, OPENCTI_ADMIN_UUID);
    if (existingAdmin) {
      await userDelete(context, SYSTEM_USER, OPENCTI_ADMIN_UUID);
    }
  } else {
    const adminEmail = conf.get('app:admin:email');
    const adminPassword = conf.get('app:admin:password');
    const adminToken = conf.get('app:admin:token');
    if (isEmptyField(adminEmail) || isEmptyField(adminPassword) || isEmptyField(adminToken)
        || adminPassword === DEFAULT_INVALID_CONF_VALUE || adminToken === DEFAULT_INVALID_CONF_VALUE
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
      await initAdmin(context, adminEmail, adminPassword, adminToken);
      logApp.info('[INIT] admin user initialized');
    }
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
  want_authn_response_signed: 'wantAuthnResponseSigned',
  authn_context: 'authnContext',
  disable_requested_authn_context: 'disableRequestedAuthnContext',
  force_authn: 'forceAuthn',
  disable_request_acs_url: 'disableRequestAcsUrl',
  skip_request_compression: 'skipRequestCompression',
  cert: 'idpCert',
  decryption_pvk: 'decryptionPvk',
  decryption_cert: 'decryptionCert',
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
  const mappedConfig = configRemapping(config);
  if (config === undefined || !config.disabled) {
    const providerName = config?.label || providerIdent;
    // FORM Strategies
    if (strategy === StrategyType.STRATEGY_LOCAL) {
      const localStrategy = new LocalStrategy({}, (username, password, done) => {
        return login(username, password)
          .then((info) => {
            logApp.info('[LOCAL] Successfully logged', { username });
            addUserLoginCount();
            return done(null, info);
          })
          .catch((err) => {
            done(err);
          });
      });
      passport.use('local', localStrategy);
      PROVIDERS.push({ name: providerName, type: AuthType.AUTH_FORM, strategy, provider: 'local' });
    }
    if (strategy === StrategyType.STRATEGY_LDAP) {
      const providerRef = identifier || 'ldapauth';
      const allowSelfSigned = mappedConfig.allow_self_signed || mappedConfig.allow_self_signed === 'true';
      // Force bindCredentials to be a String
      mappedConfig.bindCredentials = `${mappedConfig.bindCredentials}`;
      const tlsConfig = R.assoc('tlsOptions', { rejectUnauthorized: !allowSelfSigned }, mappedConfig);
      const ldapOptions = { server: tlsConfig };
      const ldapStrategy = new LdapStrategy(ldapOptions, (user, done) => {
        logApp.info('[LDAP] Successfully logged', { user });
        addUserLoginCount();
        const userMail = mappedConfig.mail_attribute ? user[mappedConfig.mail_attribute] : user.mail;
        const userName = mappedConfig.account_attribute ? user[mappedConfig.account_attribute] : user.givenName;
        const firstname = user[mappedConfig.firstname_attribute] || '';
        const lastname = user[mappedConfig.lastname_attribute] || '';
        const isGroupBaseAccess = (isNotEmptyField(mappedConfig.groups_management) && isNotEmptyField(mappedConfig.groups_management?.groups_mapping));
        // region groups mapping
        const computeGroupsMapping = () => {
          const groupsMapping = mappedConfig.groups_management?.groups_mapping || [];
          const userGroups = (user._groups || [])
            .map((g) => g[mappedConfig.groups_management?.group_attribute || 'cn'])
            .filter((g) => isNotEmptyField(g));
          const groupsMapper = genConfigMapper(groupsMapping);
          return userGroups.map((a) => groupsMapper[a]).filter((r) => isNotEmptyField(r));
        };
        const groupsToAssociate = R.uniq(computeGroupsMapping());
        // endregion
        // region organizations mapping
        const isOrgaMapping = isNotEmptyField(mappedConfig.organizations_default) || isNotEmptyField(mappedConfig.organizations_management);
        const computeOrganizationsMapping = () => {
          const orgaDefault = mappedConfig.organizations_default ?? [];
          const orgasMapping = mappedConfig.organizations_management?.organizations_mapping || [];
          const orgaPath = mappedConfig.organizations_management?.organizations_path || ['organizations'];

          const availableOrgas = R.flatten(
            orgaPath.map((path) => {
              const value = R.path(path.split('.'), user) || [];
              return Array.isArray(value) ? value : [value];
            })
          );
          const orgasMapper = genConfigMapper(orgasMapping);
          return [...orgaDefault, ...availableOrgas.map((a) => orgasMapper[a]).filter((r) => isNotEmptyField(r))];
        };
        const organizationsToAssociate = isOrgaMapping ? computeOrganizationsMapping() : [];
        // endregion
        if (!userMail) {
          logApp.warn('LDAP Configuration error, cant map mail and username', { user, userMail, userName });
          done({ message: 'Configuration error, ask your administrator' });
        } else if (!isGroupBaseAccess || groupsToAssociate.length > 0) {
          logApp.info(`[LDAP] Connecting/creating account with ${userMail} [name=${userName}]`);
          const userInfo = { email: userMail, name: userName, firstname, lastname };
          const opts = {
            providerGroups: groupsToAssociate,
            providerOrganizations: organizationsToAssociate,
            autoCreateGroup: mappedConfig.auto_create_group ?? false,
          };
          providerLoginHandler(userInfo, done, opts);
        } else {
          done({ message: 'Restricted access, ask your administrator' });
        }
      });
      passport.use(providerRef, ldapStrategy);
      PROVIDERS.push({ name: providerName, type: AuthType.AUTH_FORM, strategy, provider: providerRef });
    }
    // SSO Strategies
    if (strategy === StrategyType.STRATEGY_SAML) {
      const providerRef = identifier || 'saml';
      const samlOptions = { ...mappedConfig };
      const samlStrategy = new SamlStrategy(samlOptions, (profile, done) => {
        logApp.info('[SAML] Successfully logged', { profile });
        addUserLoginCount();
        const { nameID, nameIDFormat } = profile;
        const samlAttributes = profile.attributes ? profile.attributes : profile;
        const roleAttributes = mappedConfig.roles_management?.role_attributes || ['roles'];
        const groupAttributes = mappedConfig.groups_management?.group_attributes || ['groups'];
        const userEmail = samlAttributes[mappedConfig.mail_attribute] || nameID;
        if (mappedConfig.mail_attribute && !samlAttributes[mappedConfig.mail_attribute]) {
          logApp.info(`[SAML] custom mail_attribute "${mappedConfig.mail_attribute}" in configuration but the custom field is not present SAML server response.`);
        }
        const userName = samlAttributes[mappedConfig.account_attribute] || '';
        const firstname = samlAttributes[mappedConfig.firstname_attribute] || '';
        const lastname = samlAttributes[mappedConfig.lastname_attribute] || '';
        const isGroupBaseAccess = (isNotEmptyField(mappedConfig.groups_management) && isNotEmptyField(mappedConfig.groups_management?.groups_mapping));
        logApp.info('[SAML] Groups management configuration', { groupsManagement: mappedConfig.groups_management });
        // region roles mapping
        const computeRolesMapping = () => {
          const attrRoles = roleAttributes.map((a) => (Array.isArray(samlAttributes[a]) ? samlAttributes[a] : [samlAttributes[a]]));
          const samlRoles = R.flatten(attrRoles).filter((v) => isNotEmptyField(v));
          const rolesMapping = mappedConfig.roles_management?.roles_mapping || [];
          const rolesMapper = genConfigMapper(rolesMapping);
          return samlRoles.map((a) => rolesMapper[a]).filter((r) => isNotEmptyField(r));
        };
        // endregion
        // region groups mapping
        const computeGroupsMapping = () => {
          const attrGroups = groupAttributes.map((a) => (Array.isArray(samlAttributes[a]) ? samlAttributes[a] : [samlAttributes[a]]));
          const samlGroups = R.flatten(attrGroups).filter((v) => isNotEmptyField(v));
          const groupsMapping = mappedConfig.groups_management?.groups_mapping || [];
          const groupsMapper = genConfigMapper(groupsMapping);
          return samlGroups.map((a) => groupsMapper[a]).filter((r) => isNotEmptyField(r));
        };
        const groupsToAssociate = R.uniq(computeGroupsMapping().concat(computeRolesMapping()));
        // endregion
        // region organizations mapping
        const isOrgaMapping = isNotEmptyField(mappedConfig.organizations_default) || isNotEmptyField(mappedConfig.organizations_management);
        const computeOrganizationsMapping = () => {
          const orgaDefault = mappedConfig.organizations_default ?? [];
          const orgasMapping = mappedConfig.organizations_management?.organizations_mapping || [];
          const orgaPath = mappedConfig.organizations_management?.organizations_path || ['organizations'];
          const samlOrgas = R.path(orgaPath, profile) || [];
          const availableOrgas = Array.isArray(samlOrgas) ? samlOrgas : [samlOrgas];
          const orgasMapper = genConfigMapper(orgasMapping);
          return [...orgaDefault, ...availableOrgas.map((a) => orgasMapper[a]).filter((r) => isNotEmptyField(r))];
        };
        const organizationsToAssociate = isOrgaMapping ? computeOrganizationsMapping() : [];
        // endregion
        logApp.info('[SAML] Login handler', { isGroupBaseAccess, groupsToAssociate });
        if (!isGroupBaseAccess || groupsToAssociate.length > 0) {
          const opts = {
            providerGroups: groupsToAssociate,
            providerOrganizations: organizationsToAssociate,
            autoCreateGroup: mappedConfig.auto_create_group ?? false,
          };
          providerLoginHandler({ email: userEmail, name: userName, firstname, lastname, provider_metadata: { nameID, nameIDFormat } }, done, opts);
        } else {
          done({ message: 'Restricted access, ask your administrator' });
        }
      }, (profile) => {
        // SAML Logout function
        logApp.info(`[SAML] Logout done for ${profile}`);
      });
      samlStrategy.logout_remote = samlOptions.logout_remote;
      passport.use(providerRef, samlStrategy);
      PROVIDERS.push({ name: providerName, type: AuthType.AUTH_SSO, strategy, provider: providerRef });
    }
    if (strategy === StrategyType.STRATEGY_OPENID) {
      const providerRef = identifier || 'oic';
      // Here we use directly the config and not the mapped one.
      // All config of openid lib use snake case.
      const openIdClient = config.use_proxy ? getPlatformHttpProxyAgent(config.issuer) : undefined;
      OpenIDCustom.setHttpOptionsDefaults({ timeout: 0, agent: openIdClient });
      enrichWithRemoteCredentials(`providers:${providerIdent}`, config).then((clientConfig) => {
        OpenIDIssuer.discover(config.issuer).then((issuer) => {
          const { Client } = issuer;
          const client = new Client(clientConfig);
          // region scopes generation
          const defaultScopes = mappedConfig.default_scopes ?? ['openid', 'email', 'profile'];
          const openIdScopes = [...defaultScopes];
          const groupsScope = mappedConfig.groups_management?.groups_scope;
          if (groupsScope) {
            openIdScopes.push(groupsScope);
          }
          const organizationsScope = mappedConfig.organizations_management?.organizations_scope;
          if (organizationsScope) {
            openIdScopes.push(organizationsScope);
          }
          // endregion
          const openIdScope = R.uniq(openIdScopes).join(' ');
          const options = { logout_remote: mappedConfig.logout_remote, client, passReqToCallback: true, params: { scope: openIdScope } };
          const debugCallback = (message, meta) => logApp.info(message, meta);
          const openIDStrategy = new OpenIDStrategy(options, debugCallback, (_, tokenset, userinfo, done) => {
            logApp.info('[OPENID] Successfully logged', { userinfo });
            addUserLoginCount();
            const isGroupMapping = (isNotEmptyField(mappedConfig.groups_management) && isNotEmptyField(mappedConfig.groups_management?.groups_mapping));
            logApp.info('[OPENID] Groups management configuration', { groupsManagement: mappedConfig.groups_management });
            // region groups mapping
            const computeGroupsMapping = () => {
              const readUserinfo = mappedConfig.groups_management?.read_userinfo || false;
              const token = mappedConfig.groups_management?.token_reference || 'access_token';
              const groupsPath = mappedConfig.groups_management?.groups_path || ['groups'];
              const groupsMapping = mappedConfig.groups_management?.groups_mapping || [];
              const decodedUser = jwtDecode(tokenset[token]);
              if (!readUserinfo) {
                logApp.info(`[OPENID] Groups mapping on decoded ${token}`, { decoded: decodedUser });
              }
              const availableGroups = R.flatten(groupsPath.map((path) => {
                const userClaims = (readUserinfo) ? userinfo : decodedUser;
                const value = R.path(path.split('.'), userClaims) || [];
                return Array.isArray(value) ? value : [value];
              }));
              const groupsMapper = genConfigMapper(groupsMapping);
              return availableGroups.map((a) => groupsMapper[a]).filter((r) => isNotEmptyField(r));
            };
            const mappedGroups = isGroupMapping ? computeGroupsMapping() : [];
            const groupsToAssociate = R.uniq(mappedGroups);
            // endregion
            // region organizations mapping
            const isOrgaMapping = isNotEmptyField(mappedConfig.organizations_default) || isNotEmptyField(mappedConfig.organizations_management);
            const computeOrganizationsMapping = () => {
              const orgaDefault = mappedConfig.organizations_default ?? [];
              const readUserinfo = mappedConfig.organizations_management?.read_userinfo || false;
              const orgasMapping = mappedConfig.organizations_management?.organizations_mapping || [];
              const token = mappedConfig.organizations_management?.token_reference || 'access_token';
              const orgaPath = mappedConfig.organizations_management?.organizations_path || ['organizations'];
              const decodedUser = jwtDecode(tokenset[token]);
              const availableOrgas = R.flatten(orgaPath.map((path) => {
                const userClaims = (readUserinfo) ? userinfo : decodedUser;
                const value = R.path(path.split('.'), userClaims) || [];
                return Array.isArray(value) ? value : [value];
              }));
              const orgasMapper = genConfigMapper(orgasMapping);
              return [...orgaDefault, ...availableOrgas.map((a) => orgasMapper[a]).filter((r) => isNotEmptyField(r))];
            };
            const organizationsToAssociate = isOrgaMapping ? computeOrganizationsMapping() : [];
            // endregion
            if (!isGroupMapping || groupsToAssociate.length > 0) {
              const nameAttribute = mappedConfig.name_attribute ?? 'name';
              const emailAttribute = mappedConfig.email_attribute ?? 'email';
              const firstnameAttribute = mappedConfig.firstname_attribute ?? 'given_name';
              const lastnameAttribute = mappedConfig.lastname_attribute ?? 'family_name';
              const get_user_attributes_from_id_token = mappedConfig.get_user_attributes_from_id_token ?? false;

              const user_attribute_obj = get_user_attributes_from_id_token ? jwtDecode(tokenset.id_token) : userinfo;

              const name = user_attribute_obj[nameAttribute];
              const email = user_attribute_obj[emailAttribute];
              const firstname = user_attribute_obj[firstnameAttribute];
              const lastname = user_attribute_obj[lastnameAttribute];
              const opts = {
                providerGroups: groupsToAssociate,
                providerOrganizations: organizationsToAssociate,
                autoCreateGroup: mappedConfig.auto_create_group ?? false,
              };
              providerLoginHandler({ email, name, firstname, lastname }, done, opts);
            } else {
              done({ message: 'Restricted access, ask your administrator' });
            }
          });
          openIDStrategy.logout_remote = options.logout_remote;
          logApp.debug('[OPENID] logout remote options', options);
          openIDStrategy.logout = (_, callback) => {
            const isSpecificUri = isNotEmptyField(config.logout_callback_url);
            const endpointUri = issuer.end_session_endpoint ? issuer.end_session_endpoint : `${config.issuer}/oidc/logout`;
            logApp.debug(`[OPENID] logout configuration, isSpecificUri:${isSpecificUri}, issuer.end_session_endpoint:${issuer.end_session_endpoint}, final endpointUri: ${endpointUri}`);
            if (isSpecificUri) {
              const logoutUri = `${endpointUri}?post_logout_redirect_uri=${config.logout_callback_url}`;
              callback(null, logoutUri);
            } else {
              callback(null, endpointUri);
            }
          };
          passport.use(providerRef, openIDStrategy);
          PROVIDERS.push({ name: providerName, type: AuthType.AUTH_SSO, strategy, provider: providerRef });
        }).catch((err) => {
          logApp.error('[OPENID] Error initializing authentication provider', { cause: err, provider: providerRef });
        });
      }).catch((reason) => logApp.error('[OPENID] Error when enrich with remote credentials', { cause: reason }));
    }
    if (strategy === StrategyType.STRATEGY_FACEBOOK) {
      const providerRef = identifier || 'facebook';
      const specificConfig = { profileFields: ['id', 'emails', 'name'], scope: 'email' };
      const facebookOptions = { passReqToCallback: true, ...mappedConfig, ...specificConfig };
      const facebookStrategy = new FacebookStrategy(
        facebookOptions,
        (_, __, ___, profile, done) => {
          const data = profile._json;
          logApp.info('[FACEBOOK] Successfully logged', { profile: data });
          addUserLoginCount();
          const { email } = data;
          providerLoginHandler({ email, name: data.first_name }, done);
        }
      );
      passport.use(providerRef, facebookStrategy);
      PROVIDERS.push({ name: providerName, type: AuthType.AUTH_SSO, strategy, provider: providerRef });
    }
    if (strategy === StrategyType.STRATEGY_GOOGLE) {
      const providerRef = identifier || 'google';
      const domains = mappedConfig.domains || [];
      const specificConfig = { scope: ['email', 'profile'] };
      const googleOptions = { passReqToCallback: true, ...mappedConfig, ...specificConfig };
      const googleStrategy = new GoogleStrategy(googleOptions, (_, __, ___, profile, done) => {
        logApp.info('[GOOGLE] Successfully logged', { profile });
        addUserLoginCount();
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
      PROVIDERS.push({ name: providerName, type: AuthType.AUTH_SSO, strategy, provider: providerRef });
    }
    if (strategy === StrategyType.STRATEGY_GITHUB) {
      const providerRef = identifier || 'github';
      const organizations = mappedConfig.organizations || [];
      const scope = organizations.length > 0 ? 'user:email,read:org' : 'user:email';
      const githubOptions = { passReqToCallback: true, ...mappedConfig, scope };
      const githubStrategy = new GithubStrategy(githubOptions, async (_, token, __, profile, done) => {
        logApp.info('[GITHUB] Successfully logged', { profile });
        addUserLoginCount();
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
      PROVIDERS.push({ name: providerName, type: AuthType.AUTH_SSO, strategy, provider: providerRef });
    }
    if (strategy === StrategyType.STRATEGY_AUTH0) {
      // Auth0 is a specific implementation of OpenID
      // note maybe one day it will be removed to keep only STRATEGY_OPENID.
      const providerRef = identifier || 'auth0';
      const authDomain = config.domain;
      const auth0Issuer = `https://${authDomain}/`;

      const auth0OpenIDConfiguration = {
        issuer: auth0Issuer,
        authorizationURL: `https://${authDomain}/authorize`,
        tokenURL: `https://${authDomain}/oauth/token`,
        userInfoURL: `https://${authDomain}/userinfo`,
        client_id: config.clientID ? config.clientID : mappedConfig.clientID, // backward compatibility with Json conf & env var
        client_secret: config.clientSecret ? config.clientSecret : mappedConfig.clientSecret,
        redirect_uri: config.callback_url
      };
      const auth0config = { ...config, ...auth0OpenIDConfiguration };

      // Here we use directly the config and not the mapped one.
      // All config of openid lib use snake case.
      const openIdClient = auth0config.use_proxy ? getPlatformHttpProxyAgent(auth0Issuer) : undefined;
      OpenIDCustom.setHttpOptionsDefaults({ timeout: 0, agent: openIdClient });
      OpenIDIssuer.discover(auth0Issuer).then((issuer) => {
        const { Client } = issuer;
        const client = new Client(auth0config);
        const openIdScope = mappedConfig.scope ?? 'openid email profile';
        const options = { ...auth0OpenIDConfiguration, logout_remote: mappedConfig.logout_remote, client, passReqToCallback: true, params: { scope: openIdScope } };
        const debugCallback = (message, meta) => logApp.info(message, meta);
        const auth0Strategy = new OpenIDStrategy(options, debugCallback, (_, tokenset, userinfo, done) => {
          logApp.info('[AUTH0] Successfully logged', { userinfo });
          addUserLoginCount();
          const { email, name } = userinfo;
          providerLoginHandler({ email, name }, done);
        });
        auth0Strategy.logout_remote = options.logout_remote;

        auth0Strategy.logout = (_, callback) => {
          const params = {
            client_id: mappedConfig.clientID,
            returnTo: mappedConfig.baseURL
          };
          const URLParams = new URLSearchParams(params).toString();
          let endpointUri = `https://${authDomain}/v2/logout?${URLParams}`;
          if (mappedConfig.logout_uri) {
            endpointUri = `${mappedConfig.logout_uri}?${URLParams}`;
          }
          logApp.info(`[AUTH0] Remote logout on ${endpointUri}`);
          callback(null, endpointUri);
        };
        passport.use(providerRef, auth0Strategy);
        PROVIDERS.push({ name: providerName, type: AuthType.AUTH_SSO, strategy, provider: providerRef });
      }).catch((reason) => logApp.error('[AUTH0] Error when enrich with remote credentials', { cause: reason }));
    }
    // CERT Strategies
    if (strategy === StrategyType.STRATEGY_CERT) {
      const providerRef = identifier || 'cert';
      // This strategy is directly handled by express
      PROVIDERS.push({ name: providerName, type: AuthType.AUTH_SSO, strategy, provider: providerRef });
    }
    // HEADER Strategies
    if (strategy === StrategyType.STRATEGY_HEADER) {
      // This strategy is directly handled on the fly on graphql
      const providerRef = identifier || 'header';
      const reqLoginHandler = async (req) => {
        // Group computations
        const isGroupMapping = isNotEmptyField(mappedConfig.groups_management) && isNotEmptyField(mappedConfig.groups_management?.groups_mapping);
        const computeGroupsMapping = () => {
          const groupsMapping = mappedConfig.groups_management?.groups_mapping || [];
          const groupsSplitter = mappedConfig.groups_management?.groups_splitter || ',';
          const availableGroups = (req.header(mappedConfig.groups_management?.groups_header) ?? '').split(groupsSplitter);
          const groupsMapper = genConfigMapper(groupsMapping);
          return availableGroups.map((a) => groupsMapper[a]).filter((r) => isNotEmptyField(r));
        };
        const mappedGroups = isGroupMapping ? computeGroupsMapping() : [];
        // Organization computations
        const isOrgaMapping = isNotEmptyField(mappedConfig.organizations_default) || isNotEmptyField(mappedConfig.organizations_management);
        const computeOrganizationsMapping = () => {
          const orgaDefault = mappedConfig.organizations_default ?? [];
          const orgasMapping = mappedConfig.organizations_management?.organizations_mapping || [];
          const orgasSplitter = mappedConfig.organizations_management?.organizations_splitter || ',';
          const availableOrgas = (req.header(mappedConfig.organizations_management?.organizations_header) ?? '').split(orgasSplitter);
          const orgasMapper = genConfigMapper(orgasMapping);
          return [...orgaDefault, ...availableOrgas.map((a) => orgasMapper[a]).filter((r) => isNotEmptyField(r))];
        };
        const organizationsToAssociate = isOrgaMapping ? computeOrganizationsMapping() : [];
        // Build the user login
        const email = req.header(mappedConfig.header_email);
        if (isEmptyField(email) || !validator.isEmail(email)) {
          return null;
        }
        const name = req.header(mappedConfig.header_name);
        const firstname = req.header(mappedConfig.header_firstname);
        const lastname = req.header(mappedConfig.header_lastname);
        const opts = {
          providerGroups: mappedGroups,
          providerOrganizations: organizationsToAssociate,
          autoCreateGroup: mappedConfig.auto_create_group ?? false,
        };
        const provider_metadata = { headers_audit: mappedConfig.headers_audit };
        addUserLoginCount();
        return new Promise((resolve) => {
          providerLoginHandler({ email, name, firstname, provider_metadata, lastname }, (err, user) => {
            resolve(user);
          }, opts);
        });
      };
      const headerProvider = {
        name: providerName,
        reqLoginHandler,
        type: AuthType.AUTH_REQ,
        strategy,
        logout_uri: mappedConfig.logout_uri,
        provider: providerRef
      };
      PROVIDERS.push(headerProvider);
      HEADERS_AUTHENTICATORS.push(headerProvider);
    }
  }
  // In case of disable local strategy, setup protected fallback for the admin user
  const hasLocal = PROVIDERS.find((p) => p.strategy === StrategyType.STRATEGY_LOCAL);
  if (!hasLocal) {
    const adminLocalStrategy = new LocalStrategy({}, (username, password, done) => {
      const adminEmail = conf.get('app:admin:email');
      if (username !== adminEmail) {
        return done(AuthenticationFailure());
      }
      return login(username, password)
        .then((info) => {
          addUserLoginCount();
          return done(null, info);
        })
        .catch((err) => {
          done(err);
        });
    });
    passport.use('local', adminLocalStrategy);
    PROVIDERS.push({ name: INTERNAL_SECURITY_PROVIDER, type: AuthType.AUTH_FORM, strategy, provider: 'local' });
  }
}

export default passport;
