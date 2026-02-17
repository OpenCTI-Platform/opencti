import { NODE_INSTANCE_ID } from '../../config/conf';
import {
  EnvStrategyType,
  isAuthenticationProviderMigrated,
  isAuthenticationActivatedByIdentifier,
  getProvidersFromEnvironment,
  isAuthenticationForcedFromEnv,
  genConfigMapper,
  providerLoginHandler,
  isAdminExternallyManaged,
  getConfigurationAdminEmail,
  getConfigurationAdminPassword,
  getConfigurationAdminToken,
} from './providers-configuration';
import nconf from 'nconf';
import { findAllAuthenticationProvider, getAllIdentifiers, runAuthenticationProviderMigration } from './authenticationProvider-domain';
import { getEnterpriseEditionInfo } from '../settings/licensing';
import * as R from 'ramda';
import passport from 'passport';
import GitHub from 'github-api';
import { jwtDecode } from 'jwt-decode';
import FacebookStrategy from 'passport-facebook';
import GithubStrategy from 'passport-github';
import LdapStrategy from 'passport-ldapauth';
import { Strategy as SamlStrategy } from '@node-saml/passport-saml';
import { custom as OpenIDCustom, Issuer as OpenIDIssuer, Strategy as OpenIDStrategy } from 'openid-clientv5';
import { OAuth2Strategy as GoogleStrategy } from 'passport-google-oauth';
import validator from 'validator';
import { getPlatformHttpProxyAgent, logApp } from '../../config/conf';
import { ConfigurationError } from '../../config/errors';
import { AuthType, PROVIDERS } from './providers-configuration';
import { DEFAULT_INVALID_CONF_VALUE, SYSTEM_USER } from '../../utils/access';
import { OPENCTI_ADMIN_UUID } from '../../schema/general';
import { findById, initAdmin, userDelete } from '../../domain/user';
import { isEmptyField, isNotEmptyField } from '../../database/utils';
import { enrichWithRemoteCredentials } from '../../config/credentials';
import { forgetPromise } from '../../utils/promiseUtils';
import { getSettings, updateLocalAuth, updateHeaderAuth, updateCertAuth } from '../../domain/settings';
import { logAuthInfo } from './providers-logger';

// ---------------------------------------------------------------------------
// Singleton settings migration — ensure all singleton auth settings exist
// Handles both: attribute absent (create with defaults) and old flat format (convert)
// ---------------------------------------------------------------------------

const parseMappingStrings = (mapping) => {
  if (!mapping || !Array.isArray(mapping)) return [];
  return mapping
    .filter((s) => typeof s === 'string')
    .map((s) => {
      const parts = s.split(':');
      return { provider: parts[0] || '', platform: parts[1] || '' };
    })
    .filter((m) => m.provider || m.platform);
};

/**
 * Ensure local_auth exists.
 * - If absent: create with default { enabled: true }
 * - If present: no-op
 * Returns true if the attribute was absent and had to be created.
 */
const migrateLocalAuthIfNeeded = async (context, user, settings) => {
  if (settings.local_auth) return false;
  logApp.info('[SINGLETON-MIGRATION] local_auth is absent, creating with defaults');
  await updateLocalAuth(context, user, settings.id, { enabled: true });
  logApp.info('[SINGLETON-MIGRATION] local_auth successfully ensured');
  return true;
};

/**
 * Ensure headers_auth is in the new nested format.
 * - If absent: create with defaults
 * - If old flat format (no user_info_mapping): convert flat fields to nested
 * - If already nested: no-op
 */
const migrateHeadersAuthIfNeeded = async (context, user, settings) => {
  const ha = settings.headers_auth;

  // Already in new format
  if (ha?.user_info_mapping) return;

  if (!ha) {
    logApp.info('[SINGLETON-MIGRATION] headers_auth is absent, creating with defaults');
  } else {
    logApp.info('[SINGLETON-MIGRATION] Converting headers_auth from flat to nested format');
  }

  const nested = {
    enabled: ha?.enabled ?? false,
    logout_uri: ha?.logout_uri ?? null,
    headers_audit: ha?.headers_audit ?? [],
    user_info_mapping: {
      email_expr: ha?.header_email || 'x-email',
      name_expr: ha?.header_name || 'x-name',
      firstname_expr: ha?.header_firstname || null,
      lastname_expr: ha?.header_lastname || null,
    },
    groups_mapping: {
      default_groups: [],
      groups_expr: ha?.groups_header ? [ha.groups_header] : [],
      group_splitter: ha?.groups_splitter || null,
      groups_mapping: parseMappingStrings(ha?.groups_mapping),
      auto_create_groups: ha?.auto_create_group ?? false,
      prevent_default_groups: ha?.prevent_default_groups ?? false,
    },
    organizations_mapping: {
      default_organizations: ha?.organizations_default ?? [],
      organizations_expr: ha?.organizations_header ? [ha.organizations_header] : [],
      organizations_splitter: ha?.organizations_splitter || null,
      organizations_mapping: parseMappingStrings(ha?.organizations_mapping),
      auto_create_organizations: false,
    },
  };

  await updateHeaderAuth(context, user, settings.id, nested);
  logApp.info('[SINGLETON-MIGRATION] headers_auth successfully ensured in nested format');
};

/**
 * Ensure cert_auth is in the new nested format.
 * - If absent: create with defaults
 * - If old flat format (no user_info_mapping): convert flat fields to nested
 * - If already nested: no-op
 */
const migrateCertAuthIfNeeded = async (context, user, settings) => {
  const ca = settings.cert_auth;

  // Already in new format
  if (ca?.user_info_mapping) return;

  if (!ca) {
    logApp.info('[SINGLETON-MIGRATION] cert_auth is absent, creating with defaults');
  } else {
    logApp.info('[SINGLETON-MIGRATION] Converting cert_auth from flat to nested format');
  }

  const nested = {
    enabled: ca?.enabled ?? false,
    button_label: ca?.button_label ?? null,
    user_info_mapping: {
      email_expr: ca?.email_expr || 'subject.emailAddress',
      name_expr: ca?.name_expr || 'subject.CN',
      firstname_expr: ca?.firstname_expr || null,
      lastname_expr: ca?.lastname_expr || null,
    },
    groups_mapping: {
      default_groups: [],
      groups_expr: Array.isArray(ca?.groups_expr) ? ca.groups_expr : (ca?.groups_expr ? [ca.groups_expr] : ['subject.OU']),
      group_splitter: null,
      groups_mapping: parseMappingStrings(ca?.groups_mapping),
      auto_create_groups: ca?.auto_create_group ?? ca?.auto_create_groups ?? false,
      prevent_default_groups: ca?.prevent_default_groups ?? false,
    },
    organizations_mapping: {
      default_organizations: ca?.organizations_default ?? [],
      organizations_expr: Array.isArray(ca?.organizations_expr) ? ca.organizations_expr : (ca?.organizations_expr ? [ca.organizations_expr] : ['subject.O']),
      organizations_splitter: null,
      organizations_mapping: parseMappingStrings(ca?.organizations_mapping),
      auto_create_organizations: false,
    },
  };

  await updateCertAuth(context, user, settings.id, nested);
  logApp.info('[SINGLETON-MIGRATION] cert_auth successfully ensured in nested format');
};

// (providerRef: string)
export const unregisterAuthenticationProvider = (providerRef) => {
  if (passport._strategy(providerRef)) {
    passport.unuse(providerRef);
  }

  let indexToRemove = PROVIDERS.findIndex((conf) => conf.provider === providerRef);
  let removedItem; // only last removed is enough
  while (indexToRemove !== -1) {
    removedItem = PROVIDERS[indexToRemove];
    PROVIDERS.splice(indexToRemove, 1);
    indexToRemove = PROVIDERS.findIndex((conf) => conf.provider === providerRef);
  }
  if (removedItem) {
    logAuthInfo(`Strategy ${providerRef} unregistered on node ${NODE_INSTANCE_ID}`, removedItem.strategy);
  } else {
    logApp.info(`[AUTH PROVIDER] request to remove ${providerRef} but not found in registered one`);
  }
};

// (providerRef: string, strategy: any, configuration: ProviderConfiguration)
export const registerAuthenticationProvider = (providerRef, strategy, configuration) => {
  if (isAuthenticationActivatedByIdentifier(configuration.provider)) {
    logApp.warn(`[AUTH PROVIDER] identifier ${configuration.provider} already registered. Please check your configuration to see if there is not 2 time the same identifier.`);
    unregisterAuthenticationProvider(configuration.provider);
  }

  passport.use(providerRef, strategy);
  PROVIDERS.push(configuration);
  logAuthInfo('Strategy registered', configuration.strategy, { identifier: providerRef });
};

// Admin user initialization
export const initializeAdminUser = async (context) => {
  if (isAdminExternallyManaged()) {
    logApp.info('[INIT] admin user initialization disabled by configuration');
    const existingAdmin = await findById(context, SYSTEM_USER, OPENCTI_ADMIN_UUID);
    if (existingAdmin) {
      await userDelete(context, SYSTEM_USER, OPENCTI_ADMIN_UUID);
    }
  } else {
    const adminEmail = getConfigurationAdminEmail();
    const adminPassword = getConfigurationAdminPassword();
    const adminToken = getConfigurationAdminToken();
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
export const configRemapping = (config) => {
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

export const initializeEnvAuthenticationProviders = async (context, user) => {
  const isForcedEnv = isAuthenticationForcedFromEnv();
  const existingIdentifiers = await getAllIdentifiers(context, user);
  const confProviders = getProvidersFromEnvironment();
  let shouldRunMigration = false;

  if (confProviders) {
    const providerKeys = Object.keys(confProviders);
    for (let i = 0; i < providerKeys.length; i += 1) {
      const providerIdent = providerKeys[i];
      const provider = confProviders[providerIdent];

      const { identifier, strategy, config } = provider;
      const mappedConfig = configRemapping(config);
      if (config === undefined || !config.disabled) {
        const providerName = config?.label || providerIdent;
        // FORM Strategies
        if (strategy === EnvStrategyType.STRATEGY_LDAP) {
          const providerRef = identifier || 'ldapauth';
          logApp.info(`[ENV-PROVIDER][LDAP] LdapStrategy found in configuration providerRef:${providerRef}`);
          if (isForcedEnv) {
            // region backward compatibility
            const allowSelfSigned = mappedConfig.allow_self_signed || mappedConfig.allow_self_signed === 'true';
            // Force bindCredentials to be a String
            mappedConfig.bindCredentials = `${mappedConfig.bindCredentials}`;
            const tlsConfig = R.assoc('tlsOptions', { rejectUnauthorized: !allowSelfSigned }, mappedConfig);
            const ldapOptions = { server: tlsConfig };
            const ldapStrategy = new LdapStrategy(ldapOptions, (user, done) => {
              logApp.info('[ENV-PROVIDER][LDAP] Successfully logged', { user });
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
                  }),
                );
                const orgasMapper = genConfigMapper(orgasMapping);
                return [...orgaDefault, ...availableOrgas.map((a) => orgasMapper[a]).filter((r) => isNotEmptyField(r))];
              };
              const organizationsToAssociate = isOrgaMapping ? computeOrganizationsMapping() : [];
              // endregion
              if (!userMail) {
                logApp.warn('[ENV-PROVIDER]LDAP Configuration error, cant map mail and username', { user, userMail, userName });
                done({ message: 'Configuration error, ask your administrator' });
              } else if (!isGroupBaseAccess || groupsToAssociate.length > 0) {
                logApp.info(`[ENV-PROVIDER][LDAP] Connecting/creating account with ${userMail} [name=${userName}]`);
                const userInfo = { email: userMail, name: userName, firstname, lastname };
                const opts = {
                  providerGroups: groupsToAssociate,
                  providerOrganizations: organizationsToAssociate,
                  autoCreateGroup: mappedConfig.auto_create_group ?? false,
                };
                forgetPromise(providerLoginHandler(userInfo, done, opts));
              } else {
                done({ message: 'Restricted access, ask your administrator' });
              }
            });
            passport.use(providerRef, ldapStrategy);
            PROVIDERS.push({ name: providerName, type: AuthType.AUTH_FORM, strategy, provider: providerRef });
            // end region backward compatibility
          } else {
            if (isAuthenticationProviderMigrated(existingIdentifiers, providerRef)) {
              logApp.info(`[ENV-PROVIDER][LDAP] ${providerRef} migrated, skipping old configuration`);
            } else {
              logApp.info(`[ENV-PROVIDER][LDAP] ${providerRef} is about to be converted to database configuration.`);
              shouldRunMigration = true;
            }
          }
        }
        // Authentication Strategies
        if (strategy === EnvStrategyType.STRATEGY_SAML) {
          const providerRef = identifier || 'saml';
          logApp.info(`[ENV-PROVIDER][SAML] SamlStrategy found in configuration providerRef:${providerRef}`);
          if (isForcedEnv) {
            // region backward compatibility
            const samlOptions = { ...mappedConfig };
            const samlStrategy = new SamlStrategy(samlOptions, (profile, done) => {
              logApp.info('[ENV-PROVIDER][SAML] Successfully logged', { profile });
              const { nameID, nameIDFormat } = profile;
              const samlAttributes = profile.attributes ? profile.attributes : profile;
              const roleAttributes = mappedConfig.roles_management?.role_attributes || ['roles'];
              const groupAttributes = mappedConfig.groups_management?.group_attributes || ['groups'];
              const userEmail = samlAttributes[mappedConfig.mail_attribute] || nameID;
              if (mappedConfig.mail_attribute && !samlAttributes[mappedConfig.mail_attribute]) {
                logApp.info(`[ENV-PROVIDER][SAML] custom mail_attribute "${mappedConfig.mail_attribute}" in configuration but the custom field is not present SAML server response.`);
              }
              const userName = samlAttributes[mappedConfig.account_attribute] || '';
              const firstname = samlAttributes[mappedConfig.firstname_attribute] || '';
              const lastname = samlAttributes[mappedConfig.lastname_attribute] || '';
              const isGroupBaseAccess = (isNotEmptyField(mappedConfig.groups_management) && isNotEmptyField(mappedConfig.groups_management?.groups_mapping));
              logApp.info('[ENV-PROVIDER][SAML] Groups management configuration', { groupsManagement: mappedConfig.groups_management });
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
              logApp.info('[ENV-PROVIDER][SAML] Login handler', { isGroupBaseAccess, groupsToAssociate });
              if (!isGroupBaseAccess || groupsToAssociate.length > 0) {
                const opts = {
                  providerGroups: groupsToAssociate,
                  providerOrganizations: organizationsToAssociate,
                  autoCreateGroup: mappedConfig.auto_create_group ?? false,
                };
                forgetPromise(providerLoginHandler({ email: userEmail, name: userName, firstname, lastname, provider_metadata: { nameID, nameIDFormat } }, done, opts));
              } else {
                done({ message: 'Restricted access, ask your administrator' });
              }
            }, (profile) => {
              // SAML Logout function
              logApp.info(`[ENV-PROVIDER][SAML] Logout done for ${profile}`);
            });
            passport.use(providerRef, samlStrategy);
            PROVIDERS.push({ name: providerName, type: AuthType.AUTH_SSO, strategy, provider: providerRef, logout_remote: mappedConfig.logout_remote });
            // end region backward compatibility
          } else {
            if (isAuthenticationProviderMigrated(existingIdentifiers, providerRef)) {
              logApp.info(`[ENV-PROVIDER][SAML] ${providerRef} already in database, skipping old configuration`);
            } else {
              logApp.info(`[ENV-PROVIDER][SAML] ${providerRef} is about to be converted to database configuration.`);
              shouldRunMigration = true;
            }
          }
        }
        if (strategy === EnvStrategyType.STRATEGY_OPENID) {
          const providerRef = identifier || 'oic';
          logApp.info(`[ENV-PROVIDER][OPENID] OpenIDConnectStrategy found in configuration providerRef:${providerRef}`);
          if (isForcedEnv) {
            // region backward compatibility
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
                const options = { client, passReqToCallback: true,
                  params: { scope: openIdScope, ...(mappedConfig.audience && { audience: mappedConfig.audience }),
                  } };
                const debugCallback = (message, meta) => logApp.info(message, meta);
                const openIDStrategy = new OpenIDStrategy(options, debugCallback, (_, tokenset, userinfo, done) => {
                  logApp.info('[ENV-PROVIDER][OPENID] Successfully logged', { userinfo });
                  const isGroupMapping = (isNotEmptyField(mappedConfig.groups_management) && isNotEmptyField(mappedConfig.groups_management?.groups_mapping));
                  logApp.info('[ENV-PROVIDER][OPENID] Groups management configuration', { groupsManagement: mappedConfig.groups_management });
                  // region groups mapping
                  const computeGroupsMapping = () => {
                    const readUserinfo = mappedConfig.groups_management?.read_userinfo || false;
                    const token = mappedConfig.groups_management?.token_reference || 'access_token';
                    const groupsPath = mappedConfig.groups_management?.groups_path || ['groups'];
                    const groupsMapping = mappedConfig.groups_management?.groups_mapping || [];
                    const decodedUser = jwtDecode(tokenset[token]);
                    if (!readUserinfo) {
                      logApp.info(`[ENV-PROVIDER][OPENID] Groups mapping on decoded ${token}`, { decoded: decodedUser });
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
                    forgetPromise(providerLoginHandler({ email, name, firstname, lastname }, done, opts));
                  } else {
                    done({ message: 'Restricted access, ask your administrator' });
                  }
                });
                logApp.debug('[ENV-PROVIDER][OPENID] logout remote options', options);
                openIDStrategy.logout = (_, callback) => {
                  const isSpecificUri = isNotEmptyField(config.logout_callback_url);
                  const endpointUri = issuer.end_session_endpoint ? issuer.end_session_endpoint : `${config.issuer}/oidc/logout`;
                  logApp.debug(`[ENV-PROVIDER][OPENID] logout configuration, isSpecificUri:${isSpecificUri}, issuer.end_session_endpoint:${issuer.end_session_endpoint}, final endpointUri: ${endpointUri}`);
                  if (isSpecificUri) {
                    const logoutUri = `${endpointUri}?post_logout_redirect_uri=${config.logout_callback_url}`;
                    callback(null, logoutUri);
                  } else {
                    callback(null, endpointUri);
                  }
                };
                passport.use(providerRef, openIDStrategy);
                PROVIDERS.push({ name: providerName, type: AuthType.AUTH_SSO, strategy, provider: providerRef, logout_remote: mappedConfig.logout_remote });
              }).catch((err) => {
                logApp.error('[ENV-PROVIDER][OPENID] Error initializing authentication provider', { cause: err, provider: providerRef });
              });
            }).catch((reason) => logApp.error('[ENV-PROVIDER][OPENID] Error when enrich with remote credentials', { cause: reason }));
            // end region backward compatibility
          } else {
            if (isAuthenticationProviderMigrated(existingIdentifiers, providerRef)) {
              logApp.info(`[ENV-PROVIDER][OPENID] ${providerRef} already in database, skipping old configuration`);
            } else {
              logApp.info(`[ENV-PROVIDER][OPENID] ${providerRef} is about to be converted to database configuration.`);
              shouldRunMigration = true;
            }
          }
        }
        if (strategy === EnvStrategyType.STRATEGY_FACEBOOK) {
          const providerRef = identifier || 'facebook';
          logApp.warn(`[ENV-PROVIDER][FACEBOOK] DEPRECATED Strategy found in configuration providerRef:${providerRef}, please consider using OpenID`);
          const specificConfig = { profileFields: ['id', 'emails', 'name'], scope: 'email' };
          const facebookOptions = { passReqToCallback: true, ...mappedConfig, ...specificConfig };
          const facebookStrategy = new FacebookStrategy(
            facebookOptions,
            (_, __, ___, profile, done) => {
              const data = profile._json;
              logApp.info('[ENV-PROVIDER][FACEBOOK] Successfully logged', { profile: data });
              const { email } = data;
              forgetPromise(providerLoginHandler({ email, name: data.first_name }, done));
            },
          );
          passport.use(providerRef, facebookStrategy);
          PROVIDERS.push({ name: providerName, type: AuthType.AUTH_SSO, strategy, provider: providerRef });
        }
        if (strategy === EnvStrategyType.STRATEGY_GOOGLE) {
          const providerRef = identifier || 'google';
          logApp.warn(`[ENV-PROVIDER][GOOGLE] DEPRECATED Strategy found in configuration providerRef:${providerRef}, please consider using OpenID`);
          const domains = mappedConfig.domains || [];
          const specificConfig = { scope: ['email', 'profile'] };
          const googleOptions = { passReqToCallback: true, ...mappedConfig, ...specificConfig };
          const googleStrategy = new GoogleStrategy(googleOptions, (_, __, ___, profile, done) => {
            logApp.info('[ENV-PROVIDER][GOOGLE] Successfully logged', { profile });
            const email = R.head(profile.emails).value;
            const name = profile.displayName;
            let authorized = true;
            if (domains.length > 0) {
              const [, domain] = email.split('@');
              authorized = domains.includes(domain);
            }
            if (authorized) {
              forgetPromise(providerLoginHandler({ email, name }, done));
            } else {
              done({ message: 'Restricted access, ask your administrator' });
            }
          });
          passport.use(providerRef, googleStrategy);
          PROVIDERS.push({ name: providerName, type: AuthType.AUTH_SSO, strategy, provider: providerRef });
        }
        if (strategy === EnvStrategyType.STRATEGY_GITHUB) {
          const providerRef = identifier || 'github';
          logApp.warn(`[ENV-PROVIDER][GITHUB] DEPRECATED Strategy found in configuration providerRef:${providerRef}, please consider using OpenID`);

          const organizations = mappedConfig.organizations || [];
          const scope = organizations.length > 0 ? 'user:email,read:org' : 'user:email';
          const githubOptions = { passReqToCallback: true, ...mappedConfig, scope };
          const githubStrategy = new GithubStrategy(githubOptions, async (_, token, __, profile, done) => {
            logApp.info('[ENV-PROVIDER][GITHUB] Successfully logged', { profile });
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
                forgetPromise(providerLoginHandler({ email, name: displayName }, done));
              }
            } else {
              done({ message: 'Restricted access, ask your administrator' });
            }
          });
          passport.use(providerRef, githubStrategy);
          PROVIDERS.push({ name: providerName, type: AuthType.AUTH_SSO, strategy, provider: providerRef });
        }
        if (strategy === EnvStrategyType.STRATEGY_AUTH0) {
          // Auth0 is a specific implementation of OpenID
          // note maybe one day it will be removed to keep only STRATEGY_OPENID.
          const providerRef = identifier || 'auth0';
          logApp.warn(`[ENV-PROVIDER][AUTH0] DEPRECATED Strategy found in configuration providerRef:${providerRef}, please consider using OpenID`);
          const authDomain = config.domain;
          const auth0Issuer = `https://${authDomain}/`;

          const auth0OpenIDConfiguration = {
            issuer: auth0Issuer,
            authorizationURL: `https://${authDomain}/authorize`,
            tokenURL: `https://${authDomain}/oauth/token`,
            userInfoURL: `https://${authDomain}/userinfo`,
            client_id: config.clientID ? config.clientID : mappedConfig.clientID, // backward compatibility with Json conf & env var
            client_secret: config.clientSecret ? config.clientSecret : mappedConfig.clientSecret,
            redirect_uri: config.callback_url,
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
            const options = {
              ...auth0OpenIDConfiguration,
              client,
              passReqToCallback: true,
              params: { scope: openIdScope },
            };
            const debugCallback = (message, meta) => logApp.info(message, meta);
            const auth0Strategy = new OpenIDStrategy(options, debugCallback, (_, tokenset, userinfo, done) => {
              logApp.info('[ENV-PROVIDER][AUTH0] Successfully logged', { userinfo });
              const { email, name } = userinfo;
              forgetPromise(providerLoginHandler({ email, name }, done));
            });

            auth0Strategy.logout = (_, callback) => {
              const params = {
                client_id: mappedConfig.clientID,
                returnTo: mappedConfig.baseURL,
              };
              const URLParams = new URLSearchParams(params).toString();
              let endpointUri = `https://${authDomain}/v2/logout?${URLParams}`;
              if (mappedConfig.logout_uri) {
                endpointUri = `${mappedConfig.logout_uri}?${URLParams}`;
              }
              logApp.info(`[ENV-PROVIDER][AUTH0] Remote logout on ${endpointUri}`);
              callback(null, endpointUri);
            };
            passport.use(providerRef, auth0Strategy);
            PROVIDERS.push({ name: providerName, type: AuthType.AUTH_SSO, strategy, provider: providerRef, logout_remote: mappedConfig.logout_remote });
          }).catch((reason) => logApp.error('[ENV-PROVIDER][AUTH0] Error when enrich with remote credentials', { cause: reason }));
        }
        // Singleton authentications: ensure they all exist and are in the correct nested format
        const settings = await getSettings(context);
        await migrateLocalAuthIfNeeded(context, user, settings);
        await migrateHeadersAuthIfNeeded(context, user, settings);
        await migrateCertAuthIfNeeded(context, user, settings);
      }
    }
  } else {
    logApp.info('[ENV-PROVIDER] No provider in environment.');
  }
  if (shouldRunMigration && !isForcedEnv) {
    await runAuthenticationProviderMigration(context, user, { dry_run: false });
  }
  // Safety net: force local_auth enabled when no other provider is available
  const finalSettings = await getSettings(context);
  const eeActive = getEnterpriseEditionInfo(finalSettings).license_validated;
  if (finalSettings.local_auth?.enabled === false) {
    const isHttpsEnabled = !!(nconf.get('app:https_cert:key') && nconf.get('app:https_cert:crt'));
    const hasCert = finalSettings.cert_auth?.enabled === true && eeActive && isHttpsEnabled;
    const hasHeader = finalSettings.headers_auth?.enabled === true && eeActive;
    const dbProviders = await findAllAuthenticationProvider(context, user);
    const hasDbProvider = eeActive && dbProviders.some((p) => p.enabled === true);
    if (!hasCert && !hasHeader && !hasDbProvider) {
      logApp.warn('[MIGRATION-SAFETY] No other provider available, forcing local_auth to enabled');
      await updateLocalAuth(context, user, finalSettings.id, { enabled: true });
    }
  }
  logApp.info('[ENV-PROVIDER] End of reading environment');
};
