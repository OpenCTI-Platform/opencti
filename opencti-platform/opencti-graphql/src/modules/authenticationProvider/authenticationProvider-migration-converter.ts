/**
 * Pure conversion functions: YAML/env configuration → GraphQL input types.
 *
 * This module contains ONLY pure functions with NO side effects (no database, no I/O, no logging).
 * It converts the legacy YAML/env provider configuration format into the new GraphQL input types
 * used by the AuthenticationProvider entity.
 *
 * Architecture:
 * - env config (nconf YAML) → convertXxxEnvConfig() → { base, configuration } (GraphQL input shape)
 * - Database orchestration is in authenticationProvider-migration.ts (separate concern)
 *
 * Key design: instead of maintaining hardcoded sets of "consumed" keys, each conversion
 * function uses a ConfigExtractor that tracks which keys were actually read. Anything
 * not read during conversion automatically becomes extra_conf. Adding a new first-class
 * field only requires adding a .get() call — impossible to forget the consumed-set update.
 *
 * References:
 * - authentication_binding.md for field-by-field mapping documentation
 */

import {
  type AuthenticationProviderBaseInput,
  type ExtraConfEntryInput,
  ExtraConfEntryType,
  type GroupsMappingInput,
  type LdapConfigurationInput,
  type MappingEntryInput,
  type OidcConfigurationInput,
  type OrganizationsMappingInput,
  type SamlConfigurationInput,
  type UserInfoMappingInput,
} from '../../generated/graphql';

// [/] default conf for LDAP user info mapping : email -> 'mail' & name -> 'givenName'
// [/] default conf for LDAP group mapping : ['_groups/cn'] or just ['cn'] ?
// [/] default conf for LDAP orga mapping : ['organizations'] ?

// TODO default conf for SAML  conf.mail_attribute -> conf.user_info_mapping.email_expr
// TODO default conf for SAML  conf.account_attribute -> conf.user_info_mapping.name_expr
// TODO default conf for SAML  conf.firstname_attribute -> conf.user_info_mapping.firstname_expr
// TODO default conf for SAML  conf.lastname_attribute -> conf.user_info_mapping.lastname_expr
// TODO default conf for SAML  groupsManagement?.group_attributes || ['groups']  -> conf.groups_mapping.groups_expr
// TODO default conf for SAML  orgsManagement?.organizations_path || ['organizations']; -> conf.organizations_mapping.organizations_expr

// ---------------------------------------------------------------------------
// ConfigExtractor — tracks which keys are consumed during conversion
// ---------------------------------------------------------------------------

/**
 * Wraps a raw env config object and tracks every key access.
 * After conversion, call .getUnconsumedEntries() to collect
 * everything that should go to extra_conf.
 *
 * This removes the need for manually maintained CONSUMED_KEYS sets.
 */
export class ConfigExtractor {
  private readonly consumed = new Set<string>();

  constructor(private readonly config: Record<string, any>) {}

  /** Read a key and mark it as consumed. Returns the value or the default. */
  get<T = any>(key: string, defaultValue?: T): T {
    this.consumed.add(key);
    const value = this.config[key];
    return (value !== undefined ? value : defaultValue) as T;
  }

  /** Check if a key exists without consuming it. */
  has(key: string): boolean {
    return key in this.config;
  }

  /** Mark a key as consumed without reading (for deprecated/ignored keys). */
  consume(...keys: string[]): void {
    for (const key of keys) {
      this.consumed.add(key);
    }
  }

  /** Return all key/value pairs that were NOT consumed during conversion. */
  getUnconsumedEntries(): [string, unknown][] {
    return Object.entries(this.config)
      .filter(([key]) => !this.consumed.has(key));
  }
}

// ---------------------------------------------------------------------------
// Types for the raw YAML/env configuration shape
// ---------------------------------------------------------------------------

/** A single mapping entry in the env config: "remote_value:platform_value" */
type EnvMappingEntry = string;

interface EnvGroupsManagement {
  groups_mapping?: EnvMappingEntry[];
  // OIDC-specific
  groups_path?: string[];
  groups_scope?: string;
  read_userinfo?: boolean;
  token_reference?: string;
  // SAML-specific
  group_attributes?: string[];
  // LDAP-specific
  group_attribute?: string;
}

interface EnvOrganizationsManagement {
  organizations_mapping?: EnvMappingEntry[];
  organizations_path?: string[];
  organizations_scope?: string;
  read_userinfo?: boolean;
  token_reference?: string;
}

/**
 * Raw provider entry as read from nconf YAML `providers.<key>`.
 * The `config` sub-object shape varies by strategy.
 */
export interface EnvProviderEntry {
  identifier?: string;
  strategy: string;
  config?: Record<string, any>;
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export interface ConvertedOidcProvider {
  type: 'OIDC';
  base: AuthenticationProviderBaseInput;
  configuration: OidcConfigurationInput;
  warnings: string[];
}

export interface ConvertedSamlProvider {
  type: 'SAML';
  base: AuthenticationProviderBaseInput;
  configuration: SamlConfigurationInput;
  warnings: string[];
}

export interface ConvertedLdapProvider {
  type: 'LDAP';
  base: AuthenticationProviderBaseInput;
  configuration: LdapConfigurationInput;
  warnings: string[];
}

export type ConvertedProvider = ConvertedOidcProvider | ConvertedSamlProvider | ConvertedLdapProvider;

// ---------------------------------------------------------------------------
// Helpers — all pure, no side effects
// ---------------------------------------------------------------------------

/**
 * Convert env mapping entries ("remote:platform" strings) to GraphQL MappingEntryInput[].
 */
export const convertMappingEntries = (entries: EnvMappingEntry[] | undefined): MappingEntryInput[] => {
  if (!entries || !Array.isArray(entries)) return [];
  return entries
    .map((entry) => {
      const parts = entry.split(':');
      if (parts.length !== 2) return null;
      return { provider: parts[0], platform: parts[1] } as MappingEntryInput;
    })
    .filter((e): e is MappingEntryInput => e !== null);
};

/**
 * Build ExtraConfEntryInput(s) from a key and a value.
 * Infers type from the JS runtime type of the value.
 * Arrays produce one entry per element (same key repeated), so the backend
 * groups them back into an array at runtime.
 */
export const toExtraConfEntry = (key: string, value: unknown): ExtraConfEntryInput | ExtraConfEntryInput[] | null => {
  if (value === undefined || value === null) return null;
  if (typeof value === 'boolean') {
    return { type: ExtraConfEntryType.Boolean, key, value: String(value) };
  }
  if (typeof value === 'number') {
    return { type: ExtraConfEntryType.Number, key, value: String(value) };
  }
  if (typeof value === 'string') {
    return { type: ExtraConfEntryType.String, key, value };
  }
  if (Array.isArray(value)) {
    return value
      .map((v) => toExtraConfEntry(key, v))
      .flat()
      .filter((e): e is ExtraConfEntryInput => e !== null);
  }
  // Objects and functions cannot be serialized
  return null;
};

/**
 * Default identifier per strategy, matching the legacy providers-initialization.js behavior.
 * Used when no explicit `identifier` is set in the env config entry.
 */
const STRATEGY_DEFAULT_IDENTIFIER: Record<string, string> = {
  OpenIDConnectStrategy: 'oic',
  SamlStrategy: 'saml',
  LdapStrategy: 'ldapauth',
  FacebookStrategy: 'facebook',
  GoogleStrategy: 'google',
  GithubStrategy: 'github',
  Auth0Strategy: 'auth0',
};

/**
 * Resolve the provider identifier from the env entry.
 * Uses the explicit `identifier` field, or falls back to the strategy-specific
 * default, matching the behavior of providers-initialization.js.
 */
export const resolveIdentifier = (entry: EnvProviderEntry): string => {
  return entry.identifier || STRATEGY_DEFAULT_IDENTIFIER[entry.strategy] || entry.strategy;
};

/**
 * Build the base input shared by all provider types.
 * Consumes 'label' and 'disabled' from the extractor.
 * `identifier_override` is always set (mandatory for creating the authenticator).
 */
export const buildBaseInput = (
  envKey: string,
  entry: EnvProviderEntry,
  extractor: ConfigExtractor,
): AuthenticationProviderBaseInput => {
  const label = extractor.get<string | undefined>('label', undefined);
  const disabled = extractor.get<boolean>('disabled', false);

  return {
    name: label || envKey,
    description: `Migrated from YAML configuration key "${envKey}"`,
    enabled: disabled !== true,
    button_label_override: label || null,
    identifier_override: resolveIdentifier(entry),
  };
};

/**
 * Collect unconsumed config entries into ExtraConfEntryInput[].
 * Keys are passed through as-is — all known fields that needed camelCase
 * remapping are now consumed as first-class fields by the converters.
 */
const collectExtraConf = (
  extractor: ConfigExtractor,
  warnings: string[],
): ExtraConfEntryInput[] => {
  const extraConf: ExtraConfEntryInput[] = [];
  for (const [key, value] of extractor.getUnconsumedEntries()) {
    if (typeof value === 'function') {
      warnings.push(`Config key "${key}" is a function and cannot be migrated.`);
      continue;
    }
    const result = toExtraConfEntry(key, value);
    if (result) {
      // toExtraConfEntry returns a single entry or an array (for array values)
      if (Array.isArray(result)) {
        extraConf.push(...result);
      } else {
        extraConf.push(result);
      }
    } else {
      warnings.push(`Config key "${key}" could not be converted to extra_conf (unsupported type: ${typeof value}).`);
    }
  }
  return extraConf;
};

// ---------------------------------------------------------------------------
// OIDC conversion
// ---------------------------------------------------------------------------

const buildOidcGroupsExpr = (gm: EnvGroupsManagement | undefined): string[] => {
  // Always populate with defaults — in the new model we never hide default paths.
  // Old default: groups_path=['groups'], token_reference='access_token', read_userinfo=false
  const paths = gm?.groups_path ?? ['groups'];
  const readUserinfo = gm?.read_userinfo ?? false;
  const tokenRef = gm?.token_reference ?? 'access_token';
  const prefix = readUserinfo ? 'user_info' : `tokens.${tokenRef}`;
  return paths.map((p) => `${prefix}.${p}`);
};

const buildOidcOrgsExpr = (om: EnvOrganizationsManagement | undefined): string[] => {
  // Always populate with defaults — in the new model we never hide default paths.
  // Old default: organizations_path=['organizations'], token_reference='access_token', read_userinfo=false
  const paths = om?.organizations_path ?? ['organizations'];
  const readUserinfo = om?.read_userinfo ?? false;
  const tokenRef = om?.token_reference ?? 'access_token';
  const prefix = readUserinfo ? 'user_info' : `tokens.${tokenRef}`;
  return paths.map((p) => `${prefix}.${p}`);
};

export const convertOidcEnvConfig = (envKey: string, entry: EnvProviderEntry): ConvertedOidcProvider => {
  const ext = new ConfigExtractor(entry.config ?? {});
  const warnings: string[] = [];

  // Build base early so 'label' and 'disabled' are consumed before extra_conf collection
  const base = buildBaseInput(envKey, entry, ext);

  // -- First-class configuration fields (each .get() marks the key as consumed) --
  const issuer = ext.get<string>('issuer', '');
  const clientId = ext.get<string>('client_id', '');
  const clientSecret = ext.get<string | null>('client_secret', 'default');
  const audience = ext.get<string | null>('audience', null);
  const logoutRemote = ext.get<boolean>('logout_remote', false);
  const logoutCallbackUrl = ext.get<string | null>('logout_callback_url', null);
  const useProxy = ext.get<boolean>('use_proxy', false);

  // Callback URL — redirect_uris (OIDC standard) or callback_url (OpenCTI convention)
  // redirect_uris can be an array; if so, take the first element
  const rawRedirectUris = ext.get<string | string[] | null>('redirect_uris', null);
  const redirectUri = Array.isArray(rawRedirectUris) ? (rawRedirectUris[0] ?? null) : rawRedirectUris;
  const callbackUrl = ext.get<string | null>('callback_url', null) ?? redirectUri;
  // If callback_url is provided, it already contains the full routing path — no need for identifier_override
  if (callbackUrl) {
    base.identifier_override = null;
  }

  // Scopes: merge default + groups_scope + organizations_scope
  const defaultScopes = ext.get<string[]>('default_scopes', ['openid', 'email', 'profile']);
  const gm = ext.get<EnvGroupsManagement | undefined>('groups_management', undefined);
  const om = ext.get<EnvOrganizationsManagement | undefined>('organizations_management', undefined);
  const scopes = [...defaultScopes];
  if (gm?.groups_scope) scopes.push(gm.groups_scope);
  if (om?.organizations_scope) scopes.push(om.organizations_scope);
  const uniqueScopes = [...new Set(scopes)];

  // User info mapping
  const getFromIdToken = ext.get<boolean>('get_user_attributes_from_id_token', false);
  const userInfoPrefix = getFromIdToken ? 'tokens.id_token' : 'user_info';
  if (getFromIdToken) {
    warnings.push('get_user_attributes_from_id_token=true: user info expressions prefixed with "tokens.id_token" instead of "user_info".');
  }

  const userInfoMapping: UserInfoMappingInput = {
    email_expr: `${userInfoPrefix}.${ext.get<string>('email_attribute', 'email')}`,
    name_expr: `${userInfoPrefix}.${ext.get<string>('name_attribute', 'name')}`,
    firstname_expr: `${userInfoPrefix}.${ext.get<string>('firstname_attribute', 'given_name')}`,
    lastname_expr: `${userInfoPrefix}.${ext.get<string>('lastname_attribute', 'family_name')}`,
  };

  // Groups mapping
  const autoCreateGroup = ext.get<boolean>('auto_create_group', false);
  const preventDefaultGroups = ext.get<boolean>('prevent_default_groups', false);
  const groupsMapping: GroupsMappingInput = {
    auto_create_groups: autoCreateGroup,
    prevent_default_groups: preventDefaultGroups,
    default_groups: [],
    groups_expr: buildOidcGroupsExpr(gm),
    groups_mapping: convertMappingEntries(gm?.groups_mapping),
  };

  // Organizations mapping
  const organizationsDefault = ext.get<string[]>('organizations_default', []);
  const organizationsMapping: OrganizationsMappingInput = {
    auto_create_organizations: false,
    default_organizations: organizationsDefault,
    organizations_expr: buildOidcOrgsExpr(om),
    organizations_mapping: convertMappingEntries(om?.organizations_mapping),
  };

  // Deprecated / consumed-but-ignored
  if (ext.has('roles_management')) {
    ext.consume('roles_management');
    warnings.push('roles_management is deprecated and has been ignored.');
  }

  // -- Everything unconsumed goes to extra_conf --
  const extraConf = collectExtraConf(ext, warnings);

  const configuration: OidcConfigurationInput = {
    issuer,
    client_id: clientId,
    client_secret_cleartext: clientSecret,
    callback_url: callbackUrl,
    scopes: uniqueScopes,
    audience,
    logout_remote: logoutRemote,
    logout_callback_url: logoutCallbackUrl,
    use_proxy: useProxy,
    user_info_mapping: userInfoMapping,
    groups_mapping: groupsMapping,
    organizations_mapping: organizationsMapping,
    extra_conf: extraConf,
  };

  return {
    type: 'OIDC',
    base,
    configuration,
    warnings,
  };
};

// ---------------------------------------------------------------------------
// SAML conversion
// ---------------------------------------------------------------------------

export const convertSamlEnvConfig = (envKey: string, entry: EnvProviderEntry): ConvertedSamlProvider => {
  const ext = new ConfigExtractor(entry.config ?? {});
  const warnings: string[] = [];

  // Build base early so 'label' and 'disabled' are consumed before extra_conf collection
  const base = buildBaseInput(envKey, entry, ext);

  // -- First-class configuration fields --
  const issuer = ext.get<string>('issuer', '');
  const entryPoint = ext.get<string>('entry_point', '');
  const idpCertificate = ext.get<string>('cert', '');
  const privateKey = ext.get<string | null>('private_key', null);
  const logoutRemote = ext.get<boolean>('logout_remote', false);
  const wantAssertionsSigned = ext.get<boolean>('want_assertions_signed', false);
  const wantAuthnResponseSigned = ext.get<boolean>('want_authn_response_signed', false);
  const signingCert = ext.get<string | null>('signing_cert', null);
  const ssoBindingType = ext.get<string | null>('sso_binding_type', null);
  const forceAuthn = ext.get<boolean>('force_authn', false);

  // Promoted fields (previously in extra_conf, now first-class)
  const identifierFormat = ext.get<string | null>('identifier_format', null);
  const rawSignatureAlgorithm = ext.get<string | null>('signature_algorithm', null);
  const VALID_SIGNATURE_ALGORITHMS = ['sha1', 'sha256', 'sha512'];
  let signatureAlgorithm: string | null = rawSignatureAlgorithm;
  if (rawSignatureAlgorithm && !VALID_SIGNATURE_ALGORITHMS.includes(rawSignatureAlgorithm)) {
    warnings.push(`signature_algorithm "${rawSignatureAlgorithm}" is not valid (allowed: ${VALID_SIGNATURE_ALGORITHMS.join(', ')}). Falling back to null.`);
    signatureAlgorithm = null;
  }
  const digestAlgorithm = ext.get<string | null>('digest_algorithm', null);
  const rawAuthnContext = ext.get<string | string[] | null>('authn_context', null);
  const authnContext: string[] | null = rawAuthnContext
    ? (Array.isArray(rawAuthnContext) ? rawAuthnContext : [rawAuthnContext])
    : null;
  const disableRequestedAuthnContext = ext.get<boolean>('disable_requested_authn_context', false);
  const disableRequestAcsUrl = ext.get<boolean>('disable_request_acs_url', false);
  const skipRequestCompression = ext.get<boolean>('skip_request_compression', false);
  const decryptionPvk = ext.get<string | null>('decryption_pvk', null);
  const decryptionCert = ext.get<string | null>('decryption_cert', null);

  // Callback URL — if set in env config, store it as an override
  const samlCallbackUrl = ext.get<string | null>('saml_callback_url', null);
  const callbackUrl = ext.get<string | null>('callback_url', null);
  const resolvedCallbackUrl = samlCallbackUrl || callbackUrl;
  // If callback_url is provided, it already contains the full routing path — no need for identifier_override
  if (resolvedCallbackUrl) {
    base.identifier_override = null;
  }

  // User info mapping — SAML uses attribute names directly from SAML assertions
  const userInfoMapping: UserInfoMappingInput = {
    email_expr: ext.get<string>('mail_attribute', 'email'),
    name_expr: ext.get<string>('account_attribute', 'name'),
    firstname_expr: ext.get<string | null>('firstname_attribute', null),
    lastname_expr: ext.get<string | null>('lastname_attribute', null),
  };

  // Groups mapping: SAML uses group_attributes (attribute names in SAML assertion)
  // Always populate with defaults — old default: group_attributes=['groups']
  const autoCreateGroup = ext.get<boolean>('auto_create_group', false);
  const preventDefaultGroups = ext.get<boolean>('prevent_default_groups', false);
  const gm = ext.get<EnvGroupsManagement | undefined>('groups_management', undefined);
  const groupsExpr = gm?.group_attributes ?? ['groups'];
  const groupsMapping: GroupsMappingInput = {
    auto_create_groups: autoCreateGroup,
    prevent_default_groups: preventDefaultGroups,
    default_groups: [],
    groups_expr: groupsExpr,
    groups_mapping: convertMappingEntries(gm?.groups_mapping),
  };

  // Organizations mapping
  // Always populate with defaults — old default: organizations_path=['organizations']
  // In the old SAML code, organizations_path was used as R.path(orgaPath, profile) — the array
  // was the path segments (e.g. ['org', 'list'] → profile.org.list). In the new model, each
  // array element is a dot-separated expression resolved independently. So we join the old
  // array into a single dot-separated string.
  const om = ext.get<EnvOrganizationsManagement | undefined>('organizations_management', undefined);
  const organizationsDefault = ext.get<string[]>('organizations_default', []);
  const rawOrgPath = om?.organizations_path ?? ['organizations'];
  const organizationsMapping: OrganizationsMappingInput = {
    auto_create_organizations: false,
    default_organizations: organizationsDefault,
    organizations_expr: [rawOrgPath.join('.')],
    organizations_mapping: convertMappingEntries(om?.organizations_mapping),
  };

  // Deprecated / consumed-but-ignored
  if (ext.has('roles_management')) {
    ext.consume('roles_management');
    warnings.push('roles_management is deprecated and has been ignored.');
  }

  // -- Everything unconsumed goes to extra_conf (with camelCase remapping) --
  const extraConf = collectExtraConf(ext, warnings);

  const configuration: SamlConfigurationInput = {
    issuer,
    entry_point: entryPoint,
    idp_certificate: idpCertificate,
    private_key_cleartext: privateKey,
    callback_url: resolvedCallbackUrl,
    logout_remote: logoutRemote,
    want_assertions_signed: wantAssertionsSigned,
    want_authn_response_signed: wantAuthnResponseSigned,
    signing_cert: signingCert,
    sso_binding_type: ssoBindingType,
    force_reauthentication: forceAuthn,
    identifier_format: identifierFormat,
    signature_algorithm: signatureAlgorithm,
    digest_algorithm: digestAlgorithm,
    authn_context: authnContext,
    disable_requested_authn_context: disableRequestedAuthnContext,
    disable_request_acs_url: disableRequestAcsUrl,
    skip_request_compression: skipRequestCompression,
    decryption_pvk_cleartext: decryptionPvk,
    decryption_cert: decryptionCert,
    user_info_mapping: userInfoMapping,
    groups_mapping: groupsMapping,
    organizations_mapping: organizationsMapping,
    extra_conf: extraConf,
  };

  return {
    type: 'SAML',
    base,
    configuration,
    warnings,
  };
};

// ---------------------------------------------------------------------------
// LDAP conversion
// ---------------------------------------------------------------------------

export const convertLdapEnvConfig = (envKey: string, entry: EnvProviderEntry): ConvertedLdapProvider => {
  const ext = new ConfigExtractor(entry.config ?? {});
  const warnings: string[] = [];

  // Build base early so 'label' and 'disabled' are consumed before extra_conf collection
  const base = buildBaseInput(envKey, entry, ext);

  // -- First-class configuration fields --
  const url = ext.get<string>('url', '');
  const bindDn = ext.get<string>('bind_dn', '');
  const bindCredentials = ext.get<any>('bind_credentials', 'default');
  const searchBase = ext.get<string>('search_base', '');
  const searchFilter = ext.get<string>('search_filter', '(uid={{username}})');
  const groupSearchBase = ext.get<string>('group_search_base', '');
  const groupSearchFilter = ext.get<string>('group_search_filter', '');
  const allowSelfSigned = ext.get<any>('allow_self_signed', false);

  // Promoted fields (previously in extra_conf, now first-class)
  const searchAttributes = ext.get<string[] | null>('search_attributes', null);
  const usernameField = ext.get<string | null>('username_field', null);
  const passwordField = ext.get<string | null>('password_field', null);
  const credentialsLookup = ext.get<string | null>('credentials_lookup', null);
  const groupSearchAttributes = ext.get<string[] | null>('group_search_attributes', null);

  // User info mapping — LDAP uses direct attribute names on the LDAP user object
  const userInfoMapping: UserInfoMappingInput = {
    email_expr: ext.get<string>('mail_attribute', 'mail'),
    name_expr: ext.get<string>('account_attribute', 'givenName'),
    firstname_expr: ext.get<string | null>('firstname_attribute', null),
    lastname_expr: ext.get<string | null>('lastname_attribute', null),
  };

  // Groups mapping: LDAP uses group_attribute (attribute name in _groups entries, default 'cn')
  // Always populate with defaults — old default: group_attribute='cn'
  const autoCreateGroup = ext.get<boolean>('auto_create_group', false);
  const preventDefaultGroups = ext.get<boolean>('prevent_default_groups', false);
  const gm = ext.get<EnvGroupsManagement | undefined>('groups_management', undefined);
  const groupsExpr = [gm?.group_attribute ?? 'cn'];
  const groupsMapping: GroupsMappingInput = {
    auto_create_groups: autoCreateGroup,
    prevent_default_groups: preventDefaultGroups,
    default_groups: [],
    groups_expr: groupsExpr,
    groups_mapping: convertMappingEntries(gm?.groups_mapping),
  };

  // Organizations mapping
  // Always populate with defaults — old default: organizations_path=['organizations']
  const om = ext.get<EnvOrganizationsManagement | undefined>('organizations_management', undefined);
  const organizationsDefault = ext.get<string[]>('organizations_default', []);
  const organizationsMapping: OrganizationsMappingInput = {
    auto_create_organizations: false,
    default_organizations: organizationsDefault,
    organizations_expr: om?.organizations_path ?? ['organizations'],
    organizations_mapping: convertMappingEntries(om?.organizations_mapping),
  };

  // Deprecated / consumed-but-ignored
  if (ext.has('roles_management')) {
    ext.consume('roles_management');
    warnings.push('roles_management is deprecated and has been ignored.');
  }

  // -- Everything unconsumed goes to extra_conf (with camelCase remapping) --
  const extraConf = collectExtraConf(ext, warnings);

  const configuration: LdapConfigurationInput = {
    url,
    bind_dn: bindDn,
    bind_credentials_cleartext: bindCredentials ? String(bindCredentials) : null,
    search_base: searchBase,
    search_filter: searchFilter,
    group_base: groupSearchBase,
    group_filter: groupSearchFilter,
    allow_self_signed: allowSelfSigned === true || allowSelfSigned === 'true',
    search_attributes: searchAttributes,
    username_field: usernameField,
    password_field: passwordField,
    credentials_lookup: credentialsLookup,
    group_search_attributes: groupSearchAttributes,
    user_info_mapping: userInfoMapping,
    groups_mapping: groupsMapping,
    organizations_mapping: organizationsMapping,
    extra_conf: extraConf,
  };

  return {
    type: 'LDAP',
    base,
    configuration,
    warnings,
  };
};

// ---------------------------------------------------------------------------
// Deprecated strategies → OIDC conversion
// ---------------------------------------------------------------------------

/**
 * Well-known issuer URLs for deprecated OAuth2 strategies.
 * Google has a standard OIDC discovery endpoint.
 * Facebook and Github are OAuth2-only — the issuer is a placeholder
 * that the administrator MUST replace with a proper OIDC-compatible endpoint.
 */
const DEPRECATED_STRATEGY_DEFAULTS: Record<string, {
  issuer: string;
  scopes: string[];
  issuerIsPlaceholder: boolean;
  strategyLabel: string;
}> = {
  GoogleStrategy: {
    issuer: 'https://accounts.google.com',
    scopes: ['openid', 'email', 'profile'],
    issuerIsPlaceholder: false,
    strategyLabel: 'Google',
  },
  FacebookStrategy: {
    issuer: 'https://www.facebook.com',
    scopes: ['email'],
    issuerIsPlaceholder: true,
    strategyLabel: 'Facebook',
  },
  GithubStrategy: {
    issuer: 'https://github.com',
    scopes: ['user:email'],
    issuerIsPlaceholder: true,
    strategyLabel: 'Github',
  },
  Auth0Strategy: {
    issuer: '', // derived from config.domain
    scopes: ['openid', 'email', 'profile'],
    issuerIsPlaceholder: false,
    strategyLabel: 'Auth0',
  },
};

/**
 * Convert a deprecated OAuth2 strategy (Google, Facebook, Github, Auth0)
 * into the OIDC model. The config shape is simpler than full OIDC —
 * just client_id, client_secret, callback_url, and strategy-specific fields.
 */
export const convertDeprecatedToOidc = (envKey: string, entry: EnvProviderEntry): ConvertedOidcProvider => {
  const ext = new ConfigExtractor(entry.config ?? {});
  const warnings: string[] = [];
  const defaults = DEPRECATED_STRATEGY_DEFAULTS[entry.strategy];

  const strategyLabel = defaults?.strategyLabel ?? entry.strategy;
  warnings.push(
    `${strategyLabel} strategy is deprecated. This has been migrated to OIDC. Please verify the configuration.`,
  );

  // Build base (consumes label, disabled)
  const base = buildBaseInput(envKey, entry, ext);

  // Core OIDC fields — all deprecated strategies share client_id/client_secret
  const clientId = ext.get<string>('client_id', '');
  const clientSecret = ext.get<string | null>('client_secret', 'default');
  const logoutRemote = ext.get<boolean>('logout_remote', false);

  // Callback URL — redirect_uris (OIDC standard) or callback_url (OpenCTI convention)
  const rawRedirectUris = ext.get<string | string[] | null>('redirect_uris', null);
  const redirectUri = Array.isArray(rawRedirectUris) ? (rawRedirectUris[0] ?? null) : rawRedirectUris;
  const callbackUrl = ext.get<string | null>('callback_url', null) ?? redirectUri;
  // If callback_url is provided, it already contains the full routing path — no need for identifier_override
  if (callbackUrl) {
    base.identifier_override = null;
  }

  // Issuer: Auth0 derives from config.domain, others use well-known URLs
  let issuer: string;
  if (entry.strategy === 'Auth0Strategy') {
    const domain = ext.get<string>('domain', '');
    issuer = domain ? `https://${domain}` : '';
    if (!domain) {
      warnings.push('Auth0 "domain" is missing — issuer could not be derived. Set it manually.');
    }
    // Auth0-specific fields consumed as OIDC equivalents
    const scope = ext.get<string | null>('scope', null);
    const logoutUri = ext.get<string | null>('logout_uri', null);
    const useProxy = ext.get<boolean>('use_proxy', false);
    const baseURL = ext.get<string | null>('baseURL', null);
    // Auth0 also supports the legacy camelCase form
    ext.consume('clientID', 'clientSecret');

    const scopes = scope ? scope.split(/\s+/) : (defaults?.scopes ?? ['openid', 'email', 'profile']);

    const configuration: OidcConfigurationInput = {
      issuer,
      client_id: clientId,
      client_secret_cleartext: clientSecret,
      callback_url: callbackUrl,
      scopes,
      audience: null,
      logout_remote: logoutRemote,
      logout_callback_url: logoutUri ?? baseURL,
      use_proxy: useProxy,
      user_info_mapping: {
        email_expr: 'user_info.email',
        name_expr: 'user_info.name',
        firstname_expr: 'user_info.given_name',
        lastname_expr: 'user_info.family_name',
      },
      groups_mapping: { auto_create_groups: false, prevent_default_groups: false, default_groups: [], groups_expr: [], groups_mapping: [] },
      organizations_mapping: { auto_create_organizations: false, default_organizations: [], organizations_expr: [], organizations_mapping: [] },
      extra_conf: collectExtraConf(ext, warnings),
    };

    return { type: 'OIDC', base, configuration, warnings };
  }

  // Google / Facebook / Github
  issuer = defaults?.issuer ?? '';
  const scopes = defaults?.scopes ?? ['openid', 'email', 'profile'];

  if (defaults?.issuerIsPlaceholder) {
    warnings.push(
      `${strategyLabel} does not natively support OIDC discovery. `
      + `The issuer "${issuer}" is a placeholder. You may need to configure an OIDC-compatible proxy or switch to a generic OIDC provider.`,
    );
  }

  // Google-specific: domains restriction goes to extra_conf
  if (entry.strategy === 'GoogleStrategy') {
    ext.consume('domains'); // consumed, will appear in extra_conf if present via getUnconsumed
  }

  // Github-specific: organizations restriction goes to extra_conf
  if (entry.strategy === 'GithubStrategy') {
    ext.consume('organizations');
  }

  const extraConf = collectExtraConf(ext, warnings);

  // Re-add strategy-specific fields as extra_conf so administrators can see them
  // Arrays are stored as multiple entries with the same key
  if (entry.strategy === 'GoogleStrategy' && entry.config?.domains) {
    const domains = Array.isArray(entry.config.domains) ? entry.config.domains : [entry.config.domains];
    for (const d of domains) {
      extraConf.push({ type: ExtraConfEntryType.String, key: 'domains', value: String(d) });
    }
  }
  if (entry.strategy === 'GithubStrategy' && entry.config?.organizations) {
    const orgs = Array.isArray(entry.config.organizations) ? entry.config.organizations : [entry.config.organizations];
    for (const o of orgs) {
      extraConf.push({ type: ExtraConfEntryType.String, key: 'organizations', value: String(o) });
    }
  }

  const configuration: OidcConfigurationInput = {
    issuer,
    client_id: clientId,
    client_secret_cleartext: clientSecret,
    callback_url: callbackUrl,
    scopes,
    audience: null,
    logout_remote: logoutRemote,
    logout_callback_url: null,
    use_proxy: false,
    user_info_mapping: {
      email_expr: 'user_info.email',
      name_expr: 'user_info.name',
      firstname_expr: 'user_info.given_name',
      lastname_expr: 'user_info.family_name',
    },
    groups_mapping: { auto_create_groups: false, prevent_default_groups: false, default_groups: [], groups_expr: [], groups_mapping: [] },
    organizations_mapping: { auto_create_organizations: false, default_organizations: [], organizations_expr: [], organizations_mapping: [] },
    extra_conf: extraConf,
  };

  return { type: 'OIDC', base, configuration, warnings };
};

// ---------------------------------------------------------------------------
// Top-level dispatcher
// ---------------------------------------------------------------------------

export type ConversionResult
  = | { status: 'converted'; provider: ConvertedProvider }
    | { status: 'skipped'; reason: string }
    | { status: 'error'; reason: string };

/**
 * Convert a single env provider entry to the new GraphQL input format.
 * Pure function — no side effects.
 */
export const convertEnvProviderEntry = (envKey: string, entry: EnvProviderEntry): ConversionResult => {
  const { strategy, config } = entry;

  // Skip disabled entries
  if (config?.disabled === true) {
    return { status: 'skipped', reason: `Provider "${envKey}" is disabled.` };
  }

  switch (strategy) {
    case 'OpenIDConnectStrategy':
      return { status: 'converted', provider: convertOidcEnvConfig(envKey, entry) };
    case 'SamlStrategy':
      return { status: 'converted', provider: convertSamlEnvConfig(envKey, entry) };
    case 'LdapStrategy':
      return { status: 'converted', provider: convertLdapEnvConfig(envKey, entry) };
    // Singleton strategies — handled separately via Settings
    case 'LocalStrategy':
    case 'ClientCertStrategy':
    case 'HeaderStrategy':
      return { status: 'skipped', reason: `Strategy "${strategy}" is a singleton migrated via Settings, not AuthenticationProvider.` };
    // Deprecated strategies — migrated to OIDC with warnings
    case 'FacebookStrategy':
    case 'GoogleStrategy':
    case 'GithubStrategy':
    case 'Auth0Strategy':
      return { status: 'converted', provider: convertDeprecatedToOidc(envKey, entry) };
    default:
      return { status: 'error', reason: `Unknown strategy "${strategy}" for provider key "${envKey}".` };
  }
};

/**
 * Convert all env providers to the new format.
 * Deduplicates by resolved identifier — if two entries resolve to the same
 * identifier, only the first is kept; the duplicate is reported as an error.
 * Pure function — no side effects.
 */
export const convertAllEnvProviders = (
  envProviders: Record<string, EnvProviderEntry>,
): { envKey: string; result: ConversionResult }[] => {
  const results: { envKey: string; result: ConversionResult }[] = [];
  const seenIdentifiers = new Map<string, string>(); // identifier → first envKey

  for (const [envKey, entry] of Object.entries(envProviders)) {
    const result = convertEnvProviderEntry(envKey, entry);

    // Deduplicate converted providers by resolved identifier
    if (result.status === 'converted') {
      const identifier = result.provider.base.identifier_override ?? envKey;
      const existingEnvKey = seenIdentifiers.get(identifier);
      if (existingEnvKey !== undefined) {
        results.push({
          envKey,
          result: {
            status: 'error',
            reason: `Duplicate identifier "${identifier}": already used by env key "${existingEnvKey}". Only the first entry will be migrated.`,
          },
        });
        continue;
      }
      seenIdentifiers.set(identifier, envKey);
    }

    results.push({ envKey, result });
  }

  return results;
};
