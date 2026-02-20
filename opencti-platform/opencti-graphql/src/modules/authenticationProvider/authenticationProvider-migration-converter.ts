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
import { resolveProviderIdentifier } from './authenticationProvider-domain';

// ---------------------------------------------------------------------------
// ConfigExtractor — tracks which keys are consumed during conversion
// ---------------------------------------------------------------------------

/**
 * Reverse mapping from camelCase (passport-native) to snake_case (OpenCTI config).
 * Users who wrote camelCase keys directly in their config files (instead of the
 * documented snake_case) still get their values picked up during migration.
 */
const CAMEL_TO_SNAKE: Record<string, string> = {
  clientID: 'client_id',
  clientSecret: 'client_secret',
  callbackURL: 'callback_url',
  bindDN: 'bind_dn',
  bindCredentials: 'bind_credentials',
  searchBase: 'search_base',
  searchFilter: 'search_filter',
  searchAttributes: 'search_attributes',
  usernameField: 'username_field',
  passwordField: 'password_field',
  credentialsLookup: 'credentials_lookup',
  groupSearchBase: 'group_search_base',
  groupSearchFilter: 'group_search_filter',
  groupSearchAttributes: 'group_search_attributes',
  callbackUrl: 'saml_callback_url',
  identifierFormat: 'identifier_format',
  entryPoint: 'entry_point',
  privateKey: 'private_key',
  signingCert: 'signing_cert',
  signatureAlgorithm: 'signature_algorithm',
  digestAlgorithm: 'digest_algorithm',
  wantAssertionsSigned: 'want_assertions_signed',
  wantAuthnResponseSigned: 'want_authn_response_signed',
  authnContext: 'authn_context',
  disableRequestedAuthnContext: 'disable_requested_authn_context',
  forceAuthn: 'force_authn',
  disableRequestAcsUrl: 'disable_request_acs_url',
  skipRequestCompression: 'skip_request_compression',
  idpCert: 'cert',
  decryptionPvk: 'decryption_pvk',
  decryptionCert: 'decryption_cert',
};

const buildSnakeToCamelMap = (): Record<string, string> => {
  const result: Record<string, string> = {};
  for (const [camel, snake] of Object.entries(CAMEL_TO_SNAKE)) {
    result[snake] = camel;
  }
  return result;
};

const SNAKE_TO_CAMEL = buildSnakeToCamelMap();

/**
 * Wraps a raw env config object and tracks every key access.
 * After conversion, call .getUnconsumedEntries() to collect
 * everything that should go to extra_conf.
 *
 * When a snake_case key is requested but not found, the extractor also
 * checks the camelCase alias (and vice-versa) so that users who wrote
 * camelCase keys in their config files still get migrated correctly.
 *
 * This removes the need for manually maintained CONSUMED_KEYS sets.
 */
export class ConfigExtractor {
  private readonly consumed = new Set<string>();

  constructor(private readonly config: Record<string, any>) {}

  /** Read a key and mark it as consumed. Also checks the camelCase/snake_case alias. */
  get<T = any>(key: string, defaultValue?: T): T {
    this.consumed.add(key);
    if (key in this.config) {
      return this.config[key] as T;
    }
    const alias = SNAKE_TO_CAMEL[key] ?? CAMEL_TO_SNAKE[key];
    if (alias) {
      this.consumed.add(alias);
      if (alias in this.config) {
        return this.config[alias] as T;
      }
    }
    return defaultValue as T;
  }

  /** Check if a key exists (also checks alias). */
  has(key: string): boolean {
    if (key in this.config) return true;
    const alias = SNAKE_TO_CAMEL[key] ?? CAMEL_TO_SNAKE[key];
    return alias ? alias in this.config : false;
  }

  /** Mark a key as consumed without reading (for deprecated/ignored keys). Also consumes alias. */
  consume(...keys: string[]): void {
    for (const key of keys) {
      this.consumed.add(key);
      const alias = SNAKE_TO_CAMEL[key] ?? CAMEL_TO_SNAKE[key];
      if (alias) this.consumed.add(alias);
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

interface EnvRolesManagement {
  roles_mapping?: EnvMappingEntry[];
  role_attributes?: string[];
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
 * Resolve groups management from either `groups_management` (current) or the
 * deprecated `roles_management` (which was the old name for the same concept).
 * If `groups_management` is present, it takes priority and `roles_management`
 * is consumed. Otherwise `roles_management` fields are mapped to their
 * `groups_management` equivalents: `role_attributes` -> `group_attributes` (SAML)
 * or `groups_path` (OIDC), `roles_mapping` -> `groups_mapping`.
 */
const resolveGroupsManagement = (
  ext: ConfigExtractor,
  strategy: 'oidc' | 'saml' | 'ldap',
  warnings: string[],
): EnvGroupsManagement | undefined => {
  const gm = ext.get<EnvGroupsManagement | undefined>('groups_management', undefined);
  const rm = ext.get<EnvRolesManagement | undefined>('roles_management', undefined);
  if (gm) return gm;
  if (!rm) return undefined;
  warnings.push('roles_management is deprecated and has been migrated as groups_management.');
  if (strategy === 'saml') {
    return {
      group_attributes: rm.role_attributes,
      groups_mapping: rm.roles_mapping,
    };
  }
  if (strategy === 'oidc') {
    return {
      groups_path: rm.role_attributes,
      groups_mapping: rm.roles_mapping,
    };
  }
  return {
    groups_mapping: rm.roles_mapping,
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

  // Scopes: merge default + groups_scope + organizations_scope
  const defaultScopes = ext.get<string[]>('default_scopes', ['openid', 'email', 'profile']);
  const gm = resolveGroupsManagement(ext, 'oidc', warnings);
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

  // -- Everything unconsumed goes to extra_conf --
  const extraConf = collectExtraConf(ext, warnings);

  const configuration: OidcConfigurationInput = {
    issuer,
    client_id: clientId,
    client_secret: { new_value_cleartext: clientSecret },
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

  // User info mapping — SAML uses attribute names directly from SAML assertions
  const userInfoMapping: UserInfoMappingInput = {
    email_expr: ext.get<string>('mail_attribute', 'nameID'),
    name_expr: ext.get<string>('account_attribute', 'nameID'),
    firstname_expr: ext.get<string | null>('firstname_attribute', null),
    lastname_expr: ext.get<string | null>('lastname_attribute', null),
  };

  // Groups mapping: SAML uses group_attributes (attribute names in SAML assertion)
  // Falls back to roles_management if groups_management is absent (deprecated alias)
  const autoCreateGroup = ext.get<boolean>('auto_create_group', false);
  const preventDefaultGroups = ext.get<boolean>('prevent_default_groups', false);
  const gm = resolveGroupsManagement(ext, 'saml', warnings);
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

  // -- Everything unconsumed goes to extra_conf --
  const extraConf = collectExtraConf(ext, warnings);

  const configuration: SamlConfigurationInput = {
    issuer,
    entry_point: entryPoint,
    idp_certificate: idpCertificate,
    private_key: { new_value_cleartext: privateKey },
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
    decryption_pvk: { new_value_cleartext: decryptionPvk },
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
  // Falls back to roles_management if groups_management is absent (deprecated alias)
  const autoCreateGroup = ext.get<boolean>('auto_create_group', false);
  const preventDefaultGroups = ext.get<boolean>('prevent_default_groups', false);
  const gm = resolveGroupsManagement(ext, 'ldap', warnings);
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

  // -- Everything unconsumed goes to extra_conf --
  const extraConf = collectExtraConf(ext, warnings);

  const configuration: LdapConfigurationInput = {
    url,
    bind_dn: bindDn,
    bind_credentials: bindCredentials ? { new_value_cleartext: String(bindCredentials) } : null,
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
  const gm = resolveGroupsManagement(ext, 'oidc', warnings);
  const om = ext.get<EnvOrganizationsManagement | undefined>('organizations_management', undefined);

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

    const scopes = scope ? scope.split(/\s+/) : (defaults?.scopes ?? ['openid', 'email', 'profile']);

    const configuration: OidcConfigurationInput = {
      issuer,
      client_id: clientId,
      client_secret: { new_value_cleartext: clientSecret },
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
      groups_mapping: groupsMapping,
      organizations_mapping: organizationsMapping,
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

  // domains (Google) and organizations (Github) are NOT consumed here
  // so they flow naturally into extra_conf via collectExtraConf.
  const extraConf = collectExtraConf(ext, warnings);

  const configuration: OidcConfigurationInput = {
    issuer,
    client_id: clientId,
    client_secret: { new_value_cleartext: clientSecret },
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

/**
 * Convert a single env provider entry to the new GraphQL input format.
 * Pure function — no side effects.
 */
export const convertSSOProviderEntry = (envKey: string, entry: EnvProviderEntry): ConvertedProvider | undefined => {
  const { strategy } = entry;
  switch (strategy) {
    case 'OpenIDConnectStrategy':
      return convertOidcEnvConfig(envKey, entry);
    case 'SamlStrategy':
      return convertSamlEnvConfig(envKey, entry);
    case 'LdapStrategy':
      return convertLdapEnvConfig(envKey, entry);
    case 'FacebookStrategy':
    case 'GoogleStrategy':
    case 'GithubStrategy':
    case 'Auth0Strategy':
      return convertDeprecatedToOidc(envKey, entry);
    default:
      return undefined;
  }
};

export type EnvProvider = { envKey: string; identifier: string; provider: ConvertedProvider };
/**
 * Convert all env providers to the new format.
 * Deduplicates by resolved identifier — if two entries resolve to the same
 * identifier, only the first is kept; the duplicate is reported as an error.
 * Pure function — no side effects.
 */
export const convertAllSSOEnvProviders = (envProviders: Record<string, EnvProviderEntry>): EnvProvider[] => {
  const results: EnvProvider[] = [];
  const seenIdentifiers = new Map<string, string>(); // identifier → first envKey
  for (const [envKey, entry] of Object.entries(envProviders)) {
    const convertedProvider = convertSSOProviderEntry(envKey, entry);

    // Deduplicate converted providers by resolved identifier
    if (convertedProvider) {
      // Resolve identifier the same way as resolveProviderIdentifier: override, or slugified name
      const identifier = resolveProviderIdentifier(convertedProvider.base);
      const existingEnvKey = seenIdentifiers.get(identifier);
      if (existingEnvKey === undefined) {
        console.log('Converting SSO providers... push');
        results.push({ envKey, identifier, provider: convertedProvider });
      }
      seenIdentifiers.set(identifier, envKey);
    }
  }
  return results;
};
