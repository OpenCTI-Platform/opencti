import type { StixObject } from '../../types/stix-2-1-common';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import { AuthenticationProviderType, ExtraConfEntryType, type LdapConfiguration, type OidcConfiguration, type SamlConfiguration } from '../../generated/graphql';

export const ENTITY_TYPE_AUTHENTICATION_PROVIDER = 'AuthenticationProvider';

// Mapping configuration
//
// All _expr fields use dot-separated notation (e.g. 'user_info.email', 'tokens.access_token.groups').
// Resolution splits on '.' and traverses the path: resolvePath(root, expr.split('.'))
//
// OIDC:  context = { tokens: fn(name), user_info: fn() } — paths like 'user_info.email' or 'tokens.id_token.sub'
// SAML:  context = profile.attributes ?? profile — paths like 'email' (flat) or 'org.list' (nested)
// LDAP user_info: special case — uses direct property access user[expr] (simple attribute name)
// LDAP groups:    special case — iterates user._groups entries and reads g[expr] (simple attribute name)
// LDAP orgs:      uses dot-separated paths on the user object: resolvePath(user, expr.split('.'))
export interface UserInfoMapping {
  email_expr: string; // dot-separated path, e.g. 'user_info.email' (OIDC) or 'mail' (LDAP)
  name_expr: string; // dot-separated path, e.g. 'user_info.name' (OIDC) or 'givenName' (LDAP)
  firstname_expr?: string; // dot-separated path, e.g. 'user_info.given_name'
  lastname_expr?: string; // dot-separated path, e.g. 'user_info.family_name'
}

export interface GroupsMapping {
  default_groups: string[];
  groups_expr: string[]; // each element is a dot-separated expression resolved against the provider context
  group_splitter?: string | undefined;
  groups_mapping: { provider: string; platform: string }[];
  auto_create_groups: boolean;
  prevent_default_groups: boolean;
}

export interface OrganizationsMapping {
  default_organizations: string[];
  organizations_expr: string[]; // each element is a dot-separated expression resolved against the provider context
  organizations_splitter?: string | undefined;
  organizations_mapping: { provider: string; platform: string }[];
  auto_create_organizations: boolean;
}

export type MappingConfiguration = {
  user_info_mapping: UserInfoMapping;
  groups_mapping: GroupsMapping;
  organizations_mapping: OrganizationsMapping;
};

// Extra configuration
export interface ExtraConfEntry {
  type: ExtraConfEntryType;
  key: string;
  value: string;
}

// Common configuration for all providers

export interface ProviderMeta {
  name: string;
  identifier: string;
}

// OIDC configuration
export const oidcSecretFields = [{ key: 'client_secret', mandatory: true }];

type OidcCommonConfiguration = MappingConfiguration & {
  issuer: string;
  client_id: string;
  scopes: string[];
  audience?: string;
  callback_url?: string;
  logout_remote: boolean;
  logout_callback_url?: string;
  use_proxy: boolean;
};

export type OidcStoreConfiguration = OidcCommonConfiguration & {
  client_secret_encrypted: string;
  extra_conf: ExtraConfEntry[];
};

// SAML configuration
export const samlSecretFields = [
  { key: 'private_key', mandatory: true },
  { key: 'decryption_pvk', mandatory: false },
];

type SamlCommonConfiguration = MappingConfiguration & {
  issuer: string;
  entry_point: string;
  idp_certificate: string;
  callback_url?: string;
  logout_remote: boolean;
  want_assertions_signed: boolean;
  want_authn_response_signed: boolean;
  signing_cert?: string;
  sso_binding_type: string;
  force_reauthentication: boolean;
  identifier_format?: string;
  signature_algorithm?: 'sha1' | 'sha256' | 'sha512';
  digest_algorithm?: string;
  authn_context?: string[];
  disable_requested_authn_context: boolean;
  disable_request_acs_url: boolean;
  skip_request_compression: boolean;
  decryption_cert?: string;
};

export type SamlStoreConfiguration = SamlCommonConfiguration & {
  private_key_encrypted: string;
  decryption_pvk_encrypted?: string;
  extra_conf: ExtraConfEntry[];
};

// LDAP configuration
export const ldapSecretFields = [{ key: 'bind_credentials', mandatory: false }];

export type LdapCommonConfiguration = MappingConfiguration & {
  url: string;
  bind_dn: string;
  search_base: string;
  search_filter: string;
  group_base: string;
  group_filter: string;
  allow_self_signed: boolean;
  search_attributes?: string[];
  username_field?: string;
  password_field?: string;
  credentials_lookup?: string;
  group_search_attributes?: string[];
};

export type LdapStoreConfiguration = LdapCommonConfiguration & {
  bind_credentials_encrypted: string;
  extra_conf: ExtraConfEntry[];
};

export type AuthenticationProviderStoreConfiguration = OidcStoreConfiguration | SamlStoreConfiguration | LdapStoreConfiguration;

export interface BasicStoreEntityAuthenticationProvider<T extends AuthenticationProviderStoreConfiguration | unknown = unknown> extends BasicStoreEntity {
  name: string;
  description: string;
  enabled: boolean;
  button_label_override?: string;
  identifier_override?: string;
  type: AuthenticationProviderType;
  configuration: T;
}

export interface StoreEntityAuthenticationProvider<T = OidcConfiguration | SamlConfiguration | LdapConfiguration> extends StoreEntity {
  name: string;
  description: string;
  enabled: boolean;
  button_label_override?: string;
  identifier_override?: string;
  type: AuthenticationProviderType;
  configuration: T;
}

export interface StixAuthenticationProvider extends StixObject {
  name: string;
  description: string;
  enabled: boolean;
  button_label_override?: string;
  identifier_override?: string;
}
