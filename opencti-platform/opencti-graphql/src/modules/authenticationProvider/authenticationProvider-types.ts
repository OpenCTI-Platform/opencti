import type { StixObject } from '../../types/stix-2-1-common';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import { AuthenticationProviderType, ExtraConfEntryType, type LdapConfiguration, type OidcConfiguration, type SamlConfiguration } from '../../generated/graphql';

export const ENTITY_TYPE_AUTHENTICATION_PROVIDER = 'AuthenticationProvider';

// Mapping configuration
export interface UserInfoMapping {
  email_expr: string; // eg 'user_info/email'
  name_expr: string; // eg 'user_info/username'
  firstname_expr?: string; // eg 'user_info/given_name'
  lastname_expr?: string; // eg 'user_info/family_name'
}

export interface GroupsMapping {
  default_groups: string[];
  groups_expr: string[];
  groups_mapping: { provider: string; platform: string }[];
  auto_create_group: boolean;
}

export interface OrganizationsMapping {
  default_organizations: string[];
  organizations_expr: string[];
  organizations_mapping: { provider: string; platform: string }[];
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

interface ProviderConfiguration {
  name: string;
  identifier: string;
}

// OIDC configuration
export const oidcSecretFields = ['client_secret'];

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

export type OidcProviderConfiguration = ProviderConfiguration & OidcCommonConfiguration & {
  client_secret: string;
  extra_conf: { [extraKey: string]: unknown };
};

// SAML configuration
export const samlSecretFields = ['private_key'];

type SamlCommonConfiguration = MappingConfiguration & {
  issuer: string;
  entry_point: string;
  idp_certificate: string;
  callback_url: string;
  logout_remote: boolean;
};

export type SamlStoreConfiguration = SamlCommonConfiguration & {
  private_key_encrypted: string;
  extra_conf: ExtraConfEntry[];
};

export type SamlProviderConfiguration = ProviderConfiguration & SamlCommonConfiguration & {
  private_key: string;
  extra_conf: { [extraKey: string]: unknown };
};

// LDAP configuration
export const ldapSecretFields = ['bind_credentials'];

export type LdapCommonConfiguration = MappingConfiguration & {
  url: string;
  bind_dn: string;
  search_base: string;
  search_filter: string;
  group_base: string;
  group_filter: string;
  allow_self_signed: boolean;
};

export type LdapStoreConfiguration = LdapCommonConfiguration & {
  bind_credentials_encrypted: string;
  extra_conf: ExtraConfEntry[];
};

export type LdapProviderConfiguration = ProviderConfiguration & LdapCommonConfiguration & {
  bind_credentials: string;
  extra_conf: { [extraKey: string]: unknown };
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
  organizations_management?: OrganizationsMapping; // TODO
  groups_management?: GroupsMapping; // TODO
}

export interface StoreEntityAuthenticationProvider<T = OidcConfiguration | SamlConfiguration | LdapConfiguration> extends StoreEntity {
  name: string;
  description: string;
  enabled: boolean;
  button_label_override?: string;
  identifier_override?: string;
  type: AuthenticationProviderType;
  configuration: T;
  organizations_management?: OrganizationsMapping; // TODO
  groups_management?: GroupsMapping; // TODO
}

export interface StixAuthenticationProvider extends StixObject {
  name: string;
  description: string;
  enabled: boolean;
  button_label_override?: string;
  identifier_override?: string;
}
