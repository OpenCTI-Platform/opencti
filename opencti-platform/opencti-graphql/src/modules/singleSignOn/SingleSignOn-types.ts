import type { StixObject } from '../../types/stix-2-1-common';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import { StrategyType } from '../../config/providers-configuration';

export const ENTITY_TYPE_SINGLE_SIGN_ON = "SingleSignOn";
// export const ENTITY_TYPE_SAML_AUTH = "SAMLAuth";
// export const ENTITY_TYPE_OPENID_AUTH = "OPENIDAuth";
// export const ENTITY_TYPE_LDAP_AUTH = "LDAPAuth";
// export const ENTITY_TYPE_AUTH0_AUTH = "AUTH0Auth";
//
// export const AUTH_ENTITY_TYPE_LIST = [
//   ENTITY_TYPE_SAML_AUTH,
//   ENTITY_TYPE_OPENID_AUTH,
//   ENTITY_TYPE_LDAP_AUTH,
//   ENTITY_TYPE_AUTH0_AUTH,
// ];

interface ConfigurationType {
  key: string;
  value: string;
  type: string;
}

interface OrganizationsManagement {
  organizations_path: string[];
  organizations_mapping: string[];
}

interface GroupsManagement {
  groups_attributes: string[];
  groups_path: string[];
  groups_mapping: string[];
  read_userinfo: boolean;
}

export enum StatusScopeEnum {
  SAML = 'SAML',
  REQUEST_ACCESS = 'REQUEST_ACCESS',
}

const SAML_CONFIGURATION_KEY_LIST = ["myKey"]
const OPENID_CONFIGURATION_KEY_LIST = ["myKey"]
const LDAP_CONFIGURATION_KEY_LIST = ["myKey"]

export interface BasicStoreEntitySingleSignOn extends BasicStoreEntity {
  name: string;
  description: string;
  created_at: Date;
  updated_at: Date;
  enabled: boolean;
  strategy: StrategyType
  label?: string;
  auto_create_group?: boolean;
  prevent_default_groups?: boolean;
  logout_remote?: boolean;
  organizations_management?: OrganizationsManagement[];
  groups_management?: GroupsManagement[];
  configuration?: ConfigurationType[];
  advanced_configuration?: ConfigurationType[];
}

export interface StoreEntitySingleSignOn extends StoreEntity {
  name: string;
  description: string;
  created_at: Date;
  updated_at: Date;
  enabled: boolean;
  strategy: StrategyType
  label?: string;
  auto_create_group?: boolean;
  prevent_default_groups?: boolean;
  logout_remote?: boolean;
  organizations_management?: OrganizationsManagement[];
  groups_management?: GroupsManagement[];
  configuration?: ConfigurationType[];
  advanced_configuration?: ConfigurationType[];
}

export interface StixSingleSignOn extends StixObject {
  name: string;
  description: string;
  enabled: boolean;
  strategy: StrategyType
  label?: string;
}

// interface BasicSingleSignOnEntity extends BasicAuthEntity {
//   label: string;
//   issuer: string;
//   auto_create_group: boolean;
//   prevent_default_groups: boolean;
//   logout_remote: boolean;
//   organizations_management: OrganizationsManagement[];
//   groups_management: GroupsManagement[];
//   configuration: ConfigurationType[];
//   advanced_configuration: ConfigurationType[];
// }
//
// interface StoreSingleSignOnEntity extends StoreAuthEntity {
//   label: string;
//   issuer: string;
//   auto_create_group: boolean;
//   prevent_default_groups: boolean;
//   logout_remote: boolean;
//   organizations_management: OrganizationsManagement[];
//   groups_management: GroupsManagement[];
//   configuration: ConfigurationType[];
//   advanced_configuration: ConfigurationType[];
// }

// export interface BasicSAMLAuthEntity extends BasicSingleSignOnEntity {
//   entry_point: string;
//   saml_callback_url: string;
//   cert: string;
//   want_assertions_signed: boolean;
//   want_authn_response_signed: boolean;
//   audience: boolean;
// }
// export interface StoreSAMLAuthEntity extends StoreSingleSignOnEntity {
//   entry_point: string;
//   saml_callback_url: string;
//   cert: string;
//   want_assertions_signed: boolean;
//   want_authn_response_signed: boolean;
//   audience: boolean;
// }
//
// export interface BasicOPENIDAuthEntity extends BasicSingleSignOnEntity {
//   client_id: string;
//   client_secret: string;
//   redirect_uris: string[];
// }
// export interface StoreOPENIDAuthEntity extends StoreSingleSignOnEntity {
//   client_id: string;
//   client_secret: string;
//   redirect_uris: string[];
// }
//
// export interface BasicAuth0Entity extends BasicSingleSignOnEntity {
//   clientID: string;
//   baseURL: string;
//   clientSecret: string;
//   callback_url: string;
//   scope: string;
//   domain: string;
//   logout_uri: string;
// }
// export interface StoreAuth0Entity extends StoreSingleSignOnEntity {
//   clientID: string;
//   baseURL: string;
//   clientSecret: string;
//   callback_url: string;
//   scope: string;
//   domain: string;
//   logout_uri: string;
// }
//
// export interface BasicLDAPAuthEntity extends BasicSingleSignOnEntity {
//   url: string;
//   bind_dn: string;
//   bind_credentials: string;
//   search_base: string;
//   search_filter: string;
//   mail_attribute: string;
//   account_attribute: string;
//   firstname_attribute: string;
//   allow_self_signed: boolean;
// }
// export interface StoreLDAPAuthEntity extends StoreSingleSignOnEntity {
//   url: string;
//   bind_dn: string;
//   bind_credentials: string;
//   search_base: string;
//   search_filter: string;
//   mail_attribute: string;
//   account_attribute: string;
//   firstname_attribute: string;
//   allow_self_signed: boolean;
// }

// export type BasicSingleSignOnEntityList = BasicSAMLAuthEntity | BasicOPENIDAuthEntity | BasicAuth0Entity | BasicLDAPAuthEntity;
// export type StoreSingleSignOnEntityList = StoreSAMLAuthEntity | StoreOPENIDAuthEntity | StoreAuth0Entity | StoreLDAPAuthEntity;