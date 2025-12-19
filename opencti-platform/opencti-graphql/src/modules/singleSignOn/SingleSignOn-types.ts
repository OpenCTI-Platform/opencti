import type { StixObject } from '../../types/stix-2-1-common';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import { StrategyType } from '../../config/providers-configuration';

export const ENTITY_TYPE_SINGLE_SIGN_ON = "SingleSignOn";

export interface ConfigurationType {
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

// # Examples : declare here specific keys for each type of SSO
// SAML keys from notion :
// Page : SSO in GUI - Overall task => resources => "List of fields to be included in each Auth Type"
export const SAML_CONFIGURATION_MANDATORY_KEY_LIST = ['name', 'label', 'issuer', 'cert', 'saml_callback_url', 'entry_point'];
// export const LDAP_CONFIGURATION_KEY_LIST = [];
export const CONFIGURATION_MANDATORY_KEY_LIST = {
  [StrategyType.STRATEGY_SAML]: SAML_CONFIGURATION_MANDATORY_KEY_LIST,
  // [StrategyType.STRATEGY_LDAP]: LDAP_CONFIGURATION_KEY_LIST,
  // [...]
}

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