import type { StixObject } from '../../types/stix-2-1-common';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StrategyType } from '../../generated/graphql';

export const ENTITY_TYPE_SINGLE_SIGN_ON = 'SingleSignOn';

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

export interface BasicStoreEntitySingleSignOn extends BasicStoreEntity {
  name: string;
  description: string;
  enabled: boolean;
  strategy: StrategyType;
  label?: string;
  auto_create_group?: boolean;
  prevent_default_groups?: boolean;
  logout_remote?: boolean;
  organizations_management?: OrganizationsManagement;
  groups_management?: GroupsManagement;
  configuration?: ConfigurationType[];
  advanced_configuration?: ConfigurationType[];
}

export interface StoreEntitySingleSignOn extends StoreEntity {
  name: string;
  description: string;
  enabled: boolean;
  strategy: StrategyType;
  label?: string;
  auto_create_group?: boolean;
  prevent_default_groups?: boolean;
  logout_remote?: boolean;
  organizations_management?: OrganizationsManagement;
  groups_management?: GroupsManagement;
  configuration?: ConfigurationType[];
  advanced_configuration?: ConfigurationType[];
}

export interface StixSingleSignOn extends StixObject {
  name: string;
  description: string;
  enabled: boolean;
  strategy: StrategyType;
  label?: string;
}
