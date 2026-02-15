import type { StixObject } from '../../types/stix-2-1-common';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StrategyType } from '../../generated/graphql';

export const ENTITY_TYPE_SINGLE_SIGN_ON = 'SingleSignOn';

export interface ConfigurationType {
  key: string;
  value: string;
  type: string;
}

export interface OrganizationsManagement {
  organizations_path?: string[];
  organizations_mapping: string[];
  token_reference?: string;
  read_userinfo?: boolean;
  organizations_splitter?: string;
  organizations_header?: string;
}

export interface GroupsManagement {
  group_attributes?: string[];
  group_attribute?: string;
  groups_path?: string[];
  groups_mapping: string[];
  read_userinfo?: boolean;
  token_reference?: string;
  groups_splitter?: string;
  groups_header?: string;
}

export interface BasicStoreEntitySingleSignOn extends BasicStoreEntity {
  name: string;
  identifier: string;
  description: string;
  enabled: boolean;
  strategy: StrategyType;
  label?: string;
  organizations_management?: OrganizationsManagement;
  groups_management?: GroupsManagement;
  configuration?: ConfigurationType[];
}

export interface StoreEntitySingleSignOn extends StoreEntity {
  name: string;
  identifier: string;
  description: string;
  enabled: boolean;
  strategy: StrategyType;
  label?: string;
  organizations_management?: OrganizationsManagement;
  groups_management?: GroupsManagement;
  configuration?: ConfigurationType[];
}

export interface StixSingleSignOn extends StixObject {
  name: string;
  identifier: string;
  description: string;
  enabled: boolean;
  strategy: StrategyType;
  label?: string;
}
