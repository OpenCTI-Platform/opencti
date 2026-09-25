import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { AuthContext, AuthUser } from '../../types/user';
import type { ConnectorContractConfiguration, ConnectorPriorityGroup } from '../../generated/graphql';
import type { BasicStoreEntityCsvMapper } from '../internal/csvMapper/csvMapper-types';
import type { CatalogContractEntityFields } from '../catalog/catalog-types';

export interface ConnectorInfo {
  run_and_terminate: boolean;
  buffering: boolean;
  queue_threshold: number;
  queue_messages_size: number;
  next_run_datetime: Date | string;
  last_run_datetime: Date | string;
}

type ConnectorManagerContract = CatalogContractEntityFields;

export interface BasicStoreEntityConnector extends BasicStoreEntity {
  active: boolean;
  auto: boolean;
  auto_update: boolean;
  enrichment_resolution: string;
  only_contextual: boolean;
  connector_type: string;
  connector_scope: string;
  connector_state: string;
  connector_state_reset: boolean;
  connector_trigger_filters: string;
  connector_user_id: string;
  connector_info: ConnectorInfo;
  playbook_compatible: boolean;
  xtm_one_intent: string | null;
  // region composer (set only on composer-managed connectors)
  catalog_id?: string;
  manager_contract_image?: string;
  manager_contract_configuration?: ConnectorContractConfiguration[];
  manager_contract?: ConnectorManagerContract;
  manager_upgrade_strategy?: string;
  // endregion
}

export interface StoreEntityConnector extends StoreEntity {
  active: boolean;
  auto: boolean;
  auto_update: boolean;
  enrichment_resolution: string;
  only_contextual: boolean;
  connector_type: string;
  connector_scope: string;
  connector_state: string;
  connector_state_reset: boolean;
  connector_trigger_filters: string;
  connector_user_id: string;
  connector_info: ConnectorInfo;
  playbook_compatible: boolean;
  xtm_one_intent: string | null;
  // region composer (set only on composer-managed connectors)
  catalog_id?: string;
  manager_contract_image?: string;
  manager_contract_configuration?: ConnectorContractConfiguration[];
  manager_contract?: ConnectorManagerContract;
  manager_upgrade_strategy?: string;
  // endregion
}

export interface BasicStoreEntityConnectorManager extends BasicStoreEntity {
  public_key: string;
}

export interface StoreEntityConnectorManager extends StoreEntity {
  public_key: string;
}

export interface ConnectorConfig {
  id: string;
  name: string;
  config: {
    enable: boolean;
    validate_before_import: boolean;
  };
}

export interface InternalConnector {
  id: string;
  internal_id: string;
  active: boolean;
  auto: boolean;
  connector_scope: string;
  connector_type: string;
  connector_priority_group?: ConnectorPriorityGroup;
  name: string;
  built_in: boolean;
  connector_schema_runtime_fn?: <T extends BasicStoreEntityCsvMapper> (context: AuthContext, user: AuthUser) => Promise<T[]>;
}
