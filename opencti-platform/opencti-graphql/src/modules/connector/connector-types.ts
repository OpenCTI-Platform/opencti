import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { AuthContext, AuthUser } from '../../types/user';
import type { ConnectorContractConfiguration, ConnectorPriorityGroup } from '../../generated/graphql';
import type { BasicStoreEntityCsvMapper } from '../internal/csvMapper/csvMapper-types';
import type { CatalogContractEntityFields } from '../catalog/catalog-types';
import type { IngestionHealthFields } from '../ingestionHealth/ingestionHealth-types';

// A running connector pings regularly: a heartbeat older than this means it is down
export const CONNECTOR_LIVELINESS_GRACE_PERIOD_MS = 5 * 60 * 1000;

export interface ConnectorInfoError {
  code: string;
  message: string;
  criticity: number;
}

export interface ConnectorInfo {
  run_and_terminate: boolean;
  buffering: boolean;
  queue_threshold: number;
  queue_messages_size: number;
  next_run_datetime?: Date | string | null;
  last_run_datetime?: Date | string | null;
  errors?: ConnectorInfoError[] | null;
}

// Parent of the ConnectorInfo GraphQL type: errors live in redis and are only loaded when requested, by connector id
export interface ResolvedConnectorInfo extends ConnectorInfo {
  connector_id: string;
}

type ConnectorManagerContract = CatalogContractEntityFields;

export interface BasicStoreEntityConnector extends BasicStoreEntity, IngestionHealthFields {
  active: boolean;
  built_in?: boolean;
  auto: boolean;
  auto_update: boolean;
  enrichment_resolution: string;
  only_contextual: boolean;
  connector_type: string;
  connector_scope: string;
  connector_state: string;
  connector_state_reset: boolean;
  connector_state_timestamp?: string;
  connector_trigger_filters: string;
  connector_user_id: string;
  connector_info: ConnectorInfo;
  connector_priority_group?: ConnectorPriorityGroup;
  playbook_compatible: boolean;
  xtm_one_intent: string | null;
  version: string | null;
  slug: string | null;
  // region composer (set only on composer-managed connectors)
  catalog_id?: string;
  manager_contract_image?: string;
  manager_contract_configuration?: ConnectorContractConfiguration[];
  manager_contract?: ConnectorManagerContract;
  manager_upgrade_strategy?: string;
  manager_current_status?: string;
  manager_requested_status?: string;
  // endregion
}

export interface StoreEntityConnector extends BasicStoreEntityConnector, StoreEntity {}

// Connector of the connectors cache: without liveness, see refreshConnectorsLiveness.
// The cache is only refreshed by a notify on the connector topics (or a cache reset), and some frequent writes skip it on purpose:
// a notify reloads every connector on every node. These fields can therefore be stale here, read them from Elasticsearch:
// - connector_state, connector_state_reset, connector_state_timestamp, connector_info and updated_at (pings, state resets, built-in runs);
// - manager_contract and manager_contract_image (auto-upgrade of managed connectors).
// Any new write of a field read from this cache must notify, as registerConnector does.
export type CachedConnector = Omit<BasicStoreEntityConnector, 'active'>;

export interface BasicStoreEntityConnectorManager extends BasicStoreEntity {
  public_key: string;
  last_sync_execution?: Date | string;
}

export interface StoreEntityConnectorManager extends BasicStoreEntityConnectorManager, StoreEntity {}

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
