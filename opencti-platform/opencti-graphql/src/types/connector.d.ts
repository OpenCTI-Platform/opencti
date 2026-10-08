import type { ConnectorContractConfiguration } from '../generated/graphql';
import type { CatalogContractEntityFields } from '../modules/catalog/catalog-types';
import type { BasicStoreEntity, StoreEntity } from './store';

export interface ConnectorInfo {
  run_and_terminate: boolean;
  buffering: boolean;
  queue_threshold: number;
  queue_messages_size: number;
  next_run_datetime: DateTime;
  last_run_datetime: DateTime;
}

type ConnectorManagerContract = CatalogContractEntityFields;

export interface BasicStoreEntityConnector extends StoreEntity {
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
  version: string | null;
  slug: string | null;
  // region hunt connectors (set only on INTERNAL_HUNT connectors)
  hunt_platform?: string | null;
  hunt_languages?: string[];
  hunt_security_platform_id?: string | null;
  hunt_supports_preview?: boolean | null;
  hunt_supports_indicators?: boolean | null;
  hunt_setup?: {
    documentation_url?: string | null;
    required_permissions?: { name: string; purpose: string }[];
  } | null;
  hunt_connection_check?: {
    id: string;
    work_id?: string | null;
    status: string;
    requested_at?: string | null;
    checked_at?: string | null;
    checks?: { name: string; ok: boolean; message: string }[];
  } | null;
  hunt_max_concurrent_runs?: number | null;
  // endregion
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

export interface BasicStoreEntitySynchronizer extends BasicStoreEntity {
  name: string;
  uri: string;
  token?: string | null;
  stream_id: string;
  running: boolean;
  current_state_date?: Date;
  last_execution_date?: Date;
  last_execution_status?: string;
  listen_deletion: boolean;
  no_dependencies: boolean;
  ssl_verify: boolean;
  synchronized: boolean;
}
