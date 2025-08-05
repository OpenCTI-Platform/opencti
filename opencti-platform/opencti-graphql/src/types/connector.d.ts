import type { BasicStoreEntity, StoreEntity } from './store';

export interface ConnectorInfo {
  run_and_terminate: boolean,
  buffering: boolean,
  queue_threshold: number,
  queue_messages_size: number,
  next_run_datetime: DateTime,
  last_run_datetime: DateTime,
}

export interface BasicStoreEntityConnector extends StoreEntity {
  active: boolean,
  auto: boolean,
  auto_update: boolean,
  enrichment_resolution: string,
  only_contextual: boolean,
  connector_type: string,
  connector_scope: string,
  connector_state: string,
  connector_state_reset: boolean,
  connector_trigger_filters: string,
  connector_user_id; string,
  connector_info: ConnectorInfo,
  playbook_compatible: boolean,
}
export interface BasicStoreEntityConnectorManager extends BasicStoreEntity {
  public_key: string,
}

export interface BasicStoreEntitySynchronizer extends BasicStoreEntity {
  name: string,
  uri: string,
  token?: string | null
  stream_id: string,
  running: boolean,
  current_state_date: Date,
  listen_deletion: boolean,
  no_dependencies: boolean,
  ssl_verify: boolean
  synchronized: boolean
}
