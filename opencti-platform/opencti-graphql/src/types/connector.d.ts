import type { StoreEntity } from './store';
import { BasicStoreEntity } from './store';

export interface ConnectorInfo {
  run_and_terminate: boolean,
  buffering: boolean,
  queue_threshold: number,
  queue_messages_size: number,
  next_run_datetime: string, // TODO datetime instead of string
}

export interface BasicStoreConnector extends BasicStoreEntity {
  active: boolean,
  connector_info: ConnectorInfo,
}

export interface StoreConnector extends StoreEntity {
  active: boolean,
  connector_info: ConnectorInfo,
}
