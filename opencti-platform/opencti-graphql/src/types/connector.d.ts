import type { StoreEntity } from './store';

export interface ConnectorInfo {
  run_and_terminate: boolean,
  buffering: boolean,
  queue_threshold: number,
  queue_messages_size: number,
  next_run_datetime: string,
}

export interface StoreConnector extends StoreEntity {
  active: boolean,
  connectorInfo: ConnectorInfo,
}
