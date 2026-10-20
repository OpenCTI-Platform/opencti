import type { BasicStoreEntity } from './store';
import type { IngestionHealthFields } from '../modules/ingestionHealth/ingestionHealth-types';

export interface BasicStoreEntitySynchronizer extends BasicStoreEntity, IngestionHealthFields {
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
