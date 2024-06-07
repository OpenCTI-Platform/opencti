import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreEntity } from '../types/store';
import { BasicStoreEntityCsvMapper } from '../modules/internal/csvMapper/csvMapper-types';

export interface ConnectorConfig {
  id: string;
  name: string;
  config: {
    enable: boolean;
    validate_before_import: boolean;
  }
}

export interface Connector {
  id: string
  internal_id: string
  active: boolean
  auto: boolean
  connector_scope: string;
  connector_type: string;
  name: string;
  built_in: boolean;
  connector_schema_runtime_fn: <T extends BasicStoreEntityCsvMapper> (context: AuthContext, user: AuthUser) => Promise<T[]>;
}

export interface BasicStoreEntityConnector extends Connector, BasicStoreEntity {
  connector_trigger_filters: string;
}
