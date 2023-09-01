import { AuthContext, AuthUser } from '../types/user';
import { BasicStoreEntityCsvMapper } from '../modules/internal/csvMapper/csvMapper-types';

export interface ConnectorConfig {
  id: string;
  name: string;
  running: boolean;
  config: {
    enable: boolean;
    validate_before_import: boolean;
    scheduleTime: number;
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
