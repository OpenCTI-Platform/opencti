import type { AuthContext, AuthUser } from '../types/user';
import { BasicStoreEntityCsvMapper } from '../modules/internal/csvMapper/csvMapper-types';
import type { ConnectorPriorityGroup } from '../generated/graphql';

/**
 * This is the type for internal connector like import CSV.
 * It's NOT the type for connector entity.
 */

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
  connector_priority_group?: ConnectorPriorityGroup
  name: string;
  built_in: boolean;
  connector_schema_runtime_fn?: <T extends BasicStoreEntityCsvMapper> (context: AuthContext, user: AuthUser) => Promise<T[]>;
}
