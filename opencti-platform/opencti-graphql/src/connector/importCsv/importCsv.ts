import { CONNECTOR_INTERNAL_IMPORT_FILE } from '../../schema/general';
import type { AuthContext, AuthUser } from '../../types/user';
import { listAllEntities } from '../../database/middleware-loader';
import { ENTITY_TYPE_CSV_MAPPER } from '../../modules/internal/csvMapper/csvMapper-types';
import type { Connector } from '../connector';
import { ENABLED_IMPORT_CSV_BUILT_IN_CONNECTOR } from './importCsv-configuration';

export const IMPORT_CSV_CONNECTOR_ID = 'd336676c-4ee5-4257-96ff-b2a86688d4af';

export const IMPORT_CSV_CONNECTOR: Connector = {
  id: IMPORT_CSV_CONNECTOR_ID,
  internal_id: IMPORT_CSV_CONNECTOR_ID,
  active: ENABLED_IMPORT_CSV_BUILT_IN_CONNECTOR,
  auto: false,
  connector_scope: 'text/csv',
  connector_type: CONNECTOR_INTERNAL_IMPORT_FILE,
  name: 'ImportCsv',
  built_in: true,
  connector_schema_runtime_fn: (context: AuthContext, user: AuthUser) => listAllEntities(context, user, [ENTITY_TYPE_CSV_MAPPER]),
};
