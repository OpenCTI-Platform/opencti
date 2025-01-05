import type { AuthContext, AuthUser } from '../../types/user';
import { listAllEntities } from '../../database/middleware-loader';
import { type BasicStoreEntityIngestionJson, ENTITY_TYPE_INGESTION_JSON_COLLECTION } from './ingestion-types';

export const findAllJsonIngestions = async (context: AuthContext, user: AuthUser, opts = {}) => {
  return listAllEntities<BasicStoreEntityIngestionJson>(context, user, [ENTITY_TYPE_INGESTION_JSON_COLLECTION], opts);
};
