import { getEntitiesListFromCache } from '../database/cache';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import type { BasicStoreEntityConnector } from '../types/connector';
import type { AuthContext, AuthUser } from '../types/user';
import { SYSTEM_USER } from './access';

/**
 * @param context Context of the write, carrying the work id when it comes from a worker.
 * @param user User performing the write.
 * @returns True if the write comes from a worker running as a connector user.
 */
export const isFromConnectorWork = async (context: AuthContext, user: AuthUser) => {
  if (!context.workId) {
    return false;
  }
  const connectors = await getEntitiesListFromCache<BasicStoreEntityConnector>(context, SYSTEM_USER, ENTITY_TYPE_CONNECTOR);
  return connectors.some((connector) => connector.connector_user_id === user.id);
};
