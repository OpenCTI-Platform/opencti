import { getEntitiesMapFromCache, getEntitiesListFromCache } from '../../database/cache';
import { SYSTEM_USER } from '../../utils/access';
import { ENTITY_TYPE_PUBLIC_DASHBOARD, type PublicDashboardCached } from './publicDashboard-types';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import type { AuthContext, AuthUser } from '../../types/user';
import { UnsupportedError } from '../../config/errors';
import { computeAvailableMarkings } from '../../domain/user';
import type { StoreMarkingDefinition } from '../../types/store';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';

export const getWidgetsConfigAndUser = async (
  context: AuthContext,
  uriKey: string,
): Promise<{ user: AuthUser, widgets: any, config: any }> => {
  // Get publicDashboard from cache
  const publicDashboardsMapByUriKey = await getEntitiesMapFromCache<PublicDashboardCached>(context, SYSTEM_USER, ENTITY_TYPE_PUBLIC_DASHBOARD);
  const publicDashboard = publicDashboardsMapByUriKey.get(uriKey);
  if (!publicDashboard) {
    throw UnsupportedError('Dashboard not found');
  }

  const { user_id, private_manifest, allowed_markings }: PublicDashboardCached = publicDashboard;

  // Get user from cache
  const platformUsersMap = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const plateformUser = platformUsersMap.get(user_id);
  if (!plateformUser) {
    throw UnsupportedError('User not found');
  }
  const user = { ...plateformUser, origin: { user_id: plateformUser.id, referer: 'public-dashboard' } };

  // replace User markings by publicDashboard allowed_markings
  const allMarkings = await getEntitiesListFromCache<StoreMarkingDefinition>(context, user, ENTITY_TYPE_MARKING_DEFINITION);
  user.allowed_marking = computeAvailableMarkings(allowed_markings, allMarkings); // TODO what if user is downgraded ??

  // Get widget query configuration
  const { widgets, config } = private_manifest;
  return { user, widgets, config };
};
