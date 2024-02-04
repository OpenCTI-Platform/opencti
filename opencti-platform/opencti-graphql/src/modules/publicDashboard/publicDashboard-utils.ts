import { getEntitiesMapFromCache } from '../../database/cache';
import { SYSTEM_USER } from '../../utils/access';
import { ENTITY_TYPE_PUBLIC_DASHBOARD, type PublicDashboardCached } from './publicDashboard-types';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import type { AuthContext, AuthUser } from '../../types/user';
import { UnsupportedError } from '../../config/errors';

export const getWidgetsConfigAndUser = async (
  context: AuthContext,
  uriKey: string,
): Promise<{ user: AuthUser, widgets: any, config: any }> => {
  // Get publicDashboard from cache
  const publicDashboardsMapByUriKey = await getEntitiesMapFromCache<PublicDashboardCached>(context, SYSTEM_USER, ENTITY_TYPE_PUBLIC_DASHBOARD);
  const dashboard = publicDashboardsMapByUriKey.get(uriKey);
  if (!dashboard) {
    throw UnsupportedError('Dashboard not found');
  }

  const { user_id, private_manifest, allowed_markings_ids }: PublicDashboardCached = dashboard;

  // Get user from cache
  const platformUsersMap = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const plateformUser = platformUsersMap.get(user_id);
  if (!plateformUser) {
    throw UnsupportedError('User not found');
  }
  const user = { ...plateformUser, origin: { user_id: plateformUser.id, referer: 'public-dashboard' } };
  // // TODO:  modifiy user marking

  // Get widget query configuration
  const { widgets, config } = private_manifest;
  return { user, widgets, config };
};
