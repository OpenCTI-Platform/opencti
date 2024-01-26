import { getEntitiesListFromCache, getEntitiesMapFromCache } from '../../database/cache';
import { SYSTEM_USER } from '../../utils/access';
import { type BasicStoreEntityPublicDashboard, ENTITY_TYPE_PUBLIC_DASHBOARD } from './publicDashboard-types';
import { fromBase64 } from '../../database/utils';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import type { AuthContext, AuthUser } from '../../types/user';
import { UnsupportedError } from '../../config/errors';

export const getWidgetsUserAndMarkings = async (
  context: AuthContext,
  uriKey: string,
): Promise<{ user: AuthUser, widgets: any, allowed_markings_ids: string[] }> => {
  // Get publicDashboard from cache
  const publicDashboards = await getEntitiesListFromCache<BasicStoreEntityPublicDashboard>(context, SYSTEM_USER, ENTITY_TYPE_PUBLIC_DASHBOARD);
  const dashboard = publicDashboards.find((p) => p.uri_key === uriKey);
  if (!dashboard) {
    throw UnsupportedError('Dashboard not found');
  }
  const { user_id, private_manifest, allowed_markings_ids } = dashboard;

  // Get user from cache
  const platformUsersMap = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const plateformUser = platformUsersMap.get(user_id);
  if (!plateformUser) {
    throw UnsupportedError('User not found');
  }
  const user = { ...plateformUser, origin: { user_id: plateformUser.id, referer: 'public-dashboard' } };

  // Get widget query configuration
  const parsedManifest = JSON.parse(fromBase64(private_manifest) ?? '{}');
  const { widgets } = parsedManifest;
  return { user, widgets, allowed_markings_ids };
};
