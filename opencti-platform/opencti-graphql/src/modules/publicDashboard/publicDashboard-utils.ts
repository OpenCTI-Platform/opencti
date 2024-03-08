import { getEntitiesMapFromCache, getEntitiesListFromCache } from '../../database/cache';
import { SYSTEM_USER } from '../../utils/access';
import { ENTITY_TYPE_PUBLIC_DASHBOARD, type PublicDashboardCached, type PublicDashboardCachedWidget } from './publicDashboard-types';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import type { AuthContext, AuthUser, UserCapability } from '../../types/user';
import { UnsupportedError } from '../../config/errors';
import { computeAvailableMarkings } from '../../domain/user';
import type { StoreMarkingDefinition } from '../../types/store';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import { elLoadById } from '../../database/engine';
import { getAvailableDataSharingMarkings } from '../../domain/settings';

interface WidgetArguments {
  user: AuthUser,
  dataSelection: PublicDashboardCachedWidget['dataSelection'],
  parameters: PublicDashboardCachedWidget['parameters'],
}

export const getWidgetArguments = async (
  context: AuthContext,
  uriKey: string,
  widgetId: string,
): Promise<WidgetArguments> => {
  // Get publicDashboard from cache
  const publicDashboardsMapByUriKey = await getEntitiesMapFromCache<PublicDashboardCached>(context, SYSTEM_USER, ENTITY_TYPE_PUBLIC_DASHBOARD);
  const publicDashboard = publicDashboardsMapByUriKey.get(uriKey);
  if (!publicDashboard) {
    throw UnsupportedError('Dashboard not found');
  }
  if (!publicDashboard.enabled) {
    throw UnsupportedError('Dashboard not enabled');
  }

  const { user_id, private_manifest, allowed_markings }: PublicDashboardCached = publicDashboard;

  // Get user that creates the public dashboard from cache
  const platformUsersMap = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const platformUser = platformUsersMap.get(user_id);
  if (!platformUser) {
    throw UnsupportedError('User not found');
  }

  // Determine the marking definitions allowed.
  const allMarkings = await getEntitiesListFromCache<StoreMarkingDefinition>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  const availableDataSharingMarkingIds = (await getAvailableDataSharingMarkings(context, SYSTEM_USER)).map((m) => m.id);
  const availableDashboardMarkings = computeAvailableMarkings(allowed_markings, allMarkings);
  const allowedMarkings = availableDashboardMarkings.filter((m) => availableDataSharingMarkingIds.includes(m.id));
  // To replace User capabilities by KNOWLEDGE capability
  const accessKnowledgeCapability: UserCapability = await elLoadById(context, SYSTEM_USER, 'capability--cbc68f4b-1d0c-51f6-a1b9-10344503b493') as unknown as UserCapability;

  // Construct a fake user to be able to call private API
  const user = {
    ...platformUser,
    origin: { user_id: platformUser.id, referer: 'public-dashboard' },
    allowed_marking: allowedMarkings,
    capabilities: [accessKnowledgeCapability]
  };

  // Get widget query configuration
  const { widgets } = private_manifest;
  const { dataSelection, parameters } = widgets[widgetId];

  return {
    user,
    parameters,
    dataSelection
  };
};
