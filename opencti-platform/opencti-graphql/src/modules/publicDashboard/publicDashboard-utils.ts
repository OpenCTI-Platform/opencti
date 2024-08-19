import { getEntitiesListFromCache, getEntitiesMapFromCache } from '../../database/cache';
import { getUserAccessRight, MEMBER_ACCESS_RIGHT_ADMIN, SYSTEM_USER } from '../../utils/access';
import { ENTITY_TYPE_PUBLIC_DASHBOARD, type PublicDashboardCached, type PublicDashboardCachedWidget } from './publicDashboard-types';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import type { AuthContext, AuthUser, UserCapability } from '../../types/user';
import { ForbiddenAccess, FunctionalError, UnsupportedError } from '../../config/errors';
import { computeAvailableMarkings } from '../../domain/user';
import type { StoreMarkingDefinition } from '../../types/store';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import { elLoadById } from '../../database/engine';
import { cleanMarkings } from '../../utils/markingDefinition-utils';
import { findById as findWorkspace } from '../workspace/workspace-domain';

/**
 * Find which markings should be used when searching the data to populate in the widgets.
 *
 * @param context
 * @param publicDashboard The one we want to retrieve data for its widgets.
 * @param userAuthorPublicDashboard The user who creates the public dashboard.
 */
export const findWidgetsMaxMarkings = async (
  context: AuthContext,
  publicDashboard: PublicDashboardCached,
  userAuthorPublicDashboard: AuthUser
) => {
  // To find max markings allowed for widgets we keep the intersection of markings from:
  // - Max shareable markings of the user,
  // - Max markings of the public dashboard defined by the user who created it,
  // - Max markings of the user who created it.
  // (The last case is necessary if the user has lost markings between the time they create the public
  // dashboard and the time someone access the public dashboard).
  const dataSharingMaxMarkings = userAuthorPublicDashboard.max_shareable_marking;
  const dashboardMaxMarkings = publicDashboard.allowed_markings;
  // Call of cleanMarkings to keep only the max for each type.
  const userMaxMarkings = await cleanMarkings(context, userAuthorPublicDashboard.allowed_marking);

  const widgetsMaxMarkingsMap: Record<string, StoreMarkingDefinition> = {};
  [...dataSharingMaxMarkings, ...dashboardMaxMarkings, ...userMaxMarkings]
    // To be acceptable, a type should be present in all of the three arrays.
    .filter((marking) => {
      return (
        dataSharingMaxMarkings.some((m) => m.definition_type === marking.definition_type)
        && dashboardMaxMarkings.some((m) => m.definition_type === marking.definition_type)
        && userMaxMarkings.some((m) => m.definition_type === marking.definition_type)
      );
    })
    .forEach((marking) => {
      const saveMarking = widgetsMaxMarkingsMap[marking.definition_type];
      // Keep the min order for each type of markings.
      if (!saveMarking || saveMarking.x_opencti_order > marking.x_opencti_order) {
        widgetsMaxMarkingsMap[marking.definition_type] = marking;
      }
    });

  // Return the list of all available markings from the max markings determined above.
  const allMarkings = await getEntitiesListFromCache<StoreMarkingDefinition>(
    context,
    SYSTEM_USER,
    ENTITY_TYPE_MARKING_DEFINITION
  );
  return computeAvailableMarkings(Object.values(widgetsMaxMarkingsMap), allMarkings);
};

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

  const { user_id, private_manifest }: PublicDashboardCached = publicDashboard;

  // Get user that creates the public dashboard from cache
  const platformUsersMap = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const platformUser = platformUsersMap.get(user_id);
  if (!platformUser) {
    throw UnsupportedError('User not found');
  }

  // Determine the marking definitions allowed.
  const allowedMaxMarkings = await findWidgetsMaxMarkings(context, publicDashboard, platformUser);

  // To replace User capabilities by KNOWLEDGE capability
  const accessKnowledgeCapability: UserCapability = await elLoadById(
    context,
    SYSTEM_USER,
    'capability--cbc68f4b-1d0c-51f6-a1b9-10344503b493'
  ) as unknown as UserCapability;

  // Construct a fake user to be able to call private API
  const user = {
    ...platformUser,
    origin: { user_id: platformUser.id, referer: 'public-dashboard' },
    allowed_marking: allowedMaxMarkings,
    capabilities: [accessKnowledgeCapability],
    inside_platform_organization: platformUser.inside_platform_organization,
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

export const checkUserIsAdminOnDashboard = async (context: AuthContext, user: AuthUser, id: string) => {
  const publicDashboards = await getEntitiesListFromCache<PublicDashboardCached>(context, SYSTEM_USER, ENTITY_TYPE_PUBLIC_DASHBOARD);
  const publicDashboard = publicDashboards.find((p) => (p.id === id));
  if (publicDashboard === undefined) {
    throw FunctionalError('No public dashboard found', { id });
  }
  const dash = await findWorkspace(context, user, publicDashboard.dashboard_id);
  const userAccessRight = getUserAccessRight(user, dash);
  if (userAccessRight !== MEMBER_ACCESS_RIGHT_ADMIN) {
    throw ForbiddenAccess();
  }
};
