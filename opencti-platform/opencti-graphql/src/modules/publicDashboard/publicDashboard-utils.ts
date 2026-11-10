import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import { getEntitiesListFromCache, getEntitiesMapFromCache } from '../../database/cache';
import { getUserAccessRight, MEMBER_ACCESS_RIGHT_ADMIN, PUBLIC_DASHBOARD_REFERER, SYSTEM_USER } from '../../utils/access';
import { type BasicStoreEntityPublicDashboard, ENTITY_TYPE_PUBLIC_DASHBOARD, type PublicDashboardCached, type PublicDashboardCachedWidget } from './publicDashboard-types';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import type { AuthContext, AuthUser, UserCapability } from '../../types/user';
import { ForbiddenAccess, FunctionalError, UnsupportedError } from '../../config/errors';
import { computeAvailableMarkings } from '../user/user-domain';
import type { StoreMarkingDefinition } from '../../types/store';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import { elLoadById } from '../../database/engine';
import { cleanMarkings } from '../../utils/markingDefinition-utils';
import { findById as findWorkspace } from '../workspace/workspace-domain';
import { isFeatureEnabled, TIME_SERIES_BREAKDOWN_FEATURE_FLAG } from '../../config/conf';
import { fromB64, toB64 } from '../../utils/base64';
import { canWidgetBreakDown } from './publicDashboard-breakdown';

// Parameters of a widget setting its breakdown: the type of the widgets of the public dashboards is derived from them
export const WIDGET_BREAKDOWN_PARAMETERS = ['breakdownBy', 'breakdownLimit', 'breakdownOrder', 'breakdownOther'] as const;

/**
 * Public manifest as served to the visitors. A widget keeps its breakdown when it can be broken down (canWidgetBreakDown),
 * read on its stored widget of the private manifest, which keeps the filters the public one strips, and with the time
 * series breakdown feature. Otherwise it is served without, and renders its regular chart as in the private dashboards:
 * the stored manifest keeps it.
 */
export const getServedPublicManifest = (publicDashboard: Pick<BasicStoreEntityPublicDashboard, 'public_manifest' | 'private_manifest'>) => {
  const { public_manifest: publicManifest } = publicDashboard;
  if (!publicManifest) {
    return publicManifest;
  }
  const manifest = fromB64(publicManifest);
  // The viewer switch of the dashboard is not a public setting: the public time filters stay read only
  const servedConfig = manifest.config?.allowViewersToEditTimeFilters !== undefined
    ? R.omit(['allowViewersToEditTimeFilters'], manifest.config)
    : manifest.config;
  const serveWidgetsUnchanged = () => (servedConfig === manifest.config ? publicManifest : toB64({ ...manifest, config: servedConfig }));
  const widgets = Object.entries<any>(manifest.widgets ?? {});
  if (!widgets.some(([, widget]) => widget?.parameters?.breakdownBy)) {
    return serveWidgetsUnchanged();
  }
  const storedWidgets = isFeatureEnabled(TIME_SERIES_BREAKDOWN_FEATURE_FLAG)
    ? fromB64<{ widgets?: Record<string, PublicDashboardCachedWidget> }>(publicDashboard.private_manifest).widgets ?? {}
    : {};
  const isServedWithoutBreakdown = (widgetId: string, widget: any) => {
    const storedWidget = storedWidgets[widgetId];
    return !!widget?.parameters?.breakdownBy && !(storedWidget && canWidgetBreakDown(storedWidget));
  };
  if (!widgets.some(([widgetId, widget]) => isServedWithoutBreakdown(widgetId, widget))) {
    return serveWidgetsUnchanged();
  }
  const servedWidgets = widgets.map(([widgetId, widget]) => {
    return [widgetId, isServedWithoutBreakdown(widgetId, widget) ? { ...widget, parameters: R.omit(WIDGET_BREAKDOWN_PARAMETERS, widget.parameters) } : widget];
  });
  return toB64({ ...manifest, config: servedConfig, widgets: Object.fromEntries(servedWidgets) });
};

/**
 * Sanitizes a raw uri_key input to a valid [a-z0-9-] slug.
 * Falls back to a UUID v4 if the resulting slug is empty (e.g. fully non-Latin input).
 */
export const sanitizePublicDashboardUriKey = (input: string): string => {
  const slug = input.replace(/[^a-zA-Z0-9\s-]+/g, '').replace(/\s+/g, '-').toLowerCase();
  return slug || uuidv4();
};

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
  userAuthorPublicDashboard: AuthUser,
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
    ENTITY_TYPE_MARKING_DEFINITION,
  );
  return computeAvailableMarkings(Object.values(widgetsMaxMarkingsMap), allMarkings);
};

interface WidgetArguments {
  user: AuthUser;
  type: PublicDashboardCachedWidget['type'];
  perspective: PublicDashboardCachedWidget['perspective'];
  dataSelection: PublicDashboardCachedWidget['dataSelection'];
  parameters: PublicDashboardCachedWidget['parameters'];
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
    throw UnsupportedError('Dashboard not found', { uriKey });
  }
  if (!publicDashboard.enabled) {
    throw UnsupportedError('Dashboard not enabled', { uriKey });
  }

  const { user_id, private_manifest }: PublicDashboardCached = publicDashboard;

  // Get user that creates the public dashboard from cache
  const platformUsersMap = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const platformUser = platformUsersMap.get(user_id);
  if (!platformUser) {
    throw UnsupportedError('User not found', { user_id });
  }

  // Determine the marking definitions allowed.
  const allowedMaxMarkings = await findWidgetsMaxMarkings(context, publicDashboard, platformUser);

  // To replace User capabilities by KNOWLEDGE capability
  const accessKnowledgeCapability: UserCapability = await elLoadById(
    context,
    SYSTEM_USER,
    'capability--cbc68f4b-1d0c-51f6-a1b9-10344503b493',
  ) as unknown as UserCapability;

  // Construct a fake user to be able to call private API
  const user = {
    ...platformUser,
    origin: { user_id: platformUser.id, referer: PUBLIC_DASHBOARD_REFERER },
    capabilities: [accessKnowledgeCapability],
    allowed_marking: allowedMaxMarkings, // ACL - Markings
    // ACL - Authorized members
    // ACL - Authorized authorities
  };

  // Get widget query configuration
  const { widgets } = private_manifest;
  const { type, perspective, dataSelection, parameters } = widgets[widgetId];

  return {
    user,
    type,
    perspective,
    parameters,
    dataSelection,
  };
};

export const checkUserIsAdminOnDashboard = async (context: AuthContext, user: AuthUser, id: string) => {
  const publicDashboards = await getEntitiesMapFromCache<PublicDashboardCached>(context, SYSTEM_USER, ENTITY_TYPE_PUBLIC_DASHBOARD);
  const publicDashboard = publicDashboards.get(id);
  if (publicDashboard === undefined) {
    throw FunctionalError('No public dashboard found', { id });
  }
  const dash = await findWorkspace(context, user, publicDashboard.dashboard_id);
  const userAccessRight = getUserAccessRight(user, dash);
  if (userAccessRight !== MEMBER_ACCESS_RIGHT_ADMIN) {
    throw ForbiddenAccess();
  }
};
