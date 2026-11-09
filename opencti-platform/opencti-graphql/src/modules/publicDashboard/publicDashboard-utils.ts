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
import { utcDate } from '../../utils/format';
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
  // The time filters switch belongs to the dashboard variables feature: without it, the public filters stay read only
  const servedConfig = !isFeatureEnabled('DASHBOARD_VARIABLES') && manifest.config?.allowViewersToEditTimeFilters !== undefined
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
  config: PublicDashboardCached['private_manifest']['config'] | undefined;
}

// A relative range as the front computes it (computeRelativeDate): `days-7`, `months-1`, `years-1`... back from now.
// The count is bounded as at publication: a larger one is treated as unknown.
const RELATIVE_DATE_REGEXP = /^(days|months|years)-(\d{1,4})$/;
type RelativeDateUnit = 'days' | 'months' | 'years';
// The public page computes a relative start in the time zone of the visitor: days back from now, months and years
// back from the start of the visitor's day, so up to one day earlier than here. One more hour covers a daylight
// saving change in between.
const HOUR_MS = 3600 * 1000;
const RELATIVE_START_MARGIN_MS: Record<RelativeDateUnit, number> = { days: HOUR_MS, months: 25 * HOUR_MS, years: 25 * HOUR_MS };

export interface PublicDashboardTimeRange {
  startDate?: string | null;
  endDate?: string | null;
}

// The range frozen at publication: the bounds the queries fall back on, and the instants a requested bound must stay within.
interface PublishedTimeRange {
  startDate: string | undefined;
  endDate: string | undefined;
  lowest: number;
  highest: number;
}

const toTime = (value: unknown): number | null => {
  if (value === null || value === undefined || value === '') return null;
  const date = utcDate(value);
  return date.isValid() ? date.valueOf() : null;
};

const publishedTimeRangeOf = (config: PublicDashboardCached['private_manifest']['config'] | undefined): PublishedTimeRange => {
  if (config?.relativeDate) {
    const end = utcDate();
    const match = RELATIVE_DATE_REGEXP.exec(config.relativeDate);
    // Unknown relative date: the front computes no start either.
    if (!match) return { startDate: undefined, endDate: end.toISOString(), lowest: -Infinity, highest: end.valueOf() };
    const unit = match[1] as RelativeDateUnit;
    const start = end.clone().subtract(Number(match[2]), unit);
    return { startDate: start.toISOString(), endDate: end.toISOString(), lowest: start.valueOf() - RELATIVE_START_MARGIN_MS[unit], highest: end.valueOf() };
  }
  const startDate = config?.startDate ?? undefined;
  const endDate = config?.endDate ?? undefined;
  return { startDate, endDate, lowest: toTime(startDate) ?? -Infinity, highest: toTime(endDate) ?? Infinity };
};

/**
 * The time range the public widget queries run with. When the author allowed the viewers to edit the time filters
 * (the dashboard switch, copied at publication), the range sent by the visitor is honoured. Otherwise the range frozen
 * at publication is enforced here: the time filters of the public page are disabled, and a direct call to the public
 * API cannot widen them either. The range sent is kept when it lies within the published one, so the public page runs
 * exactly the queries it ran before; otherwise the published range is used, a relative one computed back from now.
 */
export const resolvePublicDashboardTimeRange = (
  config: PublicDashboardCached['private_manifest']['config'] | undefined,
  requested: PublicDashboardTimeRange,
): PublicDashboardTimeRange => {
  if (config?.allowViewersToEditTimeFilters === true) {
    return { startDate: requested.startDate, endDate: requested.endDate };
  }
  const published = publishedTimeRangeOf(config);
  // An absent bound only lies within a published range open on that side.
  const isWithin = (value: unknown, isOpenSide: boolean) => {
    if (value === null || value === undefined) return isOpenSide;
    const time = toTime(value);
    return time !== null && time >= published.lowest && time <= published.highest;
  };
  if (isWithin(requested.startDate, published.lowest === -Infinity) && isWithin(requested.endDate, published.highest === Infinity)) {
    return { startDate: requested.startDate, endDate: requested.endDate };
  }
  return { startDate: published.startDate, endDate: published.endDate };
};

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
  const { widgets, config } = private_manifest;
  const { type, perspective, dataSelection, parameters } = widgets[widgetId];

  return {
    user,
    type,
    perspective,
    parameters,
    dataSelection,
    config,
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
