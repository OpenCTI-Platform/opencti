import { Promise as BluePromise } from 'bluebird';
import type { AuthContext, AuthUser } from '../../types/user';
import { internalLoadById, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityPublicDashboard, ENTITY_TYPE_PUBLIC_DASHBOARD, type PublicDashboardCached } from './publicDashboard-types';
import { createEntity, deleteElementById, loadEntity, updateAttribute } from '../../database/middleware';
import { type BasicStoreEntityWorkspace } from '../workspace/workspace-types';
import { isNotEmptyField } from '../../database/utils';
import { notify } from '../../database/redis';
import { BUS_TOPICS, logApp } from '../../config/conf';
import {
  type EditInput,
  type FilterGroup,
  FilterMode,
  FilterOperator,
  type PublicDashboardAddInput,
  type QueryPublicBookmarksArgs,
  type QueryPublicDashboardsArgs,
  type QueryPublicStixCoreObjectsArgs,
  type QueryPublicStixCoreObjectsDistributionArgs,
  type QueryPublicStixCoreObjectsMultiTimeSeriesArgs,
  type QueryPublicStixCoreObjectsNumberArgs,
  type QueryPublicStixRelationshipsArgs,
  type QueryPublicStixRelationshipsDistributionArgs,
  type QueryPublicStixRelationshipsMultiTimeSeriesArgs,
  type QueryPublicStixRelationshipsNumberArgs
} from '../../generated/graphql';
import { ForbiddenAccess, FunctionalError, UnsupportedError } from '../../config/errors';
import { getUserAccessRight, MEMBER_ACCESS_RIGHT_ADMIN, SYSTEM_USER } from '../../utils/access';
import { publishUserAction } from '../../listener/UserActionListener';
import { findAllWorkspaces } from '../workspace/workspace-domain';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import { getEntitiesMapFromCache } from '../../database/cache';
import type { BasicStoreRelation, NumberResult, StoreEntityConnection, StoreMarkingDefinition, StoreRelationConnection } from '../../types/store';
import { checkUserIsAdminOnDashboard, getWidgetArguments } from './publicDashboard-utils';
import {
  findStixCoreObjectPaginated,
  stixCoreObjectsDistribution,
  stixCoreObjectsDistributionByEntity,
  stixCoreObjectsMultiTimeSeries,
  stixCoreObjectsNumber
} from '../../domain/stixCoreObject';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import { findStixRelationPaginated, stixRelationshipsDistribution, stixRelationshipsMultiTimeSeries, stixRelationshipsNumber } from '../../domain/stixRelationship';
import { bookmarks, checkUserCanShareMarkings } from '../../domain/user';
import { daysAgo } from '../../utils/format';
import { isStixCoreObject } from '../../schema/stixCoreObject';
import { ES_MAX_CONCURRENCY } from '../../database/engine';
import { findById as findMarkingDefinitionById } from '../../domain/markingDefinition';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { fromB64, toB64 } from '../../utils/base64';
import { computeLoaders } from '../../http/httpAuthenticatedContext';

export const findById = (
  context: AuthContext,
  user: AuthUser,
  id: string,
) => {
  return storeLoadById<BasicStoreEntityPublicDashboard>(
    context,
    user,
    id,
    ENTITY_TYPE_PUBLIC_DASHBOARD,
  );
};

export const findPublicDashboardPaginated = async (
  context: AuthContext,
  user: AuthUser,
  args: QueryPublicDashboardsArgs,
): Promise<StoreEntityConnection<BasicStoreEntityPublicDashboard>> => {
  const dashboards = await findAllWorkspaces(
    context,
    user,
    {
      filters: {
        mode: FilterMode.And,
        filters: [{ key: ['type'], values: ['dashboard'] }],
        filterGroups: []
      }
    }
  );

  const dashboardIds = dashboards.map((n) => n.id);
  if (dashboardIds.length === 0) {
    return {
      edges: [],
      pageInfo: {
        globalCount: 0,
        hasNextPage: false,
        hasPreviousPage: false,
        endCursor: '',
        startCursor: ''
      }
    };
  }

  const filters = addFilter(args.filters ?? undefined, 'dashboard_id', dashboardIds);
  return pageEntitiesConnection<BasicStoreEntityPublicDashboard>(
    context,
    user,
    [ENTITY_TYPE_PUBLIC_DASHBOARD],
    { ...args, filters },
  );
};

export const getPublicDashboardByUriKey = (
  context: AuthContext,
  uri_key: string,
) => {
  logApp.info('[OPENCTI] Public dashboard - trying to fetch public dashboard with URI KEY', { uri_key });
  return loadEntity(
    context,
    SYSTEM_USER,
    [ENTITY_TYPE_PUBLIC_DASHBOARD],
    {
      filters: {
        mode: 'and',
        filters: [
          { key: ['uri_key'], values: [uri_key], mode: 'or', operator: 'eq' }
        ],
        filterGroups: [],
      } as FilterGroup
    }
  ) as Promise<BasicStoreEntityPublicDashboard>;
};

export const getAllowedMarkings = async (
  context: AuthContext,
  user: AuthUser,
  publicDashboard: BasicStoreEntityPublicDashboard | PublicDashboardCached,
): Promise<StoreMarkingDefinition[]> => {
  const publicDashboardMarkingsIds = publicDashboard.allowed_markings_ids;
  if (!publicDashboardMarkingsIds) {
    return [];
  }
  // get markings from cache
  const markingsMap = await getEntitiesMapFromCache<StoreMarkingDefinition>(context, user, ENTITY_TYPE_MARKING_DEFINITION);
  return publicDashboardMarkingsIds.flatMap((id: string) => markingsMap.get(id) || []);
};

export const addPublicDashboard = async (
  context: AuthContext,
  user: AuthUser,
  input: PublicDashboardAddInput,
) => {
  // Get private dashboard manifest
  const dashboard: BasicStoreEntityWorkspace = await internalLoadById(
    context,
    user,
    input.dashboard_id,
  );
  if (!dashboard) {
    throw FunctionalError('Cannot find dashboard', { id: input.dashboard_id });
  }
  if (!dashboard.manifest) {
    throw FunctionalError('Cannot publish an empty dashboard', { id: input.dashboard_id });
  }

  const access = getUserAccessRight(user, dashboard);
  if (access !== MEMBER_ACCESS_RIGHT_ADMIN) {
    throw ForbiddenAccess();
  }

  // check user allowed markings
  const userMarkingIds = user.allowed_marking.map((m) => m.id);
  if (input.allowed_markings_ids?.some((id) => !userMarkingIds.includes(id))) {
    throw UnsupportedError('Not allowed markings');
  }

  // check user data sharing max markings
  if (input.allowed_markings_ids && input.allowed_markings_ids.length > 0) {
    const markingLevels = await Promise.all(input.allowed_markings_ids.map((id) => {
      return findMarkingDefinitionById(context, user, id);
    }));
    await checkUserCanShareMarkings(context, user, markingLevels);
  }

  const uriKey = input.uri_key.replace(/[^a-zA-Z0-9\s-]+/g, '').replace(/\s+/g, '-').toLowerCase();
  const existingDashboard = await getPublicDashboardByUriKey(context, uriKey);
  if (existingDashboard) {
    throw FunctionalError(`Cannot publish this dashboard, uri key ${uriKey} already used.`);
  }

  const parsedManifest = fromB64(dashboard.manifest ?? '{}');
  if (parsedManifest && isNotEmptyField(parsedManifest.widgets)) {
    Object.keys(parsedManifest.widgets).forEach((widgetId) => {
      parsedManifest.widgets[widgetId].dataSelection = parsedManifest
        .widgets[widgetId]
        .dataSelection.map((selection: any) => {
          return {
            ...(selection.label && { label: selection.label }),
            ...(selection.attribute && { attribute: selection.attribute }),
            ...(selection.date_attribute && { date_attribute: selection.date_attribute }),
            ...(selection.number && { number: selection.number }),
            ...(selection.centerLat && { centerLat: selection.centerLat }),
            ...(selection.centerLng && { centerLng: selection.centerLng }),
            ...(selection.zoom && { zoom: selection.zoom }),
            ...(selection.columns && { columns: selection.columns }),
          };
        });
    });
  }

  // Create public manifest
  const publicManifest = toB64(parsedManifest ?? '{}');

  // Create publicDashboard
  const publicDashboardToCreate = {
    name: input.name,
    enabled: input.enabled,
    description: input.description,
    public_manifest: publicManifest,
    private_manifest: dashboard.manifest,
    dashboard_id: input.dashboard_id,
    user_id: user.id,
    uri_key: uriKey,
    allowed_markings_ids: input.allowed_markings_ids,
  };

  const created = await createEntity(
    context,
    user,
    publicDashboardToCreate,
    ENTITY_TYPE_PUBLIC_DASHBOARD,
  );

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `creates public dashboard \`${created.name}\``,
    context_data: {
      id: created.id,
      entity_type: ENTITY_TYPE_PUBLIC_DASHBOARD,
      input,
    },
  });

  return notify(BUS_TOPICS[ENTITY_TYPE_PUBLIC_DASHBOARD].ADDED_TOPIC, created, user);
};

export const publicDashboardEditField = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
  input: EditInput[],
) => {
  await checkUserIsAdminOnDashboard(context, user, id);
  const { element } = await updateAttribute(
    context,
    user,
    id,
    ENTITY_TYPE_PUBLIC_DASHBOARD,
    input,
  );

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: 'Update public dashboard',
    context_data: { id: element.id, entity_type: ENTITY_TYPE_PUBLIC_DASHBOARD, input },
  });

  return notify(BUS_TOPICS[ENTITY_TYPE_PUBLIC_DASHBOARD].EDIT_TOPIC, element, user);
};

export const publicDashboardDelete = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkUserIsAdminOnDashboard(context, user, id);
  const deleted = await deleteElementById(
    context,
    user,
    id,
    ENTITY_TYPE_PUBLIC_DASHBOARD,
  );

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'extended',
    message: `deletes public dashboard \`${deleted.name}\``,
    context_data: {
      id: deleted.id,
      entity_type: ENTITY_TYPE_PUBLIC_DASHBOARD,
      input: deleted,
    },
  });

  return notify(BUS_TOPICS[ENTITY_TYPE_PUBLIC_DASHBOARD].DELETE_TOPIC, deleted, user).then(() => id);
};

// region Widgets Public API
const ensurePublicContext = async (context: AuthContext, uriKey: string, widgetId: string) => {
  const { user, dataSelection, parameters } = await getWidgetArguments(context, uriKey, widgetId);
  context.user = user;
  context.user_inside_platform_organization = true;
  context.batch = computeLoaders(context, user);

  return { user, dataSelection, parameters };
};

// heatmap & vertical-bar & line & area
export const publicStixCoreObjectsMultiTimeSeries = async (context: AuthContext, args: QueryPublicStixCoreObjectsMultiTimeSeriesArgs) => {
  const { user, dataSelection, parameters } = await ensurePublicContext(context, args.uriKey, args.widgetId);

  const timeSeriesParameters = dataSelection.map((selection) => {
    return { field: selection.date_attribute, filters: selection.filters };
  });
  const standardArgs = {
    startDate: args.startDate,
    endDate: args.endDate,
    interval: parameters?.interval ?? 'day',
    timeSeriesParameters
  };
  // Use standard API
  return stixCoreObjectsMultiTimeSeries(context, user, standardArgs);
};

export const publicStixRelationshipsMultiTimeSeries = async (
  context: AuthContext,
  args: QueryPublicStixRelationshipsMultiTimeSeriesArgs,
) => {
  const { user, dataSelection, parameters } = await ensurePublicContext(context, args.uriKey, args.widgetId);

  const timeSeriesParameters = dataSelection.map((selection) => {
    const filters = {
      filterGroups: [selection.filters],
      filters: [],
      mode: 'and'
    };
    return {
      field: selection.date_attribute,
      filters,
      dynamicFrom: selection.dynamicFrom,
      dynamicTo: selection.dynamicTo,
    };
  });

  const standardArgs = {
    operation: 'count',
    startDate: args.startDate,
    endDate: args.endDate,
    interval: parameters?.interval ?? 'day',
    timeSeriesParameters
  };

  // Use standard API
  return stixRelationshipsMultiTimeSeries(context, user, standardArgs);
};

// number
export const publicStixCoreObjectsNumber = async (
  context: AuthContext,
  args: QueryPublicStixCoreObjectsNumberArgs
): Promise<NumberResult> => {
  const { user, dataSelection } = await ensurePublicContext(context, args.uriKey, args.widgetId);

  const selection = dataSelection[0];
  const { filters } = selection;

  const parameters = {
    dateAttribute: selection.date_attribute,
    startDate: args.startDate,
    endDate: daysAgo(1),
    filters,
    types: [
      ABSTRACT_STIX_CORE_OBJECT,
    ]
  };

  // Use standard API
  return stixCoreObjectsNumber(context, user, parameters) as unknown as Promise<NumberResult>;
};

export const publicStixRelationshipsNumber = async (
  context: AuthContext,
  args: QueryPublicStixRelationshipsNumberArgs
): Promise<NumberResult> => {
  const { user, dataSelection } = await ensurePublicContext(context, args.uriKey, args.widgetId);

  const selection = dataSelection[0];
  const { filters } = selection;

  const parameters = {
    startDate: args.startDate,
    endDate: daysAgo(1),
    filters,
    dateAttribute: selection.date_attribute,
    dynamicFrom: selection.dynamicFrom,
    dynamicTo: selection.dynamicTo,
  };

  // Use standard API
  return stixRelationshipsNumber(context, user, parameters) as unknown as Promise<NumberResult>;
};

// donut & horizontal-bar & distribution-list & radar & tree
export const publicStixCoreObjectsDistribution = async (
  context: AuthContext,
  args: QueryPublicStixCoreObjectsDistributionArgs
) => {
  const { user, dataSelection } = await ensurePublicContext(context, args.uriKey, args.widgetId);

  const mainSelection = dataSelection[0];
  const breakdownSelection = dataSelection[1];
  const { filters: mainFilters } = mainSelection;

  const parameters = {
    startDate: args.startDate,
    endDate: args.endDate,
    filters: mainFilters,
    toTypes: mainSelection.toTypes,
    field: mainSelection.attribute,
    dateAttribute: mainSelection.date_attribute || 'created_at',
    operation: 'count',
    limit: mainSelection.number ?? 10,
    types: [
      ABSTRACT_STIX_CORE_OBJECT,
    ],
  };

  // Use standard API
  const mainDistribution = await stixCoreObjectsDistribution(context, user, parameters);
  if (!breakdownSelection) {
    // Stop here if there is no breakdown to make with a second selection.
    return mainDistribution;
  }

  return BluePromise.map(
    mainDistribution,
    async (distributionItem) => {
      if (!isStixCoreObject(distributionItem.entity.entity_type)) {
        return distributionItem;
      }

      const breakdownFilters: FilterGroup = {
        filterGroups: breakdownSelection.filters ? [breakdownSelection.filters] : [],
        filters: [{
          key: ['fromId'],
          values: [distributionItem.entity.id],
          mode: FilterMode.And,
          operator: FilterOperator.Eq,
        }],
        mode: FilterMode.And
      };

      const breakdownParameters = {
        startDate: args.startDate,
        endDate: args.endDate,
        filters: breakdownFilters,
        toTypes: breakdownSelection.toTypes,
        field: breakdownSelection.attribute,
        dateAttribute: breakdownSelection.date_attribute || 'created_at',
        operation: 'count',
        limit: breakdownSelection.number ?? 10,
        types: [
          ABSTRACT_STIX_CORE_OBJECT,
        ],
      };

      return {
        ...distributionItem,
        breakdownDistribution: await stixCoreObjectsDistribution(context, user, breakdownParameters),
      };
    },
    { concurrency: ES_MAX_CONCURRENCY }
  );
};

export const publicStixRelationshipsDistribution = async (
  context: AuthContext,
  args: QueryPublicStixRelationshipsDistributionArgs
) => {
  const { user, dataSelection } = await ensurePublicContext(context, args.uriKey, args.widgetId);

  const mainSelection = dataSelection[0];
  const breakdownSelection = dataSelection[1];
  const { filters: mainFilters } = mainSelection;

  const parameters = {
    operation: 'count',
    field: mainSelection.attribute || 'entity_type', // TODO check for StixRelationshipsDonut
    startDate: args.startDate,
    endDate: args.endDate,
    filters: mainFilters,
    dynamicFrom: mainSelection.dynamicFrom,
    dynamicTo: mainSelection.dynamicTo,
    dateAttribute: mainSelection.date_attribute,
    isTo: mainSelection.isTo,
    limit: mainSelection.number ?? 10,
  };

  // Use standard API
  const mainDistribution = await stixRelationshipsDistribution(context, user, parameters);
  if (!breakdownSelection) {
    // Stop here if there is no breakdown to make with a second selection.
    return mainDistribution;
  }

  return BluePromise.map(
    mainDistribution,
    async (distributionItem) => {
      if (!isStixCoreObject(distributionItem.entity.entity_type)) {
        return distributionItem;
      }

      const breakdownFilters: FilterGroup = {
        filterGroups: breakdownSelection.filters ? [breakdownSelection.filters] : [],
        filters: breakdownSelection.perspective === 'entities' ? [] : [{
          key: ['fromId'],
          values: [distributionItem.entity.id],
          mode: FilterMode.And,
          operator: FilterOperator.Eq,
        }],
        mode: FilterMode.And
      };

      const breakdownParameters = {
        operation: 'count',
        field: breakdownSelection.attribute || 'entity_type',
        startDate: args.startDate,
        endDate: args.endDate,
        filters: breakdownFilters,
        dynamicFrom: breakdownSelection.dynamicFrom,
        dynamicTo: breakdownSelection.dynamicTo,
        dateAttribute: breakdownSelection.date_attribute,
        limit: breakdownSelection.number ?? 10,
      };

      let breakdownDistribution: any;
      if (breakdownSelection.perspective === 'entities') {
        breakdownDistribution = await stixCoreObjectsDistributionByEntity(
          context,
          user,
          {
            ...breakdownParameters,
            types: ['Stix-Core-Object'],
            objectId: distributionItem.entity.id
          }
        );
      } else {
        breakdownDistribution = await stixRelationshipsDistribution(
          context,
          user,
          {
            ...breakdownParameters,
            isTo: breakdownSelection.isTo,
            fromOrToId: distributionItem.entity.id,
          }
        );
      }

      return {
        ...distributionItem,
        breakdownDistribution,
      };
    },
    { concurrency: ES_MAX_CONCURRENCY }
  );
};

// bookmarks
export const publicBookmarks = async (
  context: AuthContext,
  args: QueryPublicBookmarksArgs
) => {
  const { user, dataSelection } = await ensurePublicContext(context, args.uriKey, args.widgetId);

  const selection = dataSelection[0];
  const { filters } = selection;

  const parameters = {
    filters
  };

  // Use standard API
  return bookmarks(context, user, parameters);
};

// list & timeline
export const publicStixCoreObjectsPaginated = async (
  context: AuthContext,
  args: QueryPublicStixCoreObjectsArgs
) => {
  const { user, dataSelection } = await ensurePublicContext(context, args.uriKey, args.widgetId);

  const selection = dataSelection[0];
  const { filters } = selection;

  const parameters = {
    startDate: args.startDate,
    endDate: args.endDate,
    types: [
      ABSTRACT_STIX_CORE_OBJECT,
    ],
    filters,
    orderBy: selection.date_attribute,
    orderMode: 'desc',
    first: selection.number ?? 10,
  };

  // Use standard API
  return findStixCoreObjectPaginated(context, user, parameters);
};

export const publicStixRelationships = async (
  context: AuthContext,
  args: QueryPublicStixRelationshipsArgs
) => {
  const { user, dataSelection } = await ensurePublicContext(context, args.uriKey, args.widgetId);

  const selection = dataSelection[0];
  const { filters } = selection;

  const parameters = {
    startDate: args.startDate,
    endDate: args.endDate,
    filters,
    dynamicFrom: selection.dynamicFrom,
    dynamicTo: selection.dynamicTo,
    orderBy: selection.date_attribute,
    orderMode: 'desc',
    first: 50,
  };

  // Use standard API
  return (await findStixRelationPaginated(context, user, parameters) as unknown as StoreRelationConnection<BasicStoreRelation>);
};
// endregion
