import { v4 as uuidv4 } from 'uuid';
import type { AuthContext, AuthUser } from '../../types/user';
import { internalLoadById, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { ENTITY_TYPE_PUBLIC_DASHBOARD, type BasicStoreEntityPublicDashboard, type PublicDashboardCached } from './publicDashboard-types';
import { createEntity, deleteElementById, loadEntity, updateAttribute } from '../../database/middleware';
import { type BasicStoreEntityWorkspace } from '../workspace/workspace-types';
import { fromBase64, isNotEmptyField, toBase64 } from '../../database/utils';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import type {
  EditInput,
  FilterGroup,
  PublicDashboardAddInput,
  QueryPublicDashboardsArgs,
  QueryPublicStixCoreObjectsNumberArgs,
  QueryPublicStixCoreObjectsMultiTimeSeriesArgs,
  QueryPublicStixRelationshipsMultiTimeSeriesArgs,
  QueryPublicStixRelationshipsNumberArgs,
  QueryPublicStixCoreObjectsDistributionArgs,
  QueryPublicStixRelationshipsDistributionArgs,
  QueryPublicBookmarksArgs,
  QueryPublicStixCoreObjectsArgs,
  QueryPublicStixRelationshipsArgs,
} from '../../generated/graphql';
import { FunctionalError, UnsupportedError } from '../../config/errors';
import { SYSTEM_USER } from '../../utils/access';
import { publishUserAction } from '../../listener/UserActionListener';
import { initializeAuthorizedMembers } from '../workspace/workspace-domain';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import { getEntitiesMapFromCache } from '../../database/cache';
import type { NumberResult, StoreMarkingDefinition } from '../../types/store';
import { getWidgetArguments } from './publicDashboard-utils';
import { stixCoreObjectsDistribution, stixCoreObjectsMultiTimeSeries, stixCoreObjectsNumber, findAll as stixCoreObjects } from '../../domain/stixCoreObject';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import { stixRelationshipsDistribution, stixRelationshipsMultiTimeSeries, stixRelationshipsNumber, findAll as stixRelationships } from '../../domain/stixRelationship';
import { bookmarks } from '../../domain/user';

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

export const findAll = (
  context: AuthContext,
  user: AuthUser,
  args: QueryPublicDashboardsArgs,
) => {
  return listEntitiesPaginated<BasicStoreEntityPublicDashboard>(
    context,
    user,
    [ENTITY_TYPE_PUBLIC_DASHBOARD],
    args,
  );
};

export const getPublicDashboardByUriKey = (
  context: AuthContext,
  uri_key: string,
) => {
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
  // get markings from cache
  const markingsMap = await getEntitiesMapFromCache<StoreMarkingDefinition>(context, user, ENTITY_TYPE_MARKING_DEFINITION);
  const publicDashboardMarkingsIds = publicDashboard.allowed_markings_ids;
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
    throw FunctionalError('Cannot find dashboard');
  }
  if (!dashboard.manifest) {
    throw FunctionalError('Cannot published empty dashboard');
  }

  const parsedManifest = JSON.parse(fromBase64(dashboard.manifest) ?? '{}');
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
          };
        });
    });
  }

  // Create public manifest
  const publicManifest = toBase64(JSON.stringify(parsedManifest) ?? '{}');

  const authorizedMembers = initializeAuthorizedMembers(
    [{ id: user.id, access_right: 'admin' }, { id: 'ALL', access_right: 'view' }],
    user,
  );
  // Create publicDashboard
  const publicDashboardToCreate = {
    name: input.name,
    description: input.description,
    public_manifest: publicManifest,
    private_manifest: dashboard.manifest,
    dashboard_id: input.dashboard_id,
    user_id: user.id,
    uri_key: uuidv4(),
    authorized_members: authorizedMembers,
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
  const invalidInput = input.some((item: EditInput) => item.key !== 'name' && item.key !== 'uri_key');
  if (invalidInput) {
    throw UnsupportedError('Only name and uri_key can be updated');
  }

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
    message: 'Uupdate public dashbaord',
    context_data: { id: element.id, entity_type: ENTITY_TYPE_PUBLIC_DASHBOARD, input },
  });

  return notify(BUS_TOPICS[ENTITY_TYPE_PUBLIC_DASHBOARD].EDIT_TOPIC, element, user);
};

export const publicDashboardDelete = async (context: AuthContext, user: AuthUser, id: string) => {
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

// heatmap & vertical-bar & line & area
export const publicStixCoreObjectsMultiTimeSeries = async (context: AuthContext, args: QueryPublicStixCoreObjectsMultiTimeSeriesArgs) => {
  const { user, parameters, dataSelection } = await getWidgetArguments(context, args.uriKey, args.widgetId);
  const timeSeriesParameters = dataSelection.map((selection: { filters: any; date_attribute: any; }) => {
    const filters = {
      filterGroups: [selection.filters],
      filters: [],
      mode: 'and'
    };
    return {
      field: selection.date_attribute,
      filters,
    };
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
  const { user, parameters, dataSelection } = await getWidgetArguments(context, args.uriKey, args.widgetId);
  const timeSeriesParameters = dataSelection.map((selection: { filters: any; date_attribute: any; }) => {
    const filters = {
      filterGroups: [selection.filters],
      filters: [],
      mode: 'and'
    };
    return {
      field: selection.date_attribute,
      filters,
    };
  });

  const standardArgs = {
    operation: 'count',
    startDate: args.startDate,
    endDate: args.endDate,
    interval: parameters?.interval ? parameters?.interval : 'month',
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
  const { user, dataSelection } = await getWidgetArguments(context, args.uriKey, args.widgetId);

  const selection = dataSelection[0];
  const { filters } = selection;

  const parameters = {
    dateAttribute: selection.date_attribute,
    startDate: args.startDate,
    endDate: args.endDate,
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
  const { user, dataSelection } = await getWidgetArguments(context, args.uriKey, args.widgetId);

  const selection = dataSelection[0];
  const { filters } = selection;

  const parameters = {
    startDate: args.startDate,
    endDate: args.endDate,
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
  const { user, dataSelection } = await getWidgetArguments(context, args.uriKey, args.widgetId);

  const selection = dataSelection[0];
  const { filters } = selection;

  const parameters = {
    startDate: args.startDate,
    endDate: args.endDate,
    filters,
    toTypes: selection.toTypes,
    field: selection.attribute,
    dateAttribute: selection.date_attribute || 'created_at',
    operation: 'count',
    limit: selection.number ?? 10,
    types: [
      ABSTRACT_STIX_CORE_OBJECT,
    ],
  };

  // Use standard API
  return stixCoreObjectsDistribution(context, user, parameters);
};

export const publicStixRelationshipsDistribution = async (
  context: AuthContext,
  args: QueryPublicStixRelationshipsDistributionArgs
) => {
  const { user, dataSelection } = await getWidgetArguments(context, args.uriKey, args.widgetId);
  context.user = user;

  const selection = dataSelection[0];
  const { filters } = selection;

  const parameters = {
    operation: 'count',
    field: selection.attribute || 'entity_type', // TODO check for StixRelationshipsDonut
    startDate: args.startDate,
    endDate: args.endDate,
    filters,
    dynamicFrom: selection.dynamicFrom,
    dynamicTo: selection.dynamicTo,
    dateAttribute: selection.date_attribute,
    isTo: selection.isTo,
    limit: selection.number ?? 10,
  };

  // Use standard API
  return stixRelationshipsDistribution(context, user, parameters);
};

// bookmarks
export const publicBookmarks = async (
  context: AuthContext,
  args: QueryPublicBookmarksArgs
) => {
  const { user, dataSelection } = await getWidgetArguments(context, args.uriKey, args.widgetId);

  const selection = dataSelection[0];
  const { filters } = selection;

  const parameters = {
    filters
  };

  // Use standard API
  return bookmarks(context, user, parameters);
};

// list & timeline
export const publicStixCoreObjects = async (
  context: AuthContext,
  args: QueryPublicStixCoreObjectsArgs
) => {
  const { user, dataSelection } = await getWidgetArguments(context, args.uriKey, args.widgetId);
  context.user = user; // context.user is used in standard api
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
  return stixCoreObjects(context, user, parameters);
};

export const publicStixRelationships = async (
  context: AuthContext,
  args: QueryPublicStixRelationshipsArgs
) => {
  const { user, dataSelection } = await getWidgetArguments(context, args.uriKey, args.widgetId);
  context.user = user;

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
  return stixRelationships(context, user, parameters);
};
// endregion
