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
  Distribution,
  StixDomainObjectConnection,
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
  // Removing the "dataSelection" key
  if (parsedManifest && isNotEmptyField(parsedManifest.widgets)) {
    Object.keys(parsedManifest.widgets).forEach((widgetId) => {
      delete parsedManifest.widgets[widgetId].dataSelection;
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
  const { user, config, timeSeriesParameters } = await getWidgetArguments(context, args.uriKey, args.widgetId, true);

  const standardArgs = {
    startDate: args.startDate,
    endDate: args.endDate,
    interval: config.interval,
    timeSeriesParameters
  };

  // Use standard API
  return stixCoreObjectsMultiTimeSeries(context, user, standardArgs);
};

export const publicStixRelationshipsMultiTimeSeries = async (
  context: AuthContext,
  args: QueryPublicStixRelationshipsMultiTimeSeriesArgs,
) => {
  const { user, config, timeSeriesParameters } = await getWidgetConfig(context, args.uriKey, args.widgetId, true);

  const standardArgs = {
    operation: '', // todo needed?
    startDate: args.startDate,
    endDate: args.endDate,
    interval: config.interval ? config.interval : 'month', // Todo should be in config but is is not
    onlyInferred: config.onlyInferred, // todo needed?
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
  const { user, config, filters, dateAttribute } = await getWidgetArguments(context, args.uriKey, args.widgetId);

  const parameters = {
    dateAttribute,
    startDate: args.startDate,
    endDate: args.endDate,
    filters,
    onlyInferred: config.onlyInferred,
    search: config.search,
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
  const { user, config, filters } = await getWidgetConfig(context, args.uriKey, args.widgetId);

  const parameters = { // TODO check args really needed given from front
    dateAttribute: args.dateAttribute,
    authorId: args.authorId,
    noDirection: args.noDirection,
    startDate: args.startDate,
    endDate: args.endDate,
    filters,
    onlyInferred: config.onlyInferred,
    search: config.search,
    fromOrToId: args.fromOrToId,
    elementWithTargetTypes: args.elementWithTargetTypes,
    fromId: args.fromId,
    fromRole: args.fromRole,
    fromTypes: args.fromTypes,
    toId: args.toId,
    toRole: args.toRole,
    toTypes: args.toTypes,
    relationship_type: args.relationship_type,
    confidences: args.confidences,
    dynamicFrom: args.dynamicFrom, // TODO args??
    dynamicTo: args.dynamicTo, // TODO args??
  };

  // Use standard API
  return stixRelationshipsNumber(context, user, parameters) as unknown as Promise<NumberResult>;
};

// donut & horizontal-bar & distribution-list & radar & tree
export const publicStixCoreObjectsDistribution = async (
  context: AuthContext,
  args: QueryPublicStixCoreObjectsDistributionArgs
) => {
  const { user, config, filters } = await getWidgetConfig(context, args.uriKey, args.widgetId);

  const parameters = {
    startDate: args.startDate,
    endDate: args.endDate,
    filters,
    relationship_type: args.relationship_type,
    toTypes: args.toTypes,
    field: 'entity_type', // TODO check: harcoded because it has always this value in front network
    dateAttribute: args.dateAttribute,
    operation: args.operation ? args.operation : 'count', // TODO check
    limit: args.limit,
    order: args.order,
    types: [
      ABSTRACT_STIX_CORE_OBJECT,
    ],
    search: config.search,
  };

  // Use standard API
  return stixCoreObjectsDistribution(context, user, parameters);
};

export const publicStixRelationshipsDistribution = async (
  context: AuthContext,
  args: QueryPublicStixRelationshipsDistributionArgs
) => {
  const { user, config, filters } = await getWidgetConfig(context, args.uriKey, args.widgetId);

  const parameters = {
    operation: 'count', // TODO check
    field: 'entity_type', // TODO check
    startDate: args.startDate,
    endDate: args.endDate,
    filters,
    dynamicFrom: args.dynamicFrom, // TODO check
    dynamicTo: args.dynamicTo, // TODO check
    dateAttribute: args.dateAttribute,
    isTo: args.isTo,
    limit: args.limit,
    elementWithTargetTypes: args.elementWithTargetTypes,
    fromRole: args.fromRole,
    fromTypes: args.fromTypes,
    toId: args.toId,
    toRole: args.toRole,
    toTypes: args.toTypes,
    relationship_type: args.relationship_type,
    confidences: args.confidences,
    order: args.order,
    search: config.search,
  };

  // Use standard API
  return stixRelationshipsDistribution(context, user, parameters);
};

// bookmarks
export const publicBookmarks = async (
  context: AuthContext,
  args: QueryPublicBookmarksArgs
) => {
  const { user, filters } = await getWidgetConfig(context, args.uriKey, args.widgetId);

  const parameters = {
    first: args.first,
    after: args.after,
    types: args.types,
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
  const { user, config, filters } = await getWidgetConfig(context, args.uriKey, args.widgetId);

  const parameters = {
    first: args.first,
    after: args.after,
    types: [
      ABSTRACT_STIX_CORE_OBJECT,
    ],
    filters,
    orderBy: args.orderBy,
    orderMode: args.orderMode,
    search: config.search,
  };

  // Use standard API
  return stixCoreObjects(context, user, parameters);
};

export const publicStixRelationships = async (
  context: AuthContext,
  args: QueryPublicStixRelationshipsArgs
) => {
  const { user, config, filters } = await getWidgetConfig(context, args.uriKey, args.widgetId);

  const parameters = {
    first: args.first,
    after: args.after,
    types: [
      ABSTRACT_STIX_CORE_OBJECT,
    ],
    filters,
    dynamicFrom: args.dynamicFrom, // TODO check
    dynamicTo: args.dynamicTo, // TODO check
    startDate: args.startDate,
    endDate: args.endDate,
    orderBy: args.orderBy,
    orderMode: args.orderMode,
    search: config.search,
    fromOrToId: args.fromOrToId,
    elementWithTargetTypes: args.elementWithTargetTypes,
    fromId: args.fromId,
    fromRole: args.fromRole,
    fromTypes: args.fromTypes,
    toId: args.toId,
    toRole: args.toRole,
    toTypes: args.toTypes,
    relationship_type: args.relationship_type,
    startTimeStart: args.startTimeStart,
    startTimeStop: args.startTimeStop,
    stopTimeStart: args.stopTimeStart,
    stopTimeStop: args.stopTimeStop,
    firstSeenStart: args.firstSeenStart,
    firstSeenStop: args.firstSeenStop,
    lastSeenStart: args.lastSeenStart,
    lastSeenStop: args.lastSeenStop,
    confidences: args.confidences,
    stix: args.stix,
  };

  // Use standard API
  return stixRelationships(context, user, parameters);
};
// endregion
