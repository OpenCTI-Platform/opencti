import * as R from 'ramda';
import {
  batchListThroughGetTo,
  deleteElementById,
  distributionRelations,
  timeSeriesRelations
} from '../database/middleware';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_RELATIONSHIP, ENTITY_TYPE_IDENTITY } from '../schema/general';
import { buildEntityFilters, listEntities, listRelations, storeLoadById } from '../database/middleware-loader';
import { STIX_SPEC_VERSION } from '../database/stix';
import {
  isNotEmptyField,
  READ_INDEX_INFERRED_RELATIONSHIPS,
  READ_INDEX_STIX_CORE_RELATIONSHIPS, READ_INDEX_STIX_SIGHTING_RELATIONSHIPS
} from '../database/utils';
import { elCount } from '../database/engine';
import { RELATION_CREATED_BY, RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';

export const findAll = async (context, user, args) => {
  return listRelations(context, user, R.propOr(ABSTRACT_STIX_RELATIONSHIP, 'relationship_type', args), args);
};

export const findById = (context, user, stixRelationshipId) => {
  return storeLoadById(context, user, stixRelationshipId, ABSTRACT_STIX_RELATIONSHIP);
};

export const stixRelationshipDelete = async (context, user, stixRelationshipId) => {
  await deleteElementById(context, user, stixRelationshipId, ABSTRACT_STIX_RELATIONSHIP);
  return stixRelationshipId;
};

// region stats
export const stixRelationshipsDistribution = async (context, user, args) => {
  const { dynamicFrom, dynamicTo } = args;
  let finalArgs = args;
  if (isNotEmptyField(dynamicFrom)) {
    const fromArgs = { connectionFormat: false, first: 500, filters: dynamicFrom };
    const fromIds = await listEntities(context, user, [ABSTRACT_STIX_CORE_OBJECT], fromArgs)
      .then((result) => result.map((n) => n.id));
    if (fromIds.length > 0) {
      finalArgs = { ...finalArgs, fromId: args.fromId ? [...fromIds, args.fromId] : fromIds };
    }
  }
  if (isNotEmptyField(dynamicTo)) {
    const toArgs = { connectionFormat: false, first: 500, filters: dynamicTo };
    const toIds = await listEntities(context, user, [ABSTRACT_STIX_CORE_OBJECT], toArgs)
      .then((result) => result.map((n) => n.id));
    if (toIds.length > 0) {
      finalArgs = { ...finalArgs, toId: args.toId ? [...toIds, args.toId] : toIds };
    }
  }
  return distributionRelations(context, context.user, finalArgs);
};
export const stixRelationshipsNumber = async (context, user, args) => {
  const { relationship_type = [ABSTRACT_STIX_RELATIONSHIP], dynamicFrom, dynamicTo } = args;
  let finalArgs = args;
  if (isNotEmptyField(dynamicFrom)) {
    const fromArgs = { connectionFormat: false, first: 500, filters: dynamicFrom };
    const fromIds = await listEntities(context, user, [ABSTRACT_STIX_CORE_OBJECT], fromArgs)
      .then((result) => result.map((n) => n.id));
    if (fromIds.length > 0) {
      finalArgs = { ...finalArgs, fromId: args.fromId ? [...fromIds, args.fromId] : fromIds };
    }
  }
  if (isNotEmptyField(dynamicTo)) {
    const toArgs = { connectionFormat: false, first: 500, filters: dynamicTo };
    const toIds = await listEntities(context, user, [ABSTRACT_STIX_CORE_OBJECT], toArgs)
      .then((result) => result.map((n) => n.id));
    if (toIds.length > 0) {
      finalArgs = { ...finalArgs, toId: args.toId ? [...toIds, args.toId] : toIds };
    }
  }
  const numberArgs = buildEntityFilters({ ...finalArgs, types: relationship_type });
  // eslint-disable-next-line max-len
  const indices = args.onlyInferred ? [READ_INDEX_INFERRED_RELATIONSHIPS] : [READ_INDEX_STIX_CORE_RELATIONSHIPS, READ_INDEX_STIX_SIGHTING_RELATIONSHIPS, READ_INDEX_INFERRED_RELATIONSHIPS];
  return {
    count: elCount(context, user, indices, numberArgs),
    total: elCount(context, user, indices, R.dissoc('endDate', numberArgs)),
  };
};
export const stixRelationshipsMultiTimeSeries = async (context, user, args) => {
  return Promise.all(args.timeSeriesParameters.map(async (timeSeriesParameter) => {
    const { dynamicFrom, dynamicTo } = timeSeriesParameter;
    let finalTimeSeriesParameter = timeSeriesParameter;
    if (isNotEmptyField(dynamicFrom)) {
      const fromArgs = { connectionFormat: false, first: 500, filters: dynamicFrom };
      const fromIds = await listEntities(context, user, [ABSTRACT_STIX_CORE_OBJECT], fromArgs)
        .then((result) => result.map((n) => n.id));
      if (fromIds.length > 0) {
        finalTimeSeriesParameter = { ...finalTimeSeriesParameter, fromId: args.fromId ? [...fromIds, args.fromId] : fromIds };
      }
    }
    if (isNotEmptyField(dynamicTo)) {
      const toArgs = { connectionFormat: false, first: 500, filters: dynamicTo };
      const toIds = await listEntities(context, user, [ABSTRACT_STIX_CORE_OBJECT], toArgs)
        .then((result) => result.map((n) => n.id));
      if (toIds.length > 0) {
        finalTimeSeriesParameter = { ...finalTimeSeriesParameter, toId: args.toId ? [...toIds, args.toId] : toIds };
      }
    }
    return { data: timeSeriesRelations(context, user, { ...args, ...finalTimeSeriesParameter }) };
  }));
};
// endregion

export const batchCreatedBy = async (context, user, stixCoreRelationshipIds) => {
  const batchCreators = await batchListThroughGetTo(
    context,
    user,
    stixCoreRelationshipIds,
    RELATION_CREATED_BY,
    ENTITY_TYPE_IDENTITY
  );
  return batchCreators.map((b) => (b.edges.length > 0 ? R.head(b.edges).node : null));
};

export const batchMarkingDefinitions = (context, user, stixCoreRelationshipIds) => {
  return batchListThroughGetTo(context, user, stixCoreRelationshipIds, RELATION_OBJECT_MARKING, ENTITY_TYPE_MARKING_DEFINITION);
};

export const getSpecVersionOrDefault = ({ spec_version }) => spec_version ?? STIX_SPEC_VERSION;
