import * as R from 'ramda';
import {
  createEntity,
  distributionEntities,
  internalLoadById,
  storeLoadById,
  timeSeriesEntities,
} from '../database/middleware';
import { listEntities } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../schema/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../schema/general';
import { elCount } from '../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { isStixId } from '../schema/schemaUtils';

export const findById = (context, user, groupingId) => {
  return storeLoadById(context, user, groupingId, ENTITY_TYPE_CONTAINER_GROUPING);
};

export const findAll = async (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_CONTAINER_GROUPING], args);
};

// Entities tab
export const groupingContainsStixObjectOrStixRelationship = async (context, user, groupingId, thingId) => {
  const resolvedThingId = isStixId(thingId) ? (await internalLoadById(context, user, thingId)).id : thingId;
  const args = {
    filters: [
      { key: 'internal_id', values: [groupingId] },
      { key: buildRefRelationKey(RELATION_OBJECT), values: [resolvedThingId] },
    ],
  };
  const groupingFound = await findAll(context, user, args);
  return groupingFound.edges.length > 0;
};

// region series
export const groupingsTimeSeries = (context, user, args) => {
  const { groupingClass } = args;
  const filters = groupingClass ? [{ isRelation: false, type: 'grouping_class', value: args.groupingClass }] : [];
  return timeSeriesEntities(context, user, ENTITY_TYPE_CONTAINER_GROUPING, filters, args);
};

export const groupingsNumber = (context, user, args) => ({
  count: elCount(user, READ_INDEX_STIX_DOMAIN_OBJECTS, R.assoc('types', [ENTITY_TYPE_CONTAINER_GROUPING], args)),
  total: elCount(
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    R.pipe(R.assoc('types', [ENTITY_TYPE_CONTAINER_GROUPING]), R.dissoc('endDate'))(args)
  ),
});

export const groupingsTimeSeriesByEntity = (context, user, args) => {
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: args.objectId }];
  return timeSeriesEntities(context, user, ENTITY_TYPE_CONTAINER_GROUPING, filters, args);
};

export const groupingsTimeSeriesByAuthor = async (context, user, args) => {
  const { authorId, groupingClass } = args;
  const filters = [{ isRelation: true, type: RELATION_CREATED_BY, value: authorId }];
  if (groupingClass) filters.push({ isRelation: false, type: 'grouping_class', value: groupingClass });
  return timeSeriesEntities(context, user, ENTITY_TYPE_CONTAINER_GROUPING, filters, args);
};

export const groupingsNumberByEntity = (context, user, args) => ({
  count: elCount(
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    R.pipe(
      R.assoc('isMetaRelationship', true),
      R.assoc('types', [ENTITY_TYPE_CONTAINER_GROUPING]),
      R.assoc('relationshipType', RELATION_OBJECT),
      R.assoc('fromId', args.objectId)
    )(args)
  ),
  total: elCount(
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    R.pipe(
      R.assoc('isMetaRelationship', true),
      R.assoc('types', [ENTITY_TYPE_CONTAINER_GROUPING]),
      R.assoc('relationshipType', RELATION_OBJECT),
      R.assoc('fromId', args.objectId),
      R.dissoc('endDate')
    )(args)
  ),
});

export const groupingsNumberByAuthor = (context, user, args) => ({
  count: elCount(
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    R.pipe(
      R.assoc('isMetaRelationship', true),
      R.assoc('types', [ENTITY_TYPE_CONTAINER_GROUPING]),
      R.assoc('relationshipType', RELATION_CREATED_BY),
      R.assoc('fromId', args.authorId)
    )(args)
  ),
  total: elCount(
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    R.pipe(
      R.assoc('isMetaRelationship', true),
      R.assoc('types', [ENTITY_TYPE_CONTAINER_GROUPING]),
      R.assoc('relationshipType', RELATION_CREATED_BY),
      R.assoc('fromId', args.authorId),
      R.dissoc('endDate')
    )(args)
  ),
});

export const groupingsDistributionByEntity = async (context, user, args) => {
  const { objectId } = args;
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: objectId }];
  return distributionEntities(context, user, ENTITY_TYPE_CONTAINER_GROUPING, filters, args);
};
// endregion

// region mutations
export const addGrouping = async (context, user, grouping) => {
  const created = await createEntity(context, user, grouping, ENTITY_TYPE_CONTAINER_GROUPING);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
// endregion
