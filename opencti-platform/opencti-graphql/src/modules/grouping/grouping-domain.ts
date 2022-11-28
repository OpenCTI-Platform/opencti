import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import {
  createEntity,
  distributionEntities,
  internalLoadById,
  storeLoadById,
  timeSeriesEntities
} from '../../database/middleware';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../../schema/general';
import type {
  GroupingAddInput,
  QueryGroupingsDistributionArgs,
  QueryGroupingsNumberArgs,
  QueryGroupingsTimeSeriesArgs,
} from '../../generated/graphql';
import { EntityOptions, listEntitiesPaginated } from '../../database/middleware-loader';
import { BasicStoreEntityGrouping, ENTITY_TYPE_CONTAINER_GROUPING, GroupingNumberResult } from './grouping-types';
import { isStixId } from '../../schema/schemaUtils';
import { RELATION_CREATED_BY, RELATION_OBJECT } from '../../schema/stixMetaRelationship';
import { elCount } from '../../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../../database/utils';
import type { BasicStoreCommon } from '../../types/store';

export const findById = (context: AuthContext, user: AuthUser, channelId: string): BasicStoreEntityGrouping => {
  return storeLoadById(context, user, channelId, ENTITY_TYPE_CONTAINER_GROUPING) as unknown as BasicStoreEntityGrouping;
};

export const findAll = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityGrouping>) => {
  return listEntitiesPaginated<BasicStoreEntityGrouping>(context, user, [ENTITY_TYPE_CONTAINER_GROUPING], opts);
};

export const addGrouping = async (context: AuthContext, user: AuthUser, channel: GroupingAddInput) => {
  const created = await createEntity(context, user, channel, ENTITY_TYPE_CONTAINER_GROUPING);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

// Entities tab
export const groupingContainsStixObjectOrStixRelationship = async (context: AuthContext, user: AuthUser, groupingId: string, thingId: string) => {
  const resolvedThingId = isStixId(thingId) ? (await internalLoadById(context, user, thingId) as unknown as BasicStoreCommon).internal_id : thingId;
  const opts: EntityOptions<BasicStoreEntityGrouping> = {
    filters: [
      { key: ['internal_id'], values: [groupingId] },
      { key: [buildRefRelationKey(RELATION_OBJECT)], values: [resolvedThingId] },
    ],
  };
  const groupingFound = await findAll(context, user, opts);
  return groupingFound.edges.length > 0;
};

// region series
export const groupingsTimeSeries = (context: AuthContext, user: AuthUser, args: QueryGroupingsTimeSeriesArgs) => {
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_GROUPING], args);
};

export const groupingsNumber = async (context: AuthContext, user: AuthUser, args: QueryGroupingsNumberArgs): Promise<GroupingNumberResult> => {
  const countOptions = R.assoc('types', [ENTITY_TYPE_CONTAINER_GROUPING], args);
  const countPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, countOptions) as Promise<number>;
  const totalOptions = R.pipe(R.assoc('types', [ENTITY_TYPE_CONTAINER_GROUPING]), R.dissoc('endDate'))(args);
  const totalPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, totalOptions) as Promise<number>;
  const [count, total] = await Promise.all([countPromise, totalPromise]);
  return { count, total };
};

export const groupingsTimeSeriesByEntity = (context: AuthContext, user: AuthUser, args: QueryGroupingsTimeSeriesArgs) => {
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: args.objectId }, ...(args.filters || [])];
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_GROUPING], { ...args, filters });
};

export const groupingsTimeSeriesByAuthor = async (context: AuthContext, user: AuthUser, args: QueryGroupingsTimeSeriesArgs) => {
  const { authorId } = args;
  const filters = [{ isRelation: true, type: RELATION_CREATED_BY, value: authorId }, ...(args.filters || [])];
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_GROUPING], { ...args, filters });
};

export const groupingsNumberByEntity = async (context: AuthContext, user: AuthUser, args: QueryGroupingsNumberArgs): Promise<GroupingNumberResult> => {
  const countOptions = R.pipe(
    R.assoc('isMetaRelationship', true),
    R.assoc('types', [ENTITY_TYPE_CONTAINER_GROUPING]),
    R.assoc('relationshipType', RELATION_OBJECT),
    R.assoc('fromId', args.objectId)
  )(args);
  const countPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, countOptions) as Promise<number>;
  const totalOptions = R.pipe(
    R.assoc('isMetaRelationship', true),
    R.assoc('types', [ENTITY_TYPE_CONTAINER_GROUPING]),
    R.assoc('relationshipType', RELATION_OBJECT),
    R.assoc('fromId', args.objectId),
    R.dissoc('endDate')
  )(args);
  const totalPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, totalOptions) as Promise<number>;
  const [count, total] = await Promise.all([countPromise, totalPromise]);
  return { count, total };
};

export const groupingsNumberByAuthor = async (context: AuthContext, user: AuthUser, args: QueryGroupingsNumberArgs): Promise<GroupingNumberResult> => {
  const countOptions = R.pipe(
    R.assoc('isMetaRelationship', true),
    R.assoc('types', [ENTITY_TYPE_CONTAINER_GROUPING]),
    R.assoc('relationshipType', RELATION_CREATED_BY),
    R.assoc('fromId', args.authorId)
  )(args);
  const countPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, countOptions) as Promise<number>;
  const totalOptions = R.pipe(
    R.assoc('isMetaRelationship', true),
    R.assoc('types', [ENTITY_TYPE_CONTAINER_GROUPING]),
    R.assoc('relationshipType', RELATION_CREATED_BY),
    R.assoc('fromId', args.authorId),
    R.dissoc('endDate')
  )(args);
  const totalPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, totalOptions) as Promise<number>;
  const [count, total] = await Promise.all([countPromise, totalPromise]);
  return { count, total };
};

export const groupingsDistributionByEntity = async (context: AuthContext, user: AuthUser, args: QueryGroupingsDistributionArgs) => {
  const { objectId } = args;
  const filters = [{ isRelation: true, type: RELATION_OBJECT, value: objectId }];
  return distributionEntities(context, user, [ENTITY_TYPE_CONTAINER_GROUPING], { ...args, filters });
};
// endregion
