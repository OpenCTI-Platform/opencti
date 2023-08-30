import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import { createEntity, distributionEntities, timeSeriesEntities } from '../../database/middleware';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../../schema/general';
import type {
  GroupingAddInput,
  QueryGroupingsDistributionArgs,
  QueryGroupingsNumberArgs,
  QueryGroupingsTimeSeriesArgs,
} from '../../generated/graphql';
import {
  type EntityOptions,
  internalLoadById,
  listEntitiesPaginated,
  storeLoadById
} from '../../database/middleware-loader';
import {
  type BasicStoreEntityGrouping,
  ENTITY_TYPE_CONTAINER_GROUPING,
  type GroupingNumberResult
} from './grouping-types';
import { isStixId } from '../../schema/schemaUtils';
import { RELATION_CREATED_BY, RELATION_OBJECT } from '../../schema/stixRefRelationship';
import { elCount } from '../../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../../database/utils';
import type { DomainFindById } from '../../domain/domainTypes';
import { addFilter } from '../../utils/filtering';

export const findById: DomainFindById<BasicStoreEntityGrouping> = (context: AuthContext, user: AuthUser, groupingId: string) => {
  return storeLoadById<BasicStoreEntityGrouping>(context, user, groupingId, ENTITY_TYPE_CONTAINER_GROUPING);
};

export const findAll = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityGrouping>) => {
  return listEntitiesPaginated<BasicStoreEntityGrouping>(context, user, [ENTITY_TYPE_CONTAINER_GROUPING], opts);
};

export const addGrouping = async (context: AuthContext, user: AuthUser, grouping: GroupingAddInput) => {
  const created = await createEntity(context, user, grouping, ENTITY_TYPE_CONTAINER_GROUPING);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

// Entities tab
export const groupingContainsStixObjectOrStixRelationship = async (context: AuthContext, user: AuthUser, groupingId: string, thingId: string) => {
  const resolvedThingId = isStixId(thingId) ? (await internalLoadById(context, user, thingId)).internal_id : thingId;
  const opts: EntityOptions<BasicStoreEntityGrouping> = {
    filters: {
      mode: 'and',
      filters: [
        { key: ['internal_id'], values: [groupingId] },
        { key: [buildRefRelationKey(RELATION_OBJECT)], values: [resolvedThingId] },
      ],
      filterGroups: [],
    },
  };
  const groupingFound = await findAll(context, user, opts);
  return groupingFound.edges.length > 0;
};

// region series
export const groupingsTimeSeries = (context: AuthContext, user: AuthUser, args: QueryGroupingsTimeSeriesArgs) => {
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_GROUPING], args);
};

export const groupingsNumber = async (context: AuthContext, user: AuthUser, args: QueryGroupingsNumberArgs): Promise<GroupingNumberResult> => {
  const countPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, { ...args, types: [ENTITY_TYPE_CONTAINER_GROUPING] }) as Promise<number>;
  const totalPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, { ...R.dissoc('endDate', args), types: [ENTITY_TYPE_CONTAINER_GROUPING] }) as Promise<number>;
  const [count, total] = await Promise.all([countPromise, totalPromise]);
  return { count, total };
};

export const groupingsTimeSeriesByEntity = (context: AuthContext, user: AuthUser, args: QueryGroupingsTimeSeriesArgs) => {
  const { objectId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_OBJECT, '*'), objectId);
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_GROUPING], { ...args, filters });
};

export const groupingsTimeSeriesByAuthor = async (context: AuthContext, user: AuthUser, args: QueryGroupingsTimeSeriesArgs) => {
  const { authorId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_CREATED_BY, '*'), authorId);
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_GROUPING], { ...args, filters });
};

export const groupingsNumberByEntity = async (context: AuthContext, user: AuthUser, args: QueryGroupingsNumberArgs): Promise<GroupingNumberResult> => {
  const { objectId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_OBJECT, '*'), objectId);
  const countPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, { ...args, types: [ENTITY_TYPE_CONTAINER_GROUPING], filters }) as Promise<number>;
  const totalPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, { ...R.dissoc('endDate', args), types: [ENTITY_TYPE_CONTAINER_GROUPING], filters }) as Promise<number>;
  const [count, total] = await Promise.all([countPromise, totalPromise]);
  return { count, total };
};

export const groupingsNumberByAuthor = async (context: AuthContext, user: AuthUser, args: QueryGroupingsNumberArgs): Promise<GroupingNumberResult> => {
  const { authorId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_CREATED_BY, '*'), authorId);
  const countPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, { ...args, types: [ENTITY_TYPE_CONTAINER_GROUPING], filters }) as Promise<number>;
  const totalPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, { ...R.dissoc('endDate', args), types: [ENTITY_TYPE_CONTAINER_GROUPING], filters }) as Promise<number>;
  const [count, total] = await Promise.all([countPromise, totalPromise]);
  return { count, total };
};

export const groupingsDistributionByEntity = async (context: AuthContext, user: AuthUser, args: QueryGroupingsDistributionArgs) => {
  const { objectId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_OBJECT, '*'), objectId);
  return distributionEntities(context, user, [ENTITY_TYPE_CONTAINER_GROUPING], { ...args, filters });
};
// endregion
