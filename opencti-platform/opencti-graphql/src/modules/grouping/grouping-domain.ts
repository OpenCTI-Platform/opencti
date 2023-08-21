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
  elList,
  EntityOptions,
  internalLoadById,
  listEntitiesPaginated,
  storeLoadById
} from '../../database/middleware-loader';
import { BasicStoreEntityGrouping, ENTITY_TYPE_CONTAINER_GROUPING, GroupingNumberResult } from './grouping-types';
import { isStixId } from '../../schema/schemaUtils';
import { RELATION_CREATED_BY, RELATION_OBJECT } from '../../schema/stixRefRelationship';
import { elCount } from '../../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../../database/utils';
import type { DomainFindById } from '../../domain/domainTypes';
import { addWorkspace } from '../workspace/workspace-domain';

export const findById: DomainFindById<BasicStoreEntityGrouping> = (context: AuthContext, user: AuthUser, channelId: string) => {
  return storeLoadById<BasicStoreEntityGrouping>(context, user, channelId, ENTITY_TYPE_CONTAINER_GROUPING);
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
  const countPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, { ...args, types: [ENTITY_TYPE_CONTAINER_GROUPING] }) as Promise<number>;
  const totalPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, { ...R.dissoc('endDate', args), types: [ENTITY_TYPE_CONTAINER_GROUPING] }) as Promise<number>;
  const [count, total] = await Promise.all([countPromise, totalPromise]);
  return { count, total };
};

export const groupingsTimeSeriesByEntity = (context: AuthContext, user: AuthUser, args: QueryGroupingsTimeSeriesArgs) => {
  const { objectId } = args;
  const filters = [{ key: [buildRefRelationKey(RELATION_OBJECT, '*')], values: [objectId] }, ...(args.filters || [])];
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_GROUPING], { ...args, filters });
};

export const groupingsTimeSeriesByAuthor = async (context: AuthContext, user: AuthUser, args: QueryGroupingsTimeSeriesArgs) => {
  const { authorId } = args;
  const filters = [{ key: [buildRefRelationKey(RELATION_CREATED_BY, '*')], values: [authorId] }, ...(args.filters || [])];
  return timeSeriesEntities(context, user, [ENTITY_TYPE_CONTAINER_GROUPING], { ...args, filters });
};

export const groupingsNumberByEntity = async (context: AuthContext, user: AuthUser, args: QueryGroupingsNumberArgs): Promise<GroupingNumberResult> => {
  const { objectId } = args;
  const filters = [{ key: [buildRefRelationKey(RELATION_OBJECT, '*')], values: [objectId] }, ...(args.filters || [])];
  const countPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, { ...args, types: [ENTITY_TYPE_CONTAINER_GROUPING], filters }) as Promise<number>;
  const totalPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, { ...R.dissoc('endDate', args), types: [ENTITY_TYPE_CONTAINER_GROUPING], filters }) as Promise<number>;
  const [count, total] = await Promise.all([countPromise, totalPromise]);
  return { count, total };
};

export const groupingsNumberByAuthor = async (context: AuthContext, user: AuthUser, args: QueryGroupingsNumberArgs): Promise<GroupingNumberResult> => {
  const { authorId } = args;
  const filters = [{ key: [buildRefRelationKey(RELATION_CREATED_BY, '*')], values: [authorId] }, ...(args.filters || [])];
  const countPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, { ...args, types: [ENTITY_TYPE_CONTAINER_GROUPING], filters }) as Promise<number>;
  const totalPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, { ...R.dissoc('endDate', args), types: [ENTITY_TYPE_CONTAINER_GROUPING], filters }) as Promise<number>;
  const [count, total] = await Promise.all([countPromise, totalPromise]);
  return { count, total };
};

export const groupingsDistributionByEntity = async (context: AuthContext, user: AuthUser, args: QueryGroupingsDistributionArgs) => {
  const { objectId } = args;
  const filters = [{ key: [buildRefRelationKey(RELATION_OBJECT, '*')], values: [objectId] }, ...(args.filters || [])];
  return distributionEntities(context, user, [ENTITY_TYPE_CONTAINER_GROUPING], { ...args, filters });
};

const nameStartedInvestigationFromGrouping = async (context: AuthContext, user: AuthUser, groupingName: string) => {
  const startedInvestigationCanonicalName = `investigation from grouping "${groupingName}"`;
  const investigations: any = await elList(context, user, [READ_INDEX_INTERNAL_OBJECTS], {
    filters: [{
      key: 'entity_type',
      values: ['workspace'],
    }, {
      key: 'type',
      values: ['investigation']
    }]
  });

  const investigationNameToMatch: RegExp = new RegExp(`^${startedInvestigationCanonicalName} (\\d+)$`);
  const highestInvestigationNumber = investigations
    .map((investigation: { name: string; }) => {
      const matches = investigation.name.match(investigationNameToMatch);

      return matches ? Number(matches[1]) : 0;
    })
    .sort((a: number, b: number) => b - a)[0];

  if (highestInvestigationNumber === undefined) {
    return startedInvestigationCanonicalName;
  } if (highestInvestigationNumber === 0) {
    return `${startedInvestigationCanonicalName} 2`;
  }

  return `${startedInvestigationCanonicalName} ${highestInvestigationNumber + 1}`;
};

export const startInvestigation = async (context: AuthContext, user: AuthUser, grouping: BasicStoreEntityGrouping) => {
  const investigationInput = {
    type: 'investigation',
    name: await nameStartedInvestigationFromGrouping(context, user, grouping.name),
    investigated_entities_ids: grouping.object
  };

  return addWorkspace(context, user, investigationInput);
};
// endregion
