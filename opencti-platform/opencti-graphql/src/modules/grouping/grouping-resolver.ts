import type { Resolvers } from '../../generated/graphql';
import {
  addGrouping,
  findAll,
  findById,
  groupingContainsStixObjectOrStixRelationship,
  groupingsDistributionByEntity,
  groupingsNumber,
  groupingsNumberByAuthor,
  groupingsNumberByEntity,
  groupingsTimeSeries,
  groupingsTimeSeriesByAuthor,
  groupingsTimeSeriesByEntity
} from './grouping-domain';
import { buildRefRelationKey } from '../../schema/general';
import {
  RELATION_CREATED_BY,
  RELATION_OBJECT,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING
} from '../../schema/stixRefRelationship';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField
} from '../../domain/stixDomainObject';
import { distributionEntities } from '../../database/middleware';
import { ENTITY_TYPE_CONTAINER_GROUPING } from './grouping-types';

const groupingResolvers: Resolvers = {
  Query: {
    grouping: (_, { id }, context) => findById(context, context.user, id),
    groupings: (_, args, context) => findAll(context, context.user, args),
    groupingsTimeSeries: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return groupingsTimeSeriesByEntity(context, context.user, args);
      }
      if (args.authorId && args.authorId.length > 0) {
        return groupingsTimeSeriesByAuthor(context, context.user, args);
      }
      return groupingsTimeSeries(context, context.user, args);
    },
    groupingsNumber: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return groupingsNumberByEntity(context, context.user, args);
      }
      if (args.authorId && args.authorId.length > 0) {
        return groupingsNumberByAuthor(context, context.user, args);
      }
      return groupingsNumber(context, context.user, args);
    },
    groupingsDistribution: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return groupingsDistributionByEntity(context, context.user, args);
      }
      return distributionEntities(context, context.user, [ENTITY_TYPE_CONTAINER_GROUPING], args);
    },
    groupingContainsStixObjectOrStixRelationship: (_, args, context) => {
      return groupingContainsStixObjectOrStixRelationship(context, context.user, args.id, args.stixObjectOrStixRelationshipId);
    },
  },
  GroupingsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    objectContains: buildRefRelationKey(RELATION_OBJECT),
  },
  Mutation: {
    groupingAdd: (_, { input }, context) => {
      return addGrouping(context, context.user, input);
    },
    groupingDelete: (_, { id }, context) => {
      return stixDomainObjectDelete(context, context.user, id);
    },
    groupingFieldPatch: (_, { id, input, commitMessage, references }, context) => {
      return stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references });
    },
    groupingContextPatch: (_, { id, input }, context) => {
      return stixDomainObjectEditContext(context, context.user, id, input);
    },
    groupingContextClean: (_, { id }, context) => {
      return stixDomainObjectCleanContext(context, context.user, id);
    },
    groupingRelationAdd: (_, { id, input }, context) => {
      return stixDomainObjectAddRelation(context, context.user, id, input);
    },
    groupingRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
      return stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType);
    },
  }
};

export default groupingResolvers;
