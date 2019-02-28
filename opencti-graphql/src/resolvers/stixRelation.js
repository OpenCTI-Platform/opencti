import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixRelation,
  stixRelationDelete,
  findAll,
  findByType,
  findById,
  findByIdInferred,
  stixRelationsTimeSeries,
  stixRelationsTimeSeriesByType,
  stixRelationsDistribution,
  stixRelationDistributionByType,
  search,
  reports,
  markingDefinitions,
  locations,
  stixRelationEditContext,
  stixRelationCleanContext,
  stixRelationEditField
} from '../domain/stixRelation';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../schema/subscriptionWrapper';
import {
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation
} from '../domain/stixDomainEntity';

const stixRelationResolvers = {
  Query: {
    stixRelation: (_, { id }) => {
      if (/V(\d+)$/i.exec(id) === null) {
        return findByIdInferred(id);
      }
      return findById(id);
    },
    stixRelations: (_, args) => {
      if (args.search && args.search.length > 0) {
        return search(args);
      }
      if (args.relationType && args.relationType.length > 0) {
        return findByType(args);
      }
      return findAll(args);
    },
    stixRelationsTimeSeries: (_, args) => {
      if (args.relationType && args.relationType.length > 0) {
        return stixRelationsTimeSeriesByType(args);
      }
      return stixRelationsTimeSeries(args);
    },
    stixRelationsDistribution: (_, args) => {
      if (args.relationType && args.relationType.length > 0) {
        return stixRelationDistributionByType(args);
      }
      return stixRelationsDistribution(args);
    }
  },
  StixRelation: {
    markingDefinitions: (stixRelation, args) =>
      markingDefinitions(stixRelation.id, args),
    locations: (stixRelation, args) =>
      locations(stixRelation.id, args),
    reports: (stixRelation, args) => {
      if (/V(\d+)$/i.exec(stixRelation.id) !== null) {
        return reports(stixRelation.id, args);
      }
      return null;
    },
    editContext: stixRelation => fetchEditContext(stixRelation.id)
  },
  Mutation: {
    stixRelationEdit: (_, { id }, { user }) => ({
      delete: () => stixRelationDelete(id),
      fieldPatch: ({ input }) => stixRelationEditField(user, id, input),
      contextPatch: ({ input }) => stixRelationEditContext(user, id, input),
      contextClean: () => stixRelationCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    }),
    stixRelationAdd: (_, { input }, { user }) => addStixRelation(user, input)
  },
  Subscription: {
    stixRelation: {
      resolve: payload => payload.instance,
      subscribe: (_, { id }, { user }) => {
        stixRelationEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.StixRelation.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          stixRelationCleanContext(user, id);
        });
      }
    }
  }
};

export default stixRelationResolvers;
