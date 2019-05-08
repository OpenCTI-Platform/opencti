import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixRelation,
  stixRelationDelete,
  findAll,
  findByStixId,
  findById,
  findByIdInferred,
  findAllWithInferences,
  stixRelationsTimeSeries,
  stixRelationsTimeSeriesWithInferences,
  stixRelationsDistribution,
  stixRelationsDistributionWithInferences,
  search,
  reports,
  markingDefinitions,
  locations,
  stixRelationEditContext,
  stixRelationCleanContext,
  stixRelationEditField,
  stixRelationAddRelation
} from '../domain/stixRelation';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../schema/subscriptionWrapper';
import { stixDomainEntityDeleteRelation } from '../domain/stixDomainEntity';

const stixRelationResolvers = {
  Query: {
    stixRelation: (_, { id }) => {
      if (id.length !== 36) {
        return findByIdInferred(id);
      }
      return findById(id);
    },
    stixRelations: (_, args) => {
      if (args.search && args.search.length > 0) {
        return search(args);
      }
      if (args.stix_id && args.stix_id.length > 0) {
        return findByStixId(args);
      }
      if (
        args.resolveInferences &&
        args.resolveRelationRole &&
        args.resolveRelationType
      ) {
        return findAllWithInferences(args);
      }
      return findAll(args);
    },
    stixRelationsTimeSeries: (_, args) => {
      if (
        args.resolveInferences &&
        args.resolveRelationRole &&
        args.resolveRelationType
      ) {
        return stixRelationsTimeSeriesWithInferences(args);
      }
      return stixRelationsTimeSeries(args);
    },
    stixRelationsDistribution: (_, args) => {
      if (
        args.resolveInferences &&
        args.resolveRelationRole &&
        args.resolveRelationType
      ) {
        return stixRelationsDistributionWithInferences(args);
      }
      return stixRelationsDistribution(args);
    }
  },
  StixRelation: {
    markingDefinitions: (stixRelation, args) =>
      markingDefinitions(stixRelation.id, args),
    locations: (stixRelation, args) => locations(stixRelation.id, args),
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
      relationAdd: ({ input }) => stixRelationAddRelation(user, id, input),
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
