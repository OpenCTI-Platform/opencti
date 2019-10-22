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
  stixRelationsNumber,
  search,
  stixRelationEditContext,
  stixRelationCleanContext,
  stixRelationEditField,
  stixRelationAddRelation,
  stixRelationDeleteRelation
} from '../domain/stixRelation';
import { pubsub } from '../database/redis';
import withCancel from '../schema/subscriptionWrapper';
import { getByGraknId } from '../database/grakn';
import { killChainPhases } from '../domain/stixDomainEntity';

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
      if (args.stix_id_key && args.stix_id_key.length > 0) {
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
    },
    stixRelationsNumber: (_, args) => stixRelationsNumber(args)
  },
  StixRelation: {
    killChainPhases: (rel, args) => killChainPhases(rel.id, args),
    from: rel => rel.from || getByGraknId(rel.fromId),
    to: rel => rel.to || getByGraknId(rel.toId)
  },
  Mutation: {
    stixRelationEdit: (_, { id }, { user }) => ({
      delete: () => stixRelationDelete(id),
      fieldPatch: ({ input }) => stixRelationEditField(user, id, input),
      contextPatch: ({ input }) => stixRelationEditContext(user, id, input),
      contextClean: () => stixRelationCleanContext(user, id),
      relationAdd: ({ input }) => stixRelationAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixRelationDeleteRelation(user, id, relationId)
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
