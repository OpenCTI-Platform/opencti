import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addKillChainPhase,
  killChainPhaseDelete,
  findAll,
  findByEntity,
  findById,
  findByPhaseName,
  killChainPhaseEditContext,
  killChainPhaseEditField,
  killChainPhaseAddRelation,
  killChainPhaseDeleteRelation,
  killChainPhaseCleanContext
} from '../domain/killChainPhase';
import { markingDefinitions } from '../domain/stixEntity';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../schema/subscriptionWrapper';

const killChainPhaseResolvers = {
  Query: {
    killChainPhase: (_, { id }) => findById(id),
    killChainPhases: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return findByEntity(args);
      }
      if (args.phaseName && args.phaseName.length > 0) {
        return findByPhaseName(args);
      }
      return findAll(args);
    }
  },
  KillChainPhase: {
    markingDefinitions: (killChainPhase, args) =>
      markingDefinitions(killChainPhase.id, args),
    editContext: killChainPhase => fetchEditContext(killChainPhase.id)
  },
  Mutation: {
    killChainPhaseEdit: (_, { id }, { user }) => ({
      delete: () => killChainPhaseDelete(id),
      fieldPatch: ({ input }) => killChainPhaseEditField(user, id, input),
      contextPatch: ({ input }) => killChainPhaseEditContext(user, id, input),
      contextClean: () => killChainPhaseCleanContext(user, id),
      relationAdd: ({ input }) => killChainPhaseAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        killChainPhaseDeleteRelation(user, id, relationId)
    }),
    killChainPhaseAdd: (_, { input }, { user }) =>
      addKillChainPhase(user, input)
  },
  Subscription: {
    killChainPhase: {
      resolve: payload => payload.instance,
      subscribe: (_, { id }, { user }) => {
        killChainPhaseEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.KillChainPhase.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          killChainPhaseCleanContext(user, id);
        });
      }
    }
  }
};

export default killChainPhaseResolvers;
