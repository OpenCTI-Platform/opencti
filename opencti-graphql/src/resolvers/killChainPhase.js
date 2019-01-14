import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addKillChainPhase,
  killChainPhaseDelete,
  findAll,
  findById,
  markingDefinitions,
  killChainPhaseEditContext,
  killChainPhaseEditField,
  killChainPhaseAddRelation,
  killChainPhaseDeleteRelation,
  killChainPhaseCleanContext
} from '../domain/killChainPhase';
import { fetchEditContext, pubsub } from '../database/redis';
import { admin, auth, withCancel } from './wrapper';

const killChainPhaseResolvers = {
  Query: {
    killChainPhase: auth((_, { id }) => findById(id)),
    killChainPhases: auth((_, args) => findAll(args))
  },
  KillChainPhase: {
    markingDefinitions: (killChainPhase, args) =>
      markingDefinitions(killChainPhase.id, args),
    editContext: admin(killChainPhase => fetchEditContext(killChainPhase.id))
  },
  Mutation: {
    killChainPhaseEdit: admin((_, { id }, { user }) => ({
      delete: () => killChainPhaseDelete(id),
      fieldPatch: ({ input }) => killChainPhaseEditField(user, id, input),
      contextPatch: ({ input }) => killChainPhaseEditContext(user, id, input),
      relationAdd: ({ input }) => killChainPhaseAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        killChainPhaseDeleteRelation(relationId)
    })),
    killChainPhaseAdd: admin((_, { input }, { user }) =>
      addKillChainPhase(user, input)
    )
  },
  Subscription: {
    killChainPhase: {
      resolve: payload => payload.instance,
      subscribe: admin((_, { id }, { user }) => {
        killChainPhaseEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.KillChainPhase.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          killChainPhaseCleanContext(user, id);
        });
      })
    }
  }
};

export default killChainPhaseResolvers;
