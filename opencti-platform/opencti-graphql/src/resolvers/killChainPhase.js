import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addKillChainPhase,
  findAll,
  findById,
  killChainPhaseAddRelation,
  killChainPhaseCleanContext,
  killChainPhaseDelete,
  killChainPhaseDeleteRelation,
  killChainPhaseEditContext,
  killChainPhaseEditField,
} from '../domain/killChainPhase';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { ENTITY_TYPE_KILL_CHAIN_PHASE } from '../schema/stixMetaObject';

const killChainPhaseResolvers = {
  Query: {
    killChainPhase: (_, { id }, { user }) => findById(user, id),
    killChainPhases: (_, args, { user }) => findAll(user, args),
  },
  KillChainPhase: {
    editContext: (killChainPhase) => fetchEditContext(killChainPhase.id),
  },
  Mutation: {
    killChainPhaseEdit: (_, { id }, { user }) => ({
      delete: () => killChainPhaseDelete(user, id),
      fieldPatch: ({ input }) => killChainPhaseEditField(user, id, input),
      contextPatch: ({ input }) => killChainPhaseEditContext(user, id, input),
      contextClean: () => killChainPhaseCleanContext(user, id),
      relationAdd: ({ input }) => killChainPhaseAddRelation(user, id, input),
      relationDelete: ({ relationId }) => killChainPhaseDeleteRelation(user, id, relationId),
    }),
    killChainPhaseAdd: (_, { input }, { user }) => addKillChainPhase(user, input),
  },
  Subscription: {
    killChainPhase: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
        killChainPhaseEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS[ENTITY_TYPE_KILL_CHAIN_PHASE].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          killChainPhaseCleanContext(user, id);
        });
      },
    },
  },
};

export default killChainPhaseResolvers;
