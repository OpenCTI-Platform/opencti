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
import { fetchEditContext, pubSubAsyncIterator } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { ENTITY_TYPE_KILL_CHAIN_PHASE } from '../schema/stixMetaObject';

const killChainPhaseResolvers = {
  Query: {
    killChainPhase: (_, { id }, context) => findById(context, context.user, id),
    killChainPhases: (_, args, context) => findAll(context, context.user, args),
  },
  KillChainPhase: {
    editContext: (killChainPhase) => fetchEditContext(killChainPhase.id),
  },
  Mutation: {
    killChainPhaseEdit: (_, { id }, context) => ({
      delete: () => killChainPhaseDelete(context, context.user, id),
      fieldPatch: ({ input }) => killChainPhaseEditField(context, context.user, id, input),
      contextPatch: ({ input }) => killChainPhaseEditContext(context, context.user, id, input),
      contextClean: () => killChainPhaseCleanContext(context, context.user, id),
      relationAdd: ({ input }) => killChainPhaseAddRelation(context, context.user, id, input),
      relationDelete: ({ relationId }) => killChainPhaseDeleteRelation(context, context.user, id, relationId),
    }),
    killChainPhaseAdd: (_, { input }, context) => addKillChainPhase(context, context.user, input),
  },
  Subscription: {
    killChainPhase: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, context) => {
        killChainPhaseEditContext(context, context.user, id);
        const filtering = withFilter(
          () => pubSubAsyncIterator(BUS_TOPICS[ENTITY_TYPE_KILL_CHAIN_PHASE].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== context.user.id && payload.instance.id === id;
          }
        )(_, { id }, context);
        return withCancel(filtering, () => {
          killChainPhaseCleanContext(context, context.user, id);
        });
      },
    },
  },
};

export default killChainPhaseResolvers;
