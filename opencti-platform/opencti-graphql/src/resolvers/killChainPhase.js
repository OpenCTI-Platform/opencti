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
import { fetchEditContext } from '../database/redis';
import { subscribeToInstanceEvents } from '../graphql/subscriptionWrapper';
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
      resolve: /* v8 ignore next */ (payload) => payload.instance,
      subscribe: /* v8 ignore next */ (_, { id }, context) => {
        const preFn = () => killChainPhaseEditContext(context, context.user, id);
        const cleanFn = () => killChainPhaseCleanContext(context, context.user, id);
        const bus = BUS_TOPICS[ENTITY_TYPE_KILL_CHAIN_PHASE];
        return subscribeToInstanceEvents(_, context, id, [bus.EDIT_TOPIC], { type: ENTITY_TYPE_KILL_CHAIN_PHASE, preFn, cleanFn });
      },
    },
  },
};

export default killChainPhaseResolvers;
