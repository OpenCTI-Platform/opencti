import { BUS_TOPICS } from '../config/conf';
import {
  addKillChainPhase,
  killChainPhaseDelete,
  findAll,
  findById,
  markingDefinitions,
  killChainPhases,
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
      fieldPatch: ({ input }) => killChainPhaseEditField(id, input),
      contextPatch: ({ input }) => killChainPhaseEditContext(user, id, input),
      relationAdd: ({ input }) => killChainPhaseAddRelation(id, input),
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
        console.log(`subscribe from ${user.email}`);
        killChainPhaseEditContext(user, id);
        return withCancel(
          pubsub.asyncIterator(BUS_TOPICS.KillChainPhase.EDIT_TOPIC),
          () => {
            console.log(`quit from ${user.email}`);
            killChainPhaseCleanContext(user, id);
          }
        );
      })
    }
  }
};

export default killChainPhaseResolvers;
