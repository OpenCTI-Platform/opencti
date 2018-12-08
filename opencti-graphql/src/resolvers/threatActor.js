import { BUS_TOPICS } from '../config/conf';
import {
  addThreatActor,
  threatActorDelete,
  findAll,
  findById,
  markingDefinitions,
  threatActorEditContext,
  threatActorEditField,
  threatActorAddRelation,
  threatActorDeleteRelation,
  threatActorCleanContext
} from '../domain/threatActor';
import { fetchEditContext, pubsub } from '../database/redis';
import { admin, auth, withCancel } from './wrapper';

const threatActorResolvers = {
  Query: {
    threatActor: auth((_, { id }) => findById(id)),
    threatActors: auth((_, args) => findAll(args))
  },
  ThreatActor: {
    markingDefinitions: (threatActor, args) =>
      markingDefinitions(threatActor.id, args),
    editContext: admin(threatActor => fetchEditContext(threatActor.id))
  },
  Mutation: {
    threatActorEdit: admin((_, { id }, { user }) => ({
      delete: () => threatActorDelete(id),
      fieldPatch: ({ input }) => threatActorEditField(id, input),
      contextPatch: ({ input }) => threatActorEditContext(user, id, input),
      relationAdd: ({ input }) => threatActorAddRelation(id, input),
      relationDelete: ({ relationId }) => threatActorDeleteRelation(relationId)
    })),
    threatActorAdd: admin((_, { input }, { user }) =>
      addThreatActor(user, input)
    )
  },
  Subscription: {
    threatActor: {
      resolve: payload => payload.instance,
      subscribe: admin((_, { id }, { user }) => {
        console.log(`subscribe from ${user.email}`);
        threatActorEditContext(user, id);
        return withCancel(
          pubsub.asyncIterator(BUS_TOPICS.ThreatActor.EDIT_TOPIC),
          () => {
            console.log(`quit from ${user.email}`);
            threatActorCleanContext(user, id);
          }
        );
      })
    }
  }
};

export default threatActorResolvers;
