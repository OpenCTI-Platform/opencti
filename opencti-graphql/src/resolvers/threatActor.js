import { withFilter } from 'graphql-subscriptions';
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
import { auth, withCancel } from './wrapper';

const threatActorResolvers = {
  Query: {
    threatActor: auth((_, { id }) => findById(id)),
    threatActors: auth((_, args) => findAll(args))
  },
  ThreatActor: {
    markingDefinitions: (threatActor, args) =>
      markingDefinitions(threatActor.id, args),
    editContext: auth(threatActor => fetchEditContext(threatActor.id))
  },
  Mutation: {
    threatActorEdit: auth((_, { id }, { user }) => ({
      delete: () => threatActorDelete(id),
      fieldPatch: ({ input }) => threatActorEditField(user, id, input),
      contextPatch: ({ input }) => threatActorEditContext(user, id, input),
      relationAdd: ({ input }) => threatActorAddRelation(user, id, input),
      relationDelete: ({ relationId }) => threatActorDeleteRelation(relationId)
    })),
    threatActorAdd: auth((_, { input }, { user }) =>
      addThreatActor(user, input)
    )
  },
  Subscription: {
    threatActor: {
      resolve: payload => payload.instance,
      subscribe: auth((_, { id }, { user }) => {
        threatActorEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.ThreatActor.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          threatActorCleanContext(user, id);
        });
      })
    }
  }
};

export default threatActorResolvers;
