import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addMarkingDefinition,
  markingDefinitionDelete,
  findAll,
  findById,
  markingDefinitionEditContext,
  markingDefinitionEditField,
  markingDefinitionAddRelation,
  markingDefinitionDeleteRelation,
  markingDefinitionCleanContext
} from '../domain/markingDefinition';
import { fetchEditContext, pubsub } from '../database/redis';
import { admin, auth, withCancel } from './wrapper';

const markingDefinitionResolvers = {
  Query: {
    markingDefinition: auth((_, { id }) => findById(id)),
    markingDefinitions: auth((_, args) => findAll(args))
  },
  MarkingDefinition: {
    editContext: admin(markingDefinition =>
      fetchEditContext(markingDefinition.id)
    )
  },
  Mutation: {
    markingDefinitionEdit: admin((_, { id }, { user }) => ({
      delete: () => markingDefinitionDelete(id),
      fieldPatch: ({ input }) => markingDefinitionEditField(user, id, input),
      contextPatch: ({ input }) =>
        markingDefinitionEditContext(user, id, input),
      relationAdd: ({ input }) => markingDefinitionAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        markingDefinitionDeleteRelation(user, id, relationId)
    })),
    markingDefinitionAdd: admin((_, { input }, { user }) =>
      addMarkingDefinition(user, input)
    )
  },
  Subscription: {
    markingDefinition: {
      resolve: payload => payload.instance,
      subscribe: admin((_, { id }, { user }) => {
        markingDefinitionEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          markingDefinitionCleanContext(user, id);
        });
      })
    }
  }
};

export default markingDefinitionResolvers;
