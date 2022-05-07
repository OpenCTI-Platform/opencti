import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addMarkingDefinition,
  findAll,
  findById,
  markingDefinitionCleanContext,
  markingDefinitionDelete,
  markingDefinitionEditContext,
  markingDefinitionEditField,
} from '../domain/markingDefinition';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { stixLoadByIdStringify } from '../database/middleware';

const markingDefinitionResolvers = {
  Query: {
    markingDefinition: (_, { id }, { user }) => findById(user, id),
    markingDefinitions: (_, args, { user }) => findAll(user, args),
  },
  MarkingDefinition: {
    toStix: (markingDefinition, _, { user }) => stixLoadByIdStringify(user, markingDefinition.id),
    editContext: (markingDefinition) => fetchEditContext(markingDefinition.id),
  },
  Mutation: {
    markingDefinitionEdit: (_, { id }, { user }) => ({
      delete: () => markingDefinitionDelete(user, id),
      fieldPatch: ({ input }) => markingDefinitionEditField(user, id, input),
      contextPatch: ({ input }) => markingDefinitionEditContext(user, id, input),
      contextClean: () => markingDefinitionCleanContext(user, id),
    }),
    markingDefinitionAdd: (_, { input }, { user }) => addMarkingDefinition(user, input),
  },
  Subscription: {
    markingDefinition: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
        markingDefinitionEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          markingDefinitionCleanContext(user, id);
        });
      },
    },
  },
};

export default markingDefinitionResolvers;
