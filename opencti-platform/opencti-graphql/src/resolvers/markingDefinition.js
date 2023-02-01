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
import { fetchEditContext, pubSubAsyncIterator } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { stixLoadByIdStringify } from '../database/middleware';

const markingDefinitionResolvers = {
  Query: {
    markingDefinition: (_, { id }, context) => findById(context, context.user, id),
    markingDefinitions: (_, args, context) => findAll(context, context.user, args),
  },
  MarkingDefinition: {
    toStix: (markingDefinition, _, context) => stixLoadByIdStringify(context, context.user, markingDefinition.id),
    editContext: (markingDefinition) => fetchEditContext(markingDefinition.id),
  },
  Mutation: {
    markingDefinitionEdit: (_, { id }, context) => ({
      delete: () => markingDefinitionDelete(context, context.user, id),
      fieldPatch: ({ input }) => markingDefinitionEditField(context, context.user, id, input),
      contextPatch: ({ input }) => markingDefinitionEditContext(context, context.user, id, input),
      contextClean: () => markingDefinitionCleanContext(context, context.user, id),
    }),
    markingDefinitionAdd: (_, { input }, context) => addMarkingDefinition(context, context.user, input),
  },
  Subscription: {
    markingDefinition: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, context) => {
        markingDefinitionEditContext(context, context.user, id);
        const filtering = withFilter(
          () => pubSubAsyncIterator(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== context.user.id && payload.instance.id === id;
          }
        )(_, { id }, context);
        return withCancel(filtering, () => {
          markingDefinitionCleanContext(context, context.user, id);
        });
      },
    },
  },
};

export default markingDefinitionResolvers;
