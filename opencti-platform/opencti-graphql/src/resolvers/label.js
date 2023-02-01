import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addLabel,
  findAll,
  findById,
  labelCleanContext,
  labelDelete,
  labelEditContext,
  labelEditField,
} from '../domain/label';
import { fetchEditContext, pubSubAsyncIterator } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { ENTITY_TYPE_LABEL } from '../schema/stixMetaObject';

const labelResolvers = {
  Query: {
    label: (_, { id }, context) => findById(context, context.user, id),
    labels: (_, args, context) => findAll(context, context.user, args),
  },
  Label: {
    editContext: (label) => fetchEditContext(label.id),
  },
  Mutation: {
    labelEdit: (_, { id }, context) => ({
      delete: () => labelDelete(context, context.user, id),
      fieldPatch: ({ input }) => labelEditField(context, context.user, id, input),
      contextPatch: ({ input }) => labelEditContext(context, context.user, id, input),
      contextClean: () => labelCleanContext(context, context.user, id),
    }),
    labelAdd: (_, { input }, context) => addLabel(context, context.user, input),
  },
  Subscription: {
    label: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, context) => {
        labelEditContext(context, context.user, id);
        const filtering = withFilter(
          () => pubSubAsyncIterator(BUS_TOPICS[ENTITY_TYPE_LABEL].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== context.user.id && payload.instance.id === id;
          }
        )(_, { id }, context);
        return withCancel(filtering, () => {
          labelCleanContext(context, context.user, id);
        });
      },
    },
  },
};

export default labelResolvers;
