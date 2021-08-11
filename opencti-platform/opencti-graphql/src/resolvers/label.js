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
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { ENTITY_TYPE_LABEL } from '../schema/stixMetaObject';

const labelResolvers = {
  Query: {
    label: (_, { id }, { user }) => findById(user, id),
    labels: (_, args, { user }) => findAll(user, args),
  },
  Label: {
    editContext: (label) => fetchEditContext(label.id),
  },
  Mutation: {
    labelEdit: (_, { id }, { user }) => ({
      delete: () => labelDelete(user, id),
      fieldPatch: ({ input }) => labelEditField(user, id, input),
      contextPatch: ({ input }) => labelEditContext(user, id, input),
      contextClean: () => labelCleanContext(user, id),
    }),
    labelAdd: (_, { input }, { user }) => addLabel(user, input),
  },
  Subscription: {
    label: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
        labelEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS[ENTITY_TYPE_LABEL].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          labelCleanContext(user, id);
        });
      },
    },
  },
};

export default labelResolvers;
