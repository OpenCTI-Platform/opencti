import { BUS_TOPICS } from '../config/conf';
import { addLabel, findAll, findById, labelCleanContext, labelDelete, labelEditContext, labelEditField } from '../domain/label';
import { fetchEditContext } from '../database/redis';
import { subscribeToInstanceEvents } from '../graphql/subscriptionWrapper';
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
      resolve: /* v8 ignore next */ (payload) => payload.instance,
      subscribe: /* v8 ignore next */ (_, { id }, context) => {
        const preFn = () => labelEditContext(context, context.user, id);
        const cleanFn = () => labelCleanContext(context, context.user, id);
        const bus = BUS_TOPICS[ENTITY_TYPE_LABEL];
        return subscribeToInstanceEvents(_, context, id, [bus.EDIT_TOPIC], { type: ENTITY_TYPE_LABEL, preFn, cleanFn });
      },
    },
  },
};

export default labelResolvers;
