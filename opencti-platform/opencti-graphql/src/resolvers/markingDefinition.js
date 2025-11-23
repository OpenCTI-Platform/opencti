import { BUS_TOPICS } from '../config/conf';
import {
  addAllowedMarkingDefinition,
  findMarkingsPaginated,
  findById,
  markingDefinitionCleanContext,
  markingDefinitionDelete,
  markingDefinitionEditContext,
  markingDefinitionEditField,
} from '../domain/markingDefinition';
import { fetchEditContext } from '../database/redis';
import { subscribeToInstanceEvents } from '../graphql/subscriptionWrapper';
import { stixLoadByIdStringify } from '../database/middleware';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';

const markingDefinitionResolvers = {
  Query: {
    markingDefinition: (_, { id }, context) => findById(context, context.user, id),
    markingDefinitions: (_, args, context) => findMarkingsPaginated(context, context.user, args),
  },
  MarkingDefinition: {
    toStix: (markingDefinition, args, context) => stixLoadByIdStringify(context, context.user, markingDefinition.id, args),
    editContext: (markingDefinition) => fetchEditContext(markingDefinition.id),
  },
  Mutation: {
    markingDefinitionEdit: (_, { id }, context) => ({
      delete: () => markingDefinitionDelete(context, context.user, id),
      fieldPatch: ({ input }) => markingDefinitionEditField(context, context.user, id, input),
      contextPatch: ({ input }) => markingDefinitionEditContext(context, context.user, id, input),
      contextClean: () => markingDefinitionCleanContext(context, context.user, id),
    }),
    markingDefinitionAdd: (_, { input }, context) => addAllowedMarkingDefinition(context, context.user, input),
  },
  Subscription: {
    markingDefinition: {
      resolve: /* v8 ignore next */ (payload) => payload.instance,
      subscribe: /* v8 ignore next */ (_, { id }, context) => {
        const preFn = () => markingDefinitionEditContext(context, context.user, id);
        const cleanFn = () => markingDefinitionCleanContext(context, context.user, id);
        const bus = BUS_TOPICS[ENTITY_TYPE_MARKING_DEFINITION];
        return subscribeToInstanceEvents(_, context, id, [bus.EDIT_TOPIC], { type: ENTITY_TYPE_MARKING_DEFINITION, preFn, cleanFn });
      },
    },
  },
};

export default markingDefinitionResolvers;
