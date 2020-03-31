import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addMarkingDefinition,
  findAll,
  findById,
  markingDefinitionAddRelation,
  markingDefinitionCleanContext,
  markingDefinitionDelete,
  markingDefinitionDeleteRelation,
  markingDefinitionEditContext,
  markingDefinitionEditField,
} from '../domain/markingDefinition';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';

const markingDefinitionResolvers = {
  Query: {
    markingDefinition: (_, { id }) => findById(id),
    markingDefinitions: (_, args) => findAll(args),
  },
  MarkingDefinitionsFilter: {
    markedBy: `${REL_INDEX_PREFIX}object_marking_refs.internal_id_key`,
  },
  MarkingDefinition: {
    editContext: (markingDefinition) => fetchEditContext(markingDefinition.id),
  },
  Mutation: {
    markingDefinitionEdit: (_, { id }, { user }) => ({
      delete: () => markingDefinitionDelete(id),
      fieldPatch: ({ input }) => markingDefinitionEditField(user, id, input),
      contextPatch: ({ input }) => markingDefinitionEditContext(user, id, input),
      relationAdd: ({ input }) => markingDefinitionAddRelation(user, id, input),
      relationDelete: ({ relationId }) => markingDefinitionDeleteRelation(user, id, relationId),
    }),
    markingDefinitionAdd: (_, { input }, { user }) => addMarkingDefinition(user, input),
  },
  Subscription: {
    markingDefinition: {
      resolve: (payload) => payload.instance,
      subscribe: (_, { id }, { user }) => {
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
