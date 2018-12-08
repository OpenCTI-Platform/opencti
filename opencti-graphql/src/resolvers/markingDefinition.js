import { BUS_TOPICS } from '../config/conf';
import {
  addMarkingDefinition,
  markingDefinitionDelete,
  findAll,
  findById,
  markingDefinitions,
  killChainPhases,
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
    editContext: admin(markingDefinition => fetchEditContext(markingDefinition.id))
  },
  Mutation: {
    markingDefinitionEdit: admin((_, { id }, { user }) => ({
      delete: () => markingDefinitionDelete(id),
      fieldPatch: ({ input }) => markingDefinitionEditField(id, input),
      contextPatch: ({ input }) => markingDefinitionEditContext(user, id, input),
      relationAdd: ({ input }) => markingDefinitionAddRelation(id, input),
      relationDelete: ({ relationId }) => markingDefinitionDeleteRelation(relationId)
    })),
    markingDefinitionAdd: admin((_, { input }, { user }) => addMarkingDefinition(user, input))
  },
  Subscription: {
    markingDefinition: {
      resolve: payload => payload.instance,
      subscribe: admin((_, { id }, { user }) => {
        console.log('subscribe from ' + user.email);
        markingDefinitionEditContext(user, id);
        return withCancel(
          pubsub.asyncIterator(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC),
          () => {
            console.log('quit from ' + user.email);
            markingDefinitionCleanContext(user, id);
          }
        );
      })
    }
  }
};

export default markingDefinitionResolvers;
