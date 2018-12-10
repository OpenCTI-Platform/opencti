import { BUS_TOPICS } from '../config/conf';
import {
  addIntrusionSet,
  intrusionSetDelete,
  findAll,
  findById,
  markingDefinitions,
  intrusionSetEditContext,
  intrusionSetEditField,
  intrusionSetAddRelation,
  intrusionSetDeleteRelation,
  intrusionSetCleanContext
} from '../domain/intrusionSet';
import { fetchEditContext, pubsub } from '../database/redis';
import { auth, withCancel } from './wrapper';

const intrusionSetResolvers = {
  Query: {
    intrusionSet: auth((_, { id }) => findById(id)),
    intrusionSets: auth((_, args) => findAll(args))
  },
  IntrusionSet: {
    markingDefinitions: (intrusionSet, args) =>
      markingDefinitions(intrusionSet.id, args),
    editContext: auth(intrusionSet => fetchEditContext(intrusionSet.id))
  },
  Mutation: {
    intrusionSetEdit: auth((_, { id }, { user }) => ({
      delete: () => intrusionSetDelete(id),
      fieldPatch: ({ input }) => intrusionSetEditField(id, input),
      contextPatch: ({ input }) => intrusionSetEditContext(user, id, input),
      relationAdd: ({ input }) => intrusionSetAddRelation(id, input),
      relationDelete: ({ relationId }) => intrusionSetDeleteRelation(relationId)
    })),
    intrusionSetAdd: auth((_, { input }, { user }) =>
      addIntrusionSet(user, input)
    )
  },
  Subscription: {
    intrusionSet: {
      resolve: payload => payload.instance,
      subscribe: auth((_, { id }, { user }) => {
        intrusionSetEditContext(user, id);
        return withCancel(
          pubsub.asyncIterator(BUS_TOPICS.IntrusionSet.EDIT_TOPIC),
          () => {
            intrusionSetCleanContext(user, id);
          }
        );
      })
    }
  }
};

export default intrusionSetResolvers;
