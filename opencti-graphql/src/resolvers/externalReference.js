import { BUS_TOPICS } from '../config/conf';
import {
  addExternalReference,
  externalReferenceDelete,
  findAll,
  findById,
  externalReferenceEditContext,
  externalReferenceEditField,
  externalReferenceAddRelation,
  externalReferenceDeleteRelation,
  externalReferenceCleanContext
} from '../domain/externalReference';
import { fetchEditContext, pubsub } from '../database/redis';
import { admin, auth, withCancel } from './wrapper';

const externalReferenceResolvers = {
  Query: {
    externalReference: auth((_, { id }) => findById(id)),
    externalReferences: auth((_, args) => findAll(args))
  },
  ExternalReference: {
    editContext: admin(externalReference =>
      fetchEditContext(externalReference.id)
    )
  },
  Mutation: {
    externalReferenceEdit: admin((_, { id }, { user }) => ({
      delete: () => externalReferenceDelete(id),
      fieldPatch: ({ input }) => externalReferenceEditField(id, input),
      contextPatch: ({ input }) =>
        externalReferenceEditContext(user, id, input),
      relationAdd: ({ input }) => externalReferenceAddRelation(id, input),
      relationDelete: ({ relationId }) =>
        externalReferenceDeleteRelation(relationId)
    })),
    externalReferenceAdd: admin((_, { input }, { user }) =>
      addExternalReference(user, input)
    )
  },
  Subscription: {
    externalReference: {
      resolve: payload => payload.instance,
      subscribe: admin((_, { id }, { user }) => {
        externalReferenceEditContext(user, id);
        return withCancel(
          pubsub.asyncIterator(BUS_TOPICS.ExternalReference.EDIT_TOPIC),
          () => {
            externalReferenceCleanContext(user, id);
          }
        );
      })
    }
  }
};

export default externalReferenceResolvers;
