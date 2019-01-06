import { BUS_TOPICS } from '../config/conf';
import {
  addExternalReference,
  externalReferenceDelete,
  findAll,
  findAllBySo,
  findById,
  search,
  externalReferenceEditContext,
  externalReferenceEditField,
  externalReferenceAddRelation,
  externalReferenceDeleteRelation,
  externalReferenceCleanContext
} from '../domain/externalReference';
import { fetchEditContext, pubsub } from '../database/redis';
import { auth, withCancel } from './wrapper';

const externalReferenceResolvers = {
  Query: {
    externalReference: auth((_, { id }) => findById(id)),
    externalReferences: auth((_, args) => {
      if (args.search && args.search.length > 0) {
        return search(args);
      }
      return findAll(args);
    }),
    externalReferencesOf: auth((_, args) => findAllBySo(args))
  },
  ExternalReference: {
    editContext: auth(externalReference =>
      fetchEditContext(externalReference.id)
    )
  },
  Mutation: {
    externalReferenceEdit: auth((_, { id }, { user }) => ({
      delete: () => externalReferenceDelete(id),
      fieldPatch: ({ input }) => externalReferenceEditField(id, input),
      contextPatch: ({ input }) =>
        externalReferenceEditContext(user, id, input),
      relationAdd: ({ input }) => externalReferenceAddRelation(id, input),
      relationDelete: ({ relationId }) =>
        externalReferenceDeleteRelation(relationId)
    })),
    externalReferenceAdd: auth((_, { input }, { user }) =>
      addExternalReference(user, input)
    )
  },
  Subscription: {
    externalReference: {
      resolve: payload => payload.instance,
      subscribe: auth((_, { id }, { user }) => {
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
