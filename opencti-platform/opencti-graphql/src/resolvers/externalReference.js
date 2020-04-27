import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addExternalReference,
  externalReferenceAddRelation,
  externalReferenceCleanContext,
  externalReferenceDelete,
  externalReferenceDeleteRelation,
  externalReferenceEditContext,
  externalReferenceEditField,
  findAll,
  findById,
} from '../domain/externalReference';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';

const externalReferenceResolvers = {
  Query: {
    externalReference: (_, { id }) => findById(id),
    externalReferences: (_, args) => findAll(args),
  },
  ExternalReferencesFilter: {
    usedBy: `${REL_INDEX_PREFIX}external_references.internal_id_key`,
  },
  ExternalReference: {
    editContext: (externalReference) => fetchEditContext(externalReference.id),
  },
  Mutation: {
    externalReferenceEdit: (_, { id }, { user }) => ({
      delete: () => externalReferenceDelete(user, id),
      fieldPatch: ({ input }) => externalReferenceEditField(user, id, input),
      contextPatch: ({ input }) => externalReferenceEditContext(user, id, input),
      contextClean: () => externalReferenceCleanContext(user, id),
      relationAdd: ({ input }) => externalReferenceAddRelation(user, id, input),
      relationDelete: ({ relationId }) => externalReferenceDeleteRelation(user, id, relationId),
    }),
    externalReferenceAdd: (_, { input }, { user }) => addExternalReference(user, input),
  },
  Subscription: {
    externalReference: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
        externalReferenceEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.ExternalReference.EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          externalReferenceCleanContext(user, id);
        });
      },
    },
  },
};

export default externalReferenceResolvers;
