import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  references,
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
import { RELATION_EXTERNAL_REFERENCE } from '../schema/stixMetaRelationship';
import { buildRefRelationKey } from '../schema/general';
import { worksForSource } from '../domain/work';
import { filesListing } from '../database/file-storage';
import { askElementEnrichmentForConnector, stixCoreObjectImportPush } from '../domain/stixCoreObject';
import { connectorsForEnrichment } from '../database/repository';

const externalReferenceResolvers = {
  Query: {
    externalReference: (_, { id }, { user }) => findById(user, id),
    externalReferences: (_, args, { user }) => findAll(user, args),
  },
  ExternalReferencesFilter: {
    usedBy: buildRefRelationKey(RELATION_EXTERNAL_REFERENCE),
  },
  ExternalReference: {
    references: (container, args, { user }) => references(user, container.id, args),
    editContext: (externalReference) => fetchEditContext(externalReference.id),
    jobs: (externalReference, args, { user }) => worksForSource(user, externalReference.id, args),
    connectors: (externalReference, { onlyAlive = false }, { user }) => connectorsForEnrichment(user, externalReference.entity_type, onlyAlive),
    importFiles: (entity, { first }, { user }) => filesListing(user, first, `import/${entity.entity_type}/${entity.id}/`),
    exportFiles: (entity, { first }, { user }) => filesListing(user, first, `export/${entity.entity_type}/${entity.id}/`),
  },
  Mutation: {
    externalReferenceEdit: (_, { id }, { user }) => ({
      delete: () => externalReferenceDelete(user, id),
      fieldPatch: ({ input }) => externalReferenceEditField(user, id, input),
      contextPatch: ({ input }) => externalReferenceEditContext(user, id, input),
      contextClean: () => externalReferenceCleanContext(user, id),
      relationAdd: ({ input }) => externalReferenceAddRelation(user, id, input),
      relationDelete: ({ fromId, relationship_type: relationshipType }) => externalReferenceDeleteRelation(user, id, fromId, relationshipType),
      askEnrichment: ({ connectorId }) => askElementEnrichmentForConnector(user, id, connectorId),
      importPush: ({ file }) => stixCoreObjectImportPush(user, id, file),
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
