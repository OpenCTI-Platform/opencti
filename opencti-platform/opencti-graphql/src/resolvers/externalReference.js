import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS, getBaseUrl } from '../config/conf';
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
import { fetchEditContext, pubSubAsyncIterator } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { RELATION_EXTERNAL_REFERENCE } from '../schema/stixMetaRelationship';
import { buildRefRelationKey } from '../schema/general';
import { worksForSource } from '../domain/work';
import { filesListing, loadFile } from '../database/file-storage';
import { askElementEnrichmentForConnector, stixCoreObjectImportPush } from '../domain/stixCoreObject';
import { connectorsForEnrichment } from '../database/repository';

const externalReferenceResolvers = {
  Query: {
    externalReference: (_, { id }, context) => findById(context, context.user, id),
    externalReferences: (_, args, context) => findAll(context, context.user, args),
  },
  ExternalReferencesFilter: {
    usedBy: buildRefRelationKey(RELATION_EXTERNAL_REFERENCE),
    creator: 'creator_id',
  },
  ExternalReference: {
    url: (externalReference, _, context) => {
      if (externalReference.fileId) {
        return getBaseUrl(context.req) + externalReference.url;
      }
      return externalReference.url;
    },
    references: (container, args, context) => references(context, context.user, container.id, args),
    editContext: (externalReference) => fetchEditContext(externalReference.id),
    jobs: (externalReference, args, context) => worksForSource(context, context.user, externalReference.id, args),
    connectors: (externalReference, { onlyAlive = false }, context) => connectorsForEnrichment(context, context.user, externalReference.entity_type, onlyAlive),
    importFiles: async (entity, { first }, context) => {
      const listing = await filesListing(context, context.user, first, `import/${entity.entity_type}/${entity.id}/`);
      if (entity.fileId) {
        try {
          const refFile = await loadFile(context, context.user, entity.fileId);
          listing.edges.unshift({ node: refFile, cursor: '' });
        } catch {
          // FileId is no longer available
        }
      }
      return listing;
    },
    exportFiles: (entity, { first }, context) => {
      return filesListing(context, context.user, first, `export/${entity.entity_type}/${entity.id}/`);
    },
  },
  Mutation: {
    externalReferenceEdit: (_, { id }, context) => ({
      delete: () => externalReferenceDelete(context, context.user, id),
      fieldPatch: ({ input }) => externalReferenceEditField(context, context.user, id, input),
      contextPatch: ({ input }) => externalReferenceEditContext(context, context.user, id, input),
      contextClean: () => externalReferenceCleanContext(context, context.user, id),
      relationAdd: ({ input }) => externalReferenceAddRelation(context, context.user, id, input),
      relationDelete: ({ fromId, relationship_type: relationshipType }) => {
        return externalReferenceDeleteRelation(context, context.user, id, fromId, relationshipType);
      },
      askEnrichment: ({ connectorId }) => askElementEnrichmentForConnector(context, context.user, id, connectorId),
      importPush: ({ file }) => stixCoreObjectImportPush(context, context.user, id, file),
    }),
    externalReferenceAdd: (_, { input }, context) => addExternalReference(context, context.user, input),
  },
  Subscription: {
    externalReference: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, context) => {
        externalReferenceEditContext(context, context.user, id);
        const filtering = withFilter(
          () => pubSubAsyncIterator(BUS_TOPICS.ExternalReference.EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== context.user.id && payload.instance.id === id;
          }
        )(_, { id }, context);
        return withCancel(filtering, () => {
          externalReferenceCleanContext(context, context.user, id);
        });
      },
    },
  },
};

export default externalReferenceResolvers;
