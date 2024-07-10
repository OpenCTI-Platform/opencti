import { BUS_TOPICS, getBaseUrl } from '../config/conf';
import {
  addExternalReference,
  externalReferenceAddRelation,
  externalReferenceCleanContext,
  externalReferenceDelete,
  externalReferenceDeleteRelation,
  externalReferenceEditContext,
  externalReferenceEditField,
  externalReferenceImportPush,
  findAll,
  findById,
  references,
} from '../domain/externalReference';
import { fetchEditContext } from '../database/redis';
import { subscribeToInstanceEvents } from '../graphql/subscriptionWrapper';
import { worksForSource } from '../domain/work';
import { loadFile } from '../database/file-storage';
import { askElementEnrichmentForConnector } from '../domain/stixCoreObject';
import { connectorsForEnrichment } from '../database/repository';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../schema/stixMetaObject';
import { paginatedForPathWithEnrichment } from '../modules/internal/document/document-domain';

const externalReferenceResolvers = {
  Query: {
    externalReference: (_, { id }, context) => findById(context, context.user, id),
    externalReferences: (_, args, context) => findAll(context, context.user, args),
  },
  ExternalReference: {
    url: (externalReference, _, context) => {
      if (externalReference.fileId) {
        return getBaseUrl(context.req) + externalReference.url;
      }
      return externalReference.url;
    },
    references: (externalReference, args, context) => references(context, context.user, externalReference.id, args),
    editContext: (externalReference) => fetchEditContext(externalReference.id),
    jobs: (externalReference, args, context) => worksForSource(context, context.user, externalReference.standard_id, args),
    connectors: (externalReference, { onlyAlive = false }, context) => connectorsForEnrichment(context, context.user, externalReference.entity_type, onlyAlive),
    importFiles: async (externalReference, { first }, context) => {
      const opts = { first, entity_type: externalReference.entity_type };
      const listing = await paginatedForPathWithEnrichment(context, context.user, `import/${externalReference.entity_type}/${externalReference.id}`, externalReference.id, opts);
      if (externalReference.fileId) {
        try {
          const refFile = await loadFile(context, context.user, externalReference.fileId);
          listing.edges.unshift({ node: refFile, cursor: '' });
        } catch {
          // FileId is no longer available
        }
      }
      return listing;
    },
    exportFiles: (externalReference, { first }, context) => {
      const opts = { first, entity_type: externalReference.entity_type };
      return paginatedForPathWithEnrichment(context, context.user, `export/${externalReference.entity_type}`, externalReference.id, opts);
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
      importPush: (args) => externalReferenceImportPush(context, context.user, id, args.file, args),
    }),
    externalReferenceAdd: (_, { input }, context) => addExternalReference(context, context.user, input),
  },
  Subscription: {
    externalReference: {
      resolve: /* v8 ignore next */ (payload) => payload.instance,
      subscribe: /* v8 ignore next */ (_, { id }, context) => {
        const preFn = () => externalReferenceEditContext(context, context.user, id);
        const cleanFn = () => externalReferenceCleanContext(context, context.user, id);
        const bus = BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE];
        return subscribeToInstanceEvents(_, context, id, [bus.EDIT_TOPIC], { preFn, cleanFn });
      },
    },
  },
};

export default externalReferenceResolvers;
