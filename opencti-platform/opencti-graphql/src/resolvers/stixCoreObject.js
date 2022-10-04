import * as R from 'ramda';
import { withFilter } from 'graphql-subscriptions';
import {
  findById,
  findAll,
  stixCoreObjectAddRelation,
  stixCoreObjectAddRelations,
  stixCoreObjectDeleteRelation,
  stixCoreRelationships,
  stixCoreObjectMerge,
  batchMarkingDefinitions,
  batchLabels,
  batchCreatedBy,
  batchExternalReferences,
  batchNotes,
  batchOpinions,
  batchObservedData,
  batchReports,
  askElementEnrichmentForConnector,
  stixCoreObjectExportAsk,
  stixCoreObjectExportPush,
  stixCoreObjectDelete,
  stixCoreObjectImportPush
} from '../domain/stixCoreObject';
import { creator } from '../domain/log';
import { fetchEditContext, pubsub } from '../database/redis';
import { batchLoader, stixLoadByIdStringify } from '../database/middleware';
import { worksForSource } from '../domain/work';
import { filesListing } from '../database/file-storage';
import { stixDomainObjectCleanContext, stixDomainObjectEditContext } from '../domain/stixDomainObject';
import { BUS_TOPICS } from '../config/conf';
import { ABSTRACT_STIX_CORE_OBJECT } from '../schema/general';
import withCancel from '../graphql/subscriptionWrapper';
import { connectorsForEnrichment } from '../database/repository';

const createdByLoader = batchLoader(batchCreatedBy);
const markingDefinitionsLoader = batchLoader(batchMarkingDefinitions);
const labelsLoader = batchLoader(batchLabels);
const externalReferencesLoader = batchLoader(batchExternalReferences);
const notesLoader = batchLoader(batchNotes);
const opinionsLoader = batchLoader(batchOpinions);
const reportsLoader = batchLoader(batchReports);
const observedDataLoader = batchLoader(batchObservedData);

const stixCoreObjectResolvers = {
  Query: {
    stixCoreObject: (_, { id }, context) => findById(context, context.user, id),
    stixCoreObjectRaw: (_, { id }, context) => stixLoadByIdStringify(context, context.user, id),
    stixCoreObjects: (_, args, context) => findAll(context, context.user, args),
  },
  StixCoreObject: {
    // eslint-disable-next-line
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-|_)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      /* istanbul ignore next */
      return 'Unknown';
    },
    toStix: (stixCoreObject, _, context) => stixLoadByIdStringify(context, context.user, stixCoreObject.id),
    creator: (stixCoreObject, _, context) => creator(context, context.user, stixCoreObject.id, ABSTRACT_STIX_CORE_OBJECT),
    editContext: (stixCoreObject) => fetchEditContext(stixCoreObject.id),
    stixCoreRelationships: (stixCoreObject, args, context) => stixCoreRelationships(context, context.user, stixCoreObject.id, args),
    createdBy: (stixCoreObject, _, context) => createdByLoader.load(stixCoreObject.id, context, context.user),
    objectMarking: (stixCoreObject, _, context) => markingDefinitionsLoader.load(stixCoreObject.id, context, context.user),
    objectLabel: (stixCoreObject, _, context) => labelsLoader.load(stixCoreObject.id, context, context.user),
    externalReferences: (stixCoreObject, _, context) => externalReferencesLoader.load(stixCoreObject.id, context, context.user),
    reports: (stixCoreObject, args, context) => reportsLoader.load(stixCoreObject.id, context, context.user, args),
    notes: (stixCoreObject, _, context) => notesLoader.load(stixCoreObject.id, context, context.user),
    opinions: (stixCoreObject, _, context) => opinionsLoader.load(stixCoreObject.id, context, context.user),
    observedData: (stixCoreObject, _, context) => observedDataLoader.load(stixCoreObject.id, context, context.user),
    jobs: (stixCoreObject, args, context) => worksForSource(context, context.user, stixCoreObject.id, args),
    connectors: (stixCoreObject, { onlyAlive = false }, context) => connectorsForEnrichment(context, context.user, stixCoreObject.entity_type, onlyAlive),
    importFiles: (stixCoreObject, { first }, context) => filesListing(context, context.user, first, `import/${stixCoreObject.entity_type}/${stixCoreObject.id}/`),
    pendingFiles: (stixCoreObject, { first }, context) => filesListing(context, context.user, first, 'import/pending/', stixCoreObject.id),
    exportFiles: (stixCoreObject, { first }, context) => filesListing(context, context.user, first, `export/${stixCoreObject.entity_type}/${stixCoreObject.id}/`),
  },
  Mutation: {
    stixCoreObjectEdit: (_, { id }, context) => ({
      delete: () => stixCoreObjectDelete(context, context.user, id),
      relationAdd: ({ input }) => stixCoreObjectAddRelation(context, context.user, id, input),
      relationsAdd: ({ input }) => stixCoreObjectAddRelations(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixCoreObjectDeleteRelation(context, context.user, id, toId, relationshipType),
      merge: ({ stixCoreObjectsIds }) => stixCoreObjectMerge(context, context.user, id, stixCoreObjectsIds),
      askEnrichment: ({ connectorId }) => askElementEnrichmentForConnector(context, context, context.user, id, connectorId),
      importPush: ({ file, noTriggerImport = false }) => stixCoreObjectImportPush(context, context.user, id, file, noTriggerImport),
      exportAsk: (args) => stixCoreObjectExportAsk(context, context.user, R.assoc('stixCoreObjectId', id, args)),
      exportPush: ({ file }) => stixCoreObjectExportPush(context, context.user, id, file),
    }),
  },
  Subscription: {
    stixCoreObject: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, context) => {
        stixDomainObjectEditContext(context, context.user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== context.user.id && payload.instance.id === id;
          }
        )(_, { id }, context);
        return withCancel(filtering, () => {
          stixDomainObjectCleanContext(context, context.user, id);
        });
      },
    },
  },
};

export default stixCoreObjectResolvers;
