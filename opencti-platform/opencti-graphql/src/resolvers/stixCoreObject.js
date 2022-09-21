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
    stixCoreObject: (_, { id }, { user }) => findById(user, id),
    stixCoreObjectRaw: (_, { id }, { user }) => stixLoadByIdStringify(user, id),
    stixCoreObjects: (_, args, { user }) => findAll(user, args),
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
    toStix: (stixCoreObject, _, { user }) => stixLoadByIdStringify(user, stixCoreObject.id),
    creator: (stixCoreObject, _, { user }) => creator(user, stixCoreObject.id, ABSTRACT_STIX_CORE_OBJECT),
    editContext: (stixCoreObject) => fetchEditContext(stixCoreObject.id),
    stixCoreRelationships: (stixCoreObject, args, { user }) => stixCoreRelationships(user, stixCoreObject.id, args),
    createdBy: (stixCoreObject, _, { user }) => createdByLoader.load(stixCoreObject.id, user),
    objectMarking: (stixCoreObject, _, { user }) => markingDefinitionsLoader.load(stixCoreObject.id, user),
    objectLabel: (stixCoreObject, _, { user }) => labelsLoader.load(stixCoreObject.id, user),
    externalReferences: (stixCoreObject, _, { user }) => externalReferencesLoader.load(stixCoreObject.id, user),
    reports: (stixCoreObject, args, { user }) => reportsLoader.load(stixCoreObject.id, user, args),
    notes: (stixCoreObject, _, { user }) => notesLoader.load(stixCoreObject.id, user),
    opinions: (stixCoreObject, _, { user }) => opinionsLoader.load(stixCoreObject.id, user),
    observedData: (stixCoreObject, _, { user }) => observedDataLoader.load(stixCoreObject.id, user),
    jobs: (stixCoreObject, args, { user }) => worksForSource(user, stixCoreObject.id, args),
    connectors: (stixCoreObject, { onlyAlive = false }, { user }) => connectorsForEnrichment(user, stixCoreObject.entity_type, onlyAlive),
    importFiles: (stixCoreObject, { first }, { user }) => filesListing(user, first, `import/${stixCoreObject.entity_type}/${stixCoreObject.id}/`),
    pendingFiles: (stixCoreObject, { first }, { user }) => filesListing(user, first, 'import/pending/', stixCoreObject.id),
    exportFiles: (stixCoreObject, { first }, { user }) => filesListing(user, first, `export/${stixCoreObject.entity_type}/${stixCoreObject.id}/`),
  },
  Mutation: {
    stixCoreObjectEdit: (_, { id }, { user }) => ({
      delete: () => stixCoreObjectDelete(user, id),
      relationAdd: ({ input }) => stixCoreObjectAddRelation(user, id, input),
      relationsAdd: ({ input }) => stixCoreObjectAddRelations(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixCoreObjectDeleteRelation(user, id, toId, relationshipType),
      merge: ({ stixCoreObjectsIds }) => stixCoreObjectMerge(user, id, stixCoreObjectsIds),
      askEnrichment: ({ connectorId }) => askElementEnrichmentForConnector(user, id, connectorId),
      importPush: ({ file, noTriggerImport = false }) => stixCoreObjectImportPush(user, id, file, noTriggerImport),
      exportAsk: (args) => stixCoreObjectExportAsk(user, R.assoc('stixCoreObjectId', id, args)),
      exportPush: ({ file }) => stixCoreObjectExportPush(user, id, file),
    }),
  },
  Subscription: {
    stixCoreObject: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
        stixDomainObjectEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          stixDomainObjectCleanContext(user, id);
        });
      },
    },
  },
};

export default stixCoreObjectResolvers;
