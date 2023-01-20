import { withFilter } from 'graphql-subscriptions';
import {
  askElementEnrichmentForConnector,
  batchCases,
  batchCreatedBy,
  batchExternalReferences,
  batchLabels,
  batchMarkingDefinitions,
  batchNotes,
  batchObservedData,
  batchOpinions,
  batchReports,
  findAll,
  findById,
  stixCoreObjectAddRelation,
  stixCoreObjectAddRelations,
  stixCoreObjectCleanContext,
  stixCoreObjectDelete,
  stixCoreObjectDeleteRelation,
  stixCoreObjectEditContext,
  stixCoreObjectExportAsk,
  stixCoreObjectExportPush,
  stixCoreObjectImportPush,
  stixCoreObjectsDistribution,
  stixCoreObjectsDistributionByEntity,
  stixCoreObjectsExportAsk,
  stixCoreObjectsExportPush,
  stixCoreObjectsMultiDistribution,
  stixCoreObjectsMultiNumber,
  stixCoreObjectsMultiTimeSeries,
  stixCoreObjectsNumber,
  stixCoreObjectsTimeSeries,
  stixCoreObjectsTimeSeriesByAuthor,
  stixCoreRelationships,
} from '../domain/stixCoreObject';
import { fetchEditContext, pubsub } from '../database/redis';
import { batchLoader, distributionRelations, stixLoadByIdStringify } from '../database/middleware';
import { worksForSource } from '../domain/work';
import { filesListing } from '../database/file-storage';
import { BUS_TOPICS } from '../config/conf';
import { ABSTRACT_STIX_CORE_OBJECT } from '../schema/general';
import withCancel from '../graphql/subscriptionWrapper';
import { connectorsForEnrichment } from '../database/repository';
import { addOrganizationRestriction, batchObjectOrganizations, removeOrganizationRestriction } from '../domain/stix';
import { stixCoreObjectOptions } from '../schema/stixCoreObject';

const createdByLoader = batchLoader(batchCreatedBy);
const markingDefinitionsLoader = batchLoader(batchMarkingDefinitions);
const labelsLoader = batchLoader(batchLabels);
const externalReferencesLoader = batchLoader(batchExternalReferences);
const notesLoader = batchLoader(batchNotes);
const opinionsLoader = batchLoader(batchOpinions);
const reportsLoader = batchLoader(batchReports);
const casesLoader = batchLoader(batchCases);
const observedDataLoader = batchLoader(batchObservedData);
const batchOrganizationsLoader = batchLoader(batchObjectOrganizations);

const stixCoreObjectResolvers = {
  Query: {
    stixCoreObject: (_, { id }, context) => findById(context, context.user, id),
    stixCoreObjectRaw: (_, { id }, context) => stixLoadByIdStringify(context, context.user, id),
    stixCoreObjects: (_, args, context) => findAll(context, context.user, args),
    stixCoreObjectsTimeSeries: (_, args, context) => {
      if (args.authorId && args.authorId.length > 0) {
        return stixCoreObjectsTimeSeriesByAuthor(context, context.user, args);
      }
      return stixCoreObjectsTimeSeries(context, context.user, args);
    },
    stixCoreObjectsMultiTimeSeries: (_, args, context) => stixCoreObjectsMultiTimeSeries(context, context.user, args),
    stixCoreObjectsNumber: (_, args, context) => stixCoreObjectsNumber(context, context.user, args),
    stixCoreObjectsMultiNumber: (_, args, context) => stixCoreObjectsMultiNumber(context, context.user, args),
    stixCoreObjectsDistribution: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return stixCoreObjectsDistributionByEntity(context, context.user, args);
      }
      return stixCoreObjectsDistribution(context, context.user, args);
    },
    stixCoreObjectsMultiDistribution: (_, args, context) => stixCoreObjectsMultiDistribution(context, context.user, args),
    stixCoreObjectsExportFiles: (_, { type, first }, context) => filesListing(context, context.user, first, `export/${type}/`),
  },
  StixCoreObjectsFilter: stixCoreObjectOptions.StixCoreObjectsFilter,
  StixCoreObjectsOrdering: stixCoreObjectOptions.StixCoreObjectsOrdering,
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
    editContext: (stixCoreObject) => fetchEditContext(stixCoreObject.id),
    stixCoreObjectsDistribution: (stixCoreObject, args, context) => stixCoreObjectsDistributionByEntity(context, context.user, { ...args, objectId: stixCoreObject.id }),
    stixCoreRelationships: (stixCoreObject, args, context) => stixCoreRelationships(context, context.user, stixCoreObject.id, args),
    stixCoreRelationshipsDistribution: (stixCoreObject, args, context) => distributionRelations(context, context.user, { ...args, elementId: stixCoreObject.id }),
    createdBy: (stixCoreObject, _, context) => createdByLoader.load(stixCoreObject.id, context, context.user),
    objectMarking: (stixCoreObject, _, context) => markingDefinitionsLoader.load(stixCoreObject.id, context, context.user),
    objectLabel: (stixCoreObject, _, context) => labelsLoader.load(stixCoreObject.id, context, context.user),
    objectOrganization: (stixCoreObject, _, context) => batchOrganizationsLoader.load(stixCoreObject.id, context, context.user),
    externalReferences: (stixCoreObject, _, context) => externalReferencesLoader.load(stixCoreObject.id, context, context.user),
    reports: (stixCoreObject, args, context) => reportsLoader.load(stixCoreObject.id, context, context.user, args),
    cases: (stixCoreObject, args, context) => casesLoader.load(stixCoreObject.id, context, context.user, args),
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
      restrictionOrganizationAdd: ({ organizationId }) => addOrganizationRestriction(context, context.user, id, organizationId),
      restrictionOrganizationDelete: ({ organizationId }) => removeOrganizationRestriction(context, context.user, id, organizationId),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixCoreObjectDeleteRelation(context, context.user, id, toId, relationshipType),
      askEnrichment: ({ connectorId }) => askElementEnrichmentForConnector(context, context.user, id, connectorId),
      importPush: ({ file, noTriggerImport = false }) => stixCoreObjectImportPush(context, context.user, id, file, noTriggerImport),
      exportAsk: (args) => stixCoreObjectExportAsk(context, context.user, { ...args, stixCoreObjectId: id }),
      exportPush: ({ file }) => stixCoreObjectExportPush(context, context.user, id, file),
    }),
    stixCoreObjectsExportAsk: (_, args, context) => stixCoreObjectsExportAsk(context, context.user, args),
    stixCoreObjectsExportPush: (_, { type, file, listFilters }, context) => stixCoreObjectsExportPush(context, context.user, type, file, listFilters),
  },
  Subscription: {
    stixCoreObject: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, context) => {
        stixCoreObjectEditContext(context, context.user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== context.user.id && payload.instance.id === id;
          }
        )(_, { id }, context);
        return withCancel(filtering, () => {
          stixCoreObjectCleanContext(context, context.user, id);
        });
      },
    },
  },
};

export default stixCoreObjectResolvers;
