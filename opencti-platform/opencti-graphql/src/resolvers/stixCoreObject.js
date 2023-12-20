import { withFilter } from 'graphql-subscriptions';
import {
  askElementEnrichmentForConnector,
  batchCases,
  batchContainers,
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
  findFiltersRepresentatives,
  stixCoreObjectAddRelation,
  stixCoreObjectAddRelations,
  stixCoreObjectCleanContext,
  stixCoreObjectDelete,
  stixCoreObjectDeleteRelation,
  stixCoreObjectEditContext,
  stixCoreObjectExportAsk,
  stixCoreObjectExportPush,
  stixCoreObjectImportPush,
  stixCoreObjectsConnectedNumber,
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
import { fetchEditContext, pubSubAsyncIterator } from '../database/redis';
import { batchLoader, distributionRelations, stixLoadByIdStringify } from '../database/middleware';
import { worksForSource } from '../domain/work';
import { BUS_TOPICS } from '../config/conf';
import { ABSTRACT_STIX_CORE_OBJECT } from '../schema/general';
import withCancel from '../graphql/subscriptionWrapper';
import { connectorsForEnrichment } from '../database/repository';
import { addOrganizationRestriction, batchObjectOrganizations, removeOrganizationRestriction } from '../domain/stix';
import { stixCoreObjectOptions } from '../schema/stixCoreObject';
import { numberOfContainersForObject } from '../domain/container';
import { paginatedForPathsWithEnrichment } from '../modules/internal/document/document-domain';
import { getSpecVersionOrDefault } from '../domain/stixRelationship';

const createdByLoader = batchLoader(batchCreatedBy);
const markingDefinitionsLoader = batchLoader(batchMarkingDefinitions);
const labelsLoader = batchLoader(batchLabels);
const externalReferencesLoader = batchLoader(batchExternalReferences);
const containersLoader = batchLoader(batchContainers);
const reportsLoader = batchLoader(batchReports);
const notesLoader = batchLoader(batchNotes);
const opinionsLoader = batchLoader(batchOpinions);
const casesLoader = batchLoader(batchCases);
const observedDataLoader = batchLoader(batchObservedData);
const batchOrganizationsLoader = batchLoader(batchObjectOrganizations);

const stixCoreObjectResolvers = {
  Query: {
    stixCoreObject: (_, { id }, context) => findById(context, context.user, id),
    stixCoreObjectRaw: (_, { id }, context) => stixLoadByIdStringify(context, context.user, id),
    globalSearch: (_, args, context) => findAll(context, context.user, { ...args, globalSearch: true }),
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
    stixCoreObjectsExportFiles: (_, { type, first }, context) => {
      return paginatedForPathsWithEnrichment(context, context.user, [`export/${type}`], { first });
    },
    filtersRepresentatives: (_, { filters }, context) => findFiltersRepresentatives(context, context.user, filters),
  },
  StixCoreObjectsOrdering: stixCoreObjectOptions.StixCoreObjectsOrdering,
  StixCoreObject: {
    // eslint-disable-next-line
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-|_)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      /* v8 ignore next */
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
    containersNumber: (stixCoreObject, args, context) => numberOfContainersForObject(context, context.user, { ...args, objectId: stixCoreObject.id }),
    containers: (stixCoreObject, args, context) => containersLoader.load(stixCoreObject.id, context, context.user, args),
    reports: (stixCoreObject, args, context) => reportsLoader.load(stixCoreObject.id, context, context.user, args),
    cases: (stixCoreObject, args, context) => casesLoader.load(stixCoreObject.id, context, context.user, args),
    notes: (stixCoreObject, _, context) => notesLoader.load(stixCoreObject.id, context, context.user),
    opinions: (stixCoreObject, _, context) => opinionsLoader.load(stixCoreObject.id, context, context.user),
    observedData: (stixCoreObject, _, context) => observedDataLoader.load(stixCoreObject.id, context, context.user),
    jobs: (stixCoreObject, args, context) => worksForSource(context, context.user, stixCoreObject.standard_id, args),
    connectors: (stixCoreObject, { onlyAlive = false }, context) => connectorsForEnrichment(context, context.user, stixCoreObject.entity_type, onlyAlive),
    importFiles: (stixCoreObject, { first, prefixMimeType }, context) => {
      const opts = { first, prefixMimeTypes: prefixMimeType ? [prefixMimeType] : null, entity_id: stixCoreObject.id };
      return paginatedForPathsWithEnrichment(context, context.user, [`import/${stixCoreObject.entity_type}/${stixCoreObject.id}`], opts);
    },
    pendingFiles: (stixCoreObject, { first }, context) => {
      return paginatedForPathsWithEnrichment(context, context.user, ['import/pending'], { first, entity_id: stixCoreObject.id });
    },
    exportFiles: (stixCoreObject, { first }, context) => {
      return paginatedForPathsWithEnrichment(context, context.user, [`export/${stixCoreObject.entity_type}/${stixCoreObject.id}`], { first, entity_id: stixCoreObject.id });
    },
    numberOfConnectedElement: (stixCoreObject) => stixCoreObjectsConnectedNumber(stixCoreObject),
    spec_version: getSpecVersionOrDefault
  },
  Mutation: {
    stixCoreObjectEdit: (_, { id }, context) => ({
      delete: () => stixCoreObjectDelete(context, context.user, id),
      relationAdd: ({ input }) => stixCoreObjectAddRelation(context, context.user, id, input),
      relationsAdd: ({ input, commitMessage, references }) => stixCoreObjectAddRelations(context, context.user, id, input, { commitMessage, references }),
      restrictionOrganizationAdd: ({ organizationId }) => addOrganizationRestriction(context, context.user, id, organizationId),
      restrictionOrganizationDelete: ({ organizationId }) => removeOrganizationRestriction(context, context.user, id, organizationId),
      // eslint-disable-next-line max-len
      relationDelete: ({ toId, relationship_type: relationshipType, commitMessage, references }) => stixCoreObjectDeleteRelation(context, context.user, id, toId, relationshipType, { commitMessage, references }),
      askEnrichment: ({ connectorId }) => askElementEnrichmentForConnector(context, context.user, id, connectorId),
      importPush: ({ file, noTriggerImport = false }) => stixCoreObjectImportPush(context, context.user, id, file, noTriggerImport),
      exportAsk: (args) => stixCoreObjectExportAsk(context, context.user, id, args),
      exportPush: ({ file }) => stixCoreObjectExportPush(context, context.user, id, file),
    }),
    stixCoreObjectsExportAsk: (_, args, context) => stixCoreObjectsExportAsk(context, context.user, args),
    stixCoreObjectsExportPush: (_, { type, file, listFilters }, context) => stixCoreObjectsExportPush(context, context.user, type, file, listFilters),
  },
  Subscription: {
    stixCoreObject: {
      resolve: /* v8 ignore next */ (payload) => payload.instance,
      subscribe: /* v8 ignore next */ (_, { id }, context) => {
        stixCoreObjectEditContext(context, context.user, id);
        const filtering = withFilter(
          () => pubSubAsyncIterator(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC),
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
