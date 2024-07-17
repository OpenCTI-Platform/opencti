import {
  analysisClear,
  askElementEnrichmentForConnector,
  askElementAnalysisForConnector,
  batchMarkingDefinitions,
  casesPaginated,
  containersPaginated,
  externalReferencesPaginated,
  findAll,
  findById,
  groupingsPaginated,
  notesPaginated,
  observedDataPaginated,
  opinionsPaginated,
  reportsPaginated,
  stixCoreAnalysis,
  stixCoreObjectAddRelation,
  stixCoreObjectAddRelations,
  stixCoreObjectAnalysisPush,
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
  stixCoreRelationships
} from '../domain/stixCoreObject';
import { fetchEditContext } from '../database/redis';
import { batchLoader, distributionRelations, stixLoadByIdStringify } from '../database/middleware';
import { worksForSource } from '../domain/work';
import { BUS_TOPICS } from '../config/conf';
import { ABSTRACT_STIX_CORE_OBJECT, INPUT_CREATED_BY, INPUT_GRANTED_REFS, INPUT_LABELS } from '../schema/general';
import { subscribeToInstanceEvents } from '../graphql/subscriptionWrapper';
import { connectorsForEnrichment } from '../database/repository';
import { addOrganizationRestriction, removeOrganizationRestriction } from '../domain/stix';
import { stixCoreObjectOptions } from '../schema/stixCoreObject';
import { numberOfContainersForObject } from '../domain/container';
import { paginatedForPathWithEnrichment } from '../modules/internal/document/document-domain';
import { getSpecVersionOrDefault } from '../domain/stixRelationship';
import { loadThroughDenormalized } from './stix';

const markingDefinitionsLoader = batchLoader(batchMarkingDefinitions);

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
    stixCoreObjectsExportFiles: (_, { exportContext, first }, context) => {
      const path = `export/${exportContext.entity_type}${exportContext.entity_id ? `/${exportContext.entity_id}` : ''}`;
      const opts = { first, entity_id: exportContext.entity_id, entity_type: exportContext.entity_type };
      return paginatedForPathWithEnrichment(context, context.user, path, exportContext.entity_id, opts);
    },
    stixCoreObjectAnalysis: (_, { id, contentSource, contentType }, context) => stixCoreAnalysis(context, context.user, id, contentSource, contentType),
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
    inDraft: (stixCoreObject, _) => stixCoreObject._index.includes('draft_workspace'),
    toStix: (stixCoreObject, _, context) => stixLoadByIdStringify(context, context.user, stixCoreObject.id),
    editContext: (stixCoreObject) => fetchEditContext(stixCoreObject.id),
    // region batch loaded through rel de-normalization. Cant be ordered of filtered
    createdBy: (stixCoreObject, _, context) => loadThroughDenormalized(context, context.user, stixCoreObject, INPUT_CREATED_BY),
    objectOrganization: (stixCoreObject, _, context) => loadThroughDenormalized(context, context.user, stixCoreObject, INPUT_GRANTED_REFS, { sortBy: 'name' }),
    objectLabel: (stixCoreObject, _, context) => loadThroughDenormalized(context, context.user, stixCoreObject, INPUT_LABELS, { sortBy: 'value' }),
    objectMarking: (stixCoreObject, _, context) => markingDefinitionsLoader.load(stixCoreObject, context, context.user),
    // endregion
    // region inner listing - cant be batch loaded
    stixCoreRelationships: (stixCoreObject, args, context) => stixCoreRelationships(context, context.user, stixCoreObject.id, args),
    externalReferences: (stixCoreObject, args, context) => externalReferencesPaginated(context, context.user, stixCoreObject.id, args),
    containers: (stixCoreObject, args, context) => containersPaginated(context, context.user, stixCoreObject.id, args),
    reports: (stixCoreObject, args, context) => reportsPaginated(context, context.user, stixCoreObject.id, args),
    groupings: (stixCoreObject, args, context) => groupingsPaginated(context, context.user, stixCoreObject.id, args),
    cases: (stixCoreObject, args, context) => casesPaginated(context, context.user, stixCoreObject.id, args),
    notes: (stixCoreObject, args, context) => notesPaginated(context, context.user, stixCoreObject.id, args),
    opinions: (stixCoreObject, args, context) => opinionsPaginated(context, context.user, stixCoreObject.id, args),
    observedData: (stixCoreObject, args, context) => observedDataPaginated(context, context.user, stixCoreObject.id, args),
    // endregion
    // Files and connectors
    jobs: (stixCoreObject, args, context) => worksForSource(context, context.user, stixCoreObject.standard_id, args),
    connectors: (stixCoreObject, { onlyAlive = false }, context) => connectorsForEnrichment(context, context.user, stixCoreObject.entity_type, onlyAlive),
    importFiles: (stixCoreObject, { first, prefixMimeType }, context) => {
      const opts = { first, prefixMimeTypes: prefixMimeType ? [prefixMimeType] : null, entity_id: stixCoreObject.id, entity_type: stixCoreObject.entity_type };
      return paginatedForPathWithEnrichment(context, context.user, `import/${stixCoreObject.entity_type}/${stixCoreObject.id}`, stixCoreObject.id, opts);
    },
    pendingFiles: (stixCoreObject, { first }, context) => {
      const opts = { first, entity_type: stixCoreObject.entity_type, entity_id: stixCoreObject.id };
      return paginatedForPathWithEnrichment(context, context.user, 'import/pending', stixCoreObject.id, opts);
    },
    exportFiles: (stixCoreObject, { first }, context) => {
      const opts = { first, entity_type: stixCoreObject.entity_type };
      return paginatedForPathWithEnrichment(context, context.user, `export/${stixCoreObject.entity_type}/${stixCoreObject.id}`, stixCoreObject.id, opts);
    },
    // Figures
    stixCoreObjectsDistribution: (stixCoreObject, args, context) => stixCoreObjectsDistributionByEntity(context, context.user, { ...args, objectId: stixCoreObject.id }),
    stixCoreRelationshipsDistribution: (stixCoreObject, args, context) => distributionRelations(context, context.user, { ...args, fromOrToId: stixCoreObject.id }),
    containersNumber: (stixCoreObject, args, context) => numberOfContainersForObject(context, context.user, { ...args, objectId: stixCoreObject.id }),
    numberOfConnectedElement: (stixCoreObject) => stixCoreObjectsConnectedNumber(stixCoreObject),
    // Retro compatibility
    spec_version: getSpecVersionOrDefault
  },
  Analysis: {
    __resolveType(obj) {
      if (obj.analysisType) {
        if (obj.analysisType === 'mapping_analysis') return 'MappingAnalysis';
      }
      /* v8 ignore next */
      return 'Unknown';
    },
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
      importPush: (args) => stixCoreObjectImportPush(context, context.user, id, args.file, args),
      askAnalysis: ({ contentSource, contentType, connectorId }) => askElementAnalysisForConnector(context, context.user, id, contentSource, contentType, connectorId),
      analysisPush: (args) => stixCoreObjectAnalysisPush(context, context.user, id, args),
      analysisClear: ({ contentSource, contentType }) => analysisClear(context, context.user, id, contentSource, contentType),
      exportAsk: ({ input }) => stixCoreObjectExportAsk(context, context.user, id, input),
      exportPush: (args) => stixCoreObjectExportPush(context, context.user, id, args),
    }),
    stixCoreObjectsExportAsk: (_, { input }, context) => stixCoreObjectsExportAsk(context, context.user, input),
    stixCoreObjectsExportPush: (_, { entity_id, entity_type, file, file_markings, listFilters }, context) => {
      return stixCoreObjectsExportPush(context, context.user, entity_id, entity_type, file, file_markings, listFilters);
    },
  },
  Subscription: {
    stixCoreObject: {
      resolve: /* v8 ignore next */ (payload) => payload.instance,
      subscribe: /* v8 ignore next */ (_, { id }, context) => {
        const preFn = () => stixCoreObjectEditContext(context, context.user, id);
        const cleanFn = () => stixCoreObjectCleanContext(context, context.user, id);
        const bus = BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT];
        return subscribeToInstanceEvents(_, context, id, [bus.EDIT_TOPIC], { preFn, cleanFn });
      },
    },
  },
};

export default stixCoreObjectResolvers;
