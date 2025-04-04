import { BUS_TOPICS } from '../config/conf';
import {
  addStixCoreRelationship,
  findAll,
  findById,
  stixCoreRelationshipAddRelation,
  stixCoreRelationshipAddRelations,
  stixCoreRelationshipCleanContext,
  stixCoreRelationshipDelete,
  stixCoreRelationshipDeleteByFromAndTo,
  stixCoreRelationshipDeleteRelation,
  stixCoreRelationshipEditContext,
  stixCoreRelationshipEditField,
  stixCoreRelationshipRemoveFromDraft,
  stixCoreRelationshipsDistribution,
  stixCoreRelationshipsExportAsk,
  stixCoreRelationshipsMultiTimeSeries,
  stixCoreRelationshipsNumber
} from '../domain/stixCoreRelationship';
import { fetchEditContext } from '../database/redis';
import { subscribeToInstanceEvents } from '../graphql/subscriptionWrapper';
import { batchLoader, stixLoadByIdStringify, timeSeriesRelations } from '../database/middleware';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, INPUT_CREATED_BY, INPUT_GRANTED_REFS, INPUT_KILLCHAIN, INPUT_LABELS } from '../schema/general';
import { elBatchIds } from '../database/engine';
import { findById as findStatusById, getTypeStatuses } from '../domain/status';
import { batchCreators } from '../domain/user';
import { stixCoreRelationshipOptions } from '../schema/stixCoreRelationship';
import { addOrganizationRestriction, removeOrganizationRestriction } from '../domain/stix';
import {
  batchMarkingDefinitions,
  casesPaginated,
  containersPaginated,
  externalReferencesPaginated,
  groupingsPaginated,
  notesPaginated,
  opinionsPaginated,
  reportsPaginated,
  stixCoreObjectsExportPush
} from '../domain/stixCoreObject';
import { numberOfContainersForObject } from '../domain/container';
import { paginatedForPathWithEnrichment } from '../modules/internal/document/document-domain';
import { loadThroughDenormalized } from './stix';
import { getDraftContextIfElementInDraft } from '../database/draft-utils';

const loadByIdLoader = batchLoader(elBatchIds);
const markingDefinitionsLoader = batchLoader(batchMarkingDefinitions);
const creatorsLoader = batchLoader(batchCreators);

const stixCoreRelationshipResolvers = {
  Query: {
    stixCoreRelationship: (_, { id }, context) => findById(context, context.user, id),
    stixCoreRelationships: (_, args, context) => findAll(context, context.user, args),
    stixCoreRelationshipsTimeSeries: (_, args, context) => timeSeriesRelations(context, context.user, args),
    stixCoreRelationshipsMultiTimeSeries: (_, args, context) => stixCoreRelationshipsMultiTimeSeries(context, context.user, args),
    stixCoreRelationshipsDistribution: (_, args, context) => stixCoreRelationshipsDistribution(context, context.user, args),
    stixCoreRelationshipsNumber: (_, args, context) => stixCoreRelationshipsNumber(context, context.user, args),
    stixCoreRelationshipsExportFiles: (_, { exportContext, first }, context) => {
      const path = `export/${exportContext.entity_type}${exportContext.entity_id ? `/${exportContext.entity_id}` : ''}`;
      const opts = { first, entity_id: exportContext.entity_id, entity_type: exportContext.entity_type };
      return paginatedForPathWithEnrichment(context, context.user, path, exportContext.entity_id, opts);
    },
  },
  StixCoreRelationshipsOrdering: stixCoreRelationshipOptions.StixCoreRelationshipsOrdering,
  StixCoreRelationship: {
    // region batch loaded through rel de-normalization. Cant be ordered of filtered
    from: (rel, _, context) => {
      // If relation is in a draft, we want to force the context to also be in the same draft
      const contextToUse = getDraftContextIfElementInDraft(context, rel);
      return (rel.from ? rel.from : loadByIdLoader.load({ id: rel.fromId, type: rel.fromType }, contextToUse, context.user));
    },
    to: (rel, _, context) => {
      // If relation is in a draft, we want to force the context to also be in the same draft
      const contextToUse = getDraftContextIfElementInDraft(context, rel);
      return (rel.to ? rel.to : loadByIdLoader.load({ id: rel.toId, type: rel.toType }, contextToUse, context.user));
    },
    // region batch loaded through rel de-normalization. Cant be ordered of filtered
    createdBy: (rel, _, context) => loadThroughDenormalized(context, context.user, rel, INPUT_CREATED_BY),
    objectOrganization: (rel, _, context) => loadThroughDenormalized(context, context.user, rel, INPUT_GRANTED_REFS, { sortBy: 'name' }),
    objectLabel: (rel, _, context) => loadThroughDenormalized(context, context.user, rel, INPUT_LABELS, { sortBy: 'value' }),
    killChainPhases: (rel, _, context) => loadThroughDenormalized(context, context.user, rel, INPUT_KILLCHAIN, { sortBy: 'phase_name' }),
    creators: (rel, _, context) => creatorsLoader.load(rel.creator_id, context, context.user),
    objectMarking: (rel, _, context) => markingDefinitionsLoader.load(rel, context, context.user),
    // endregion
    // region inner listing - cant be batch loaded
    externalReferences: (rel, args, context) => externalReferencesPaginated(context, context.user, rel.id, args),
    containers: (rel, args, context) => containersPaginated(context, context.user, rel.id, args),
    reports: (rel, args, context) => reportsPaginated(context, context.user, rel.id, args),
    groupings: (rel, args, context) => groupingsPaginated(context, context.user, rel.id, args),
    cases: (rel, args, context) => casesPaginated(context, context.user, rel.id, args),
    notes: (rel, args, context) => notesPaginated(context, context.user, rel.id, args),
    opinions: (rel, args, context) => opinionsPaginated(context, context.user, rel.id, args),
    // endregion
    editContext: (rel) => fetchEditContext(rel.id),
    toStix: (rel, _, context) => stixLoadByIdStringify(context, context.user, rel.id),
    status: (entity, _, context) => (entity.x_opencti_workflow_id ? findStatusById(context, context.user, entity.x_opencti_workflow_id) : null),
    workflowEnabled: async (entity, _, context) => {
      const statusesEdges = await getTypeStatuses(context, context.user, ABSTRACT_STIX_CORE_RELATIONSHIP);
      return statusesEdges.edges.length > 0;
    },
    // Figures
    containersNumber: (rel, args, context) => numberOfContainersForObject(context, context.user, { ...args, objectId: rel.id }),
  },
  Mutation: {
    stixCoreRelationshipEdit: (_, { id }, context) => ({
      delete: () => stixCoreRelationshipDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => {
        return stixCoreRelationshipEditField(context, context.user, id, input, { commitMessage, references });
      },
      contextPatch: ({ input }) => stixCoreRelationshipEditContext(context, context.user, id, input),
      contextClean: () => stixCoreRelationshipCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixCoreRelationshipAddRelation(context, context.user, id, input),
      relationsAdd: ({ input, commitMessage, references }) => stixCoreRelationshipAddRelations(context, context.user, id, input, { commitMessage, references }),
      // eslint-disable-next-line max-len
      relationDelete: ({ toId, relationship_type: relationshipType, commitMessage, references }) => stixCoreRelationshipDeleteRelation(context, context.user, id, toId, relationshipType, { commitMessage, references }),
      restrictionOrganizationAdd: ({ organizationId }) => addOrganizationRestriction(context, context.user, id, organizationId),
      restrictionOrganizationDelete: ({ organizationId }) => removeOrganizationRestriction(context, context.user, id, organizationId),
      removeFromDraft: () => stixCoreRelationshipRemoveFromDraft(context, context.user, id),
    }),
    stixCoreRelationshipAdd: (_, { input }, context) => addStixCoreRelationship(context, context.user, input),
    stixCoreRelationshipsExportAsk: (_, { input }, context) => stixCoreRelationshipsExportAsk(context, context.user, input),
    stixCoreRelationshipsExportPush: (_, { entity_id, entity_type, file, file_markings, listFilters }, context) => {
      return stixCoreObjectsExportPush(context, context.user, entity_id, entity_type, file, file_markings, listFilters);
    },
    stixCoreRelationshipDelete: (_, { fromId, toId, relationship_type: relationshipType }, context) => {
      return stixCoreRelationshipDeleteByFromAndTo(context, context.user, fromId, toId, relationshipType);
    },
  },
  Subscription: {
    stixCoreRelationship: {
      resolve: /* v8 ignore next */ (payload) => payload.instance,
      subscribe: /* v8 ignore next */ (_, { id }, context) => {
        const preFn = () => stixCoreRelationshipEditContext(context, context.user, id);
        const cleanFn = () => stixCoreRelationshipCleanContext(context, context.user, id);
        const bus = BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP];
        return subscribeToInstanceEvents(_, context, id, [bus.EDIT_TOPIC], { type: ABSTRACT_STIX_CORE_RELATIONSHIP, preFn, cleanFn });
      },
    },
  },
};

export default stixCoreRelationshipResolvers;
