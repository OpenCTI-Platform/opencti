import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixCoreRelationship,
  batchCreatedBy,
  batchExternalReferences,
  batchKillChainPhases,
  batchLabels,
  batchMarkingDefinitions,
  batchNotes,
  batchOpinions,
  batchReports,
  batchCases,
  findAll,
  findById,
  stixCoreRelationshipAddRelation,
  stixCoreRelationshipCleanContext,
  stixCoreRelationshipDelete,
  stixCoreRelationshipDeleteByFromAndTo,
  stixCoreRelationshipDeleteRelation,
  stixCoreRelationshipEditContext,
  stixCoreRelationshipEditField,
  stixCoreRelationshipsExportAsk,
  stixCoreRelationshipsExportPush,
  stixCoreRelationshipsNumber,
  stixCoreRelationshipsMultiTimeSeries,
  stixCoreRelationshipsDistribution,
} from '../domain/stixCoreRelationship';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { batchLoader, stixLoadByIdStringify, timeSeriesRelations } from '../database/middleware';
import { ABSTRACT_STIX_CORE_RELATIONSHIP } from '../schema/general';
import { elBatchIds } from '../database/engine';
import { findById as findStatusById, getTypeStatuses } from '../domain/status';
import { filesListing } from '../database/file-storage';
import { batchUsers } from '../domain/user';
import { stixCoreRelationshipOptions } from '../schema/stixCoreRelationship';
import { addOrganizationRestriction, batchObjectOrganizations, removeOrganizationRestriction } from '../domain/stix';

const loadByIdLoader = batchLoader(elBatchIds);
const createdByLoader = batchLoader(batchCreatedBy);
const markingDefinitionsLoader = batchLoader(batchMarkingDefinitions);
const labelsLoader = batchLoader(batchLabels);
const externalReferencesLoader = batchLoader(batchExternalReferences);
const killChainPhasesLoader = batchLoader(batchKillChainPhases);
const notesLoader = batchLoader(batchNotes);
const opinionsLoader = batchLoader(batchOpinions);
const reportsLoader = batchLoader(batchReports);
const casesLoader = batchLoader(batchCases);
const batchOrganizationsLoader = batchLoader(batchObjectOrganizations);
const creatorsLoader = batchLoader(batchUsers);

const stixCoreRelationshipResolvers = {
  Query: {
    stixCoreRelationship: (_, { id }, context) => findById(context, context.user, id),
    stixCoreRelationships: (_, args, context) => findAll(context, context.user, args),
    stixCoreRelationshipsTimeSeries: (_, args, context) => timeSeriesRelations(context, context.user, args),
    stixCoreRelationshipsMultiTimeSeries: (_, args, context) => stixCoreRelationshipsMultiTimeSeries(context, context.user, args),
    stixCoreRelationshipsDistribution: (_, args, context) => stixCoreRelationshipsDistribution(context, context.user, args),
    stixCoreRelationshipsNumber: (_, args, context) => stixCoreRelationshipsNumber(context, context.user, args),
    stixCoreRelationshipsExportFiles: (_, { type, first }, context) => {
      return filesListing(context, context.user, first, `export/${type}/`);
    },
  },
  StixCoreRelationshipsFilter: stixCoreRelationshipOptions.StixCoreRelationshipsFilter,
  StixCoreRelationshipsOrdering: stixCoreRelationshipOptions.StixCoreRelationshipsOrdering,
  StixCoreRelationship: {
    from: (rel, _, context) => loadByIdLoader.load(rel.fromId, context, context.user),
    to: (rel, _, context) => loadByIdLoader.load(rel.toId, context, context.user),
    toStix: (rel, _, context) => stixLoadByIdStringify(context, context.user, rel.id),
    creator: (rel, _, context) => creatorsLoader.load(rel.creator_id, context, context.user),
    createdBy: (rel, _, context) => createdByLoader.load(rel.id, context, context.user),
    objectMarking: (rel, _, context) => markingDefinitionsLoader.load(rel.id, context, context.user),
    objectLabel: (rel, _, context) => labelsLoader.load(rel.id, context, context.user),
    objectOrganization: (rel, _, context) => batchOrganizationsLoader.load(rel.id, context, context.user),
    externalReferences: (rel, _, context) => externalReferencesLoader.load(rel.id, context, context.user),
    killChainPhases: (rel, _, context) => killChainPhasesLoader.load(rel.id, context, context.user),
    reports: (rel, _, context) => reportsLoader.load(rel.id, context, context.user),
    cases: (rel, _, context) => casesLoader.load(rel.id, context, context.user),
    notes: (rel, _, context) => notesLoader.load(rel.id, context, context.user),
    opinions: (rel, _, context) => opinionsLoader.load(rel.id, context, context.user),
    editContext: (rel) => fetchEditContext(rel.id),
    status: (entity, _, context) => (entity.x_opencti_workflow_id ? findStatusById(context, context.user, entity.x_opencti_workflow_id) : null),
    workflowEnabled: async (entity, _, context) => {
      const statusesEdges = await getTypeStatuses(context, context.user, ABSTRACT_STIX_CORE_RELATIONSHIP);
      return statusesEdges.edges.length > 0;
    },
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
      relationDelete: ({ toId, relationship_type: relationshipType }) => {
        return stixCoreRelationshipDeleteRelation(context, context.user, id, toId, relationshipType);
      },
      restrictionOrganizationAdd: ({ organizationId }) => addOrganizationRestriction(context, context.user, id, organizationId),
      restrictionOrganizationDelete: ({ organizationId }) => removeOrganizationRestriction(context, context.user, id, organizationId),
    }),
    stixCoreRelationshipAdd: (_, { input }, context) => addStixCoreRelationship(context, context.user, input),
    stixCoreRelationshipsExportAsk: (_, args, context) => stixCoreRelationshipsExportAsk(context, context.user, args),
    stixCoreRelationshipsExportPush: (_, { type, file, listFilters }, context) => {
      return stixCoreRelationshipsExportPush(context, context.user, type, file, listFilters);
    },
    stixCoreRelationshipDelete: (_, { fromId, toId, relationship_type: relationshipType }, context) => {
      return stixCoreRelationshipDeleteByFromAndTo(context, context.user, fromId, toId, relationshipType);
    },
  },
  Subscription: {
    stixCoreRelationship: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, context) => {
        stixCoreRelationshipEditContext(context, context.user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnected, an empty payload is dispatched.
            return payload.user.id !== context.user.id && payload.instance.id === id;
          }
        )(_, { id }, context);
        return withCancel(filtering, () => {
          stixCoreRelationshipCleanContext(context, context.user, id);
        });
      },
    },
  },
};

export default stixCoreRelationshipResolvers;
