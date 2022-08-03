import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixCoreRelationship,
  findAll,
  findById,
  stixCoreRelationshipAddRelation,
  stixCoreRelationshipCleanContext,
  stixCoreRelationshipDelete,
  stixCoreRelationshipDeleteByFromAndTo,
  stixCoreRelationshipDeleteRelation,
  stixCoreRelationshipEditContext,
  stixCoreRelationshipEditField,
  stixCoreRelationshipsNumber,
  batchCreatedBy,
  batchKillChainPhases,
  batchExternalReferences,
  batchLabels,
  batchMarkingDefinitions,
  batchNotes,
  batchOpinions,
  batchReports,
  stixCoreRelationshipsExportAsk,
  stixCoreRelationshipsExportPush
} from '../domain/stixCoreRelationship';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { distributionRelations, timeSeriesRelations, batchLoader, stixLoadByIdStringify } from '../database/middleware';
import { creator } from '../domain/log';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, buildRefRelationKey } from '../schema/general';
import { elBatchIds } from '../database/engine';
import { findById as findStatusById, getTypeStatuses } from '../domain/status';
import { filesListing } from '../database/file-storage';

const loadByIdLoader = batchLoader(elBatchIds);
const createdByLoader = batchLoader(batchCreatedBy);
const markingDefinitionsLoader = batchLoader(batchMarkingDefinitions);
const labelsLoader = batchLoader(batchLabels);
const externalReferencesLoader = batchLoader(batchExternalReferences);
const killChainPhasesLoader = batchLoader(batchKillChainPhases);
const notesLoader = batchLoader(batchNotes);
const opinionsLoader = batchLoader(batchOpinions);
const reportsLoader = batchLoader(batchReports);

const stixCoreRelationshipResolvers = {
  Query: {
    stixCoreRelationship: (_, { id }, { user }) => findById(user, id),
    stixCoreRelationships: (_, args, { user }) => findAll(user, args),
    stixCoreRelationshipsTimeSeries: (_, args, { user }) => timeSeriesRelations(user, args),
    stixCoreRelationshipsDistribution: (_, args, { user }) => distributionRelations(user, args),
    stixCoreRelationshipsNumber: (_, args, { user }) => stixCoreRelationshipsNumber(user, args),
    stixCoreRelationshipsExportFiles: (_, { type, first }, { user }) => filesListing(user, first, `export/${type}/`),
  },
  StixCoreRelationshipsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
  },
  StixCoreRelationship: {
    from: (rel, _, { user }) => loadByIdLoader.load(rel.fromId, user),
    to: (rel, _, { user }) => loadByIdLoader.load(rel.toId, user),
    toStix: (rel, _, { user }) => stixLoadByIdStringify(user, rel.id),
    creator: (rel, _, { user }) => creator(user, rel.id, ABSTRACT_STIX_CORE_RELATIONSHIP),
    createdBy: (rel, _, { user }) => createdByLoader.load(rel.id, user),
    objectMarking: (rel, _, { user }) => markingDefinitionsLoader.load(rel.id, user),
    objectLabel: (rel, _, { user }) => labelsLoader.load(rel.id, user),
    externalReferences: (rel, _, { user }) => externalReferencesLoader.load(rel.id, user),
    killChainPhases: (rel, _, { user }) => killChainPhasesLoader.load(rel.id, user),
    reports: (rel, _, { user }) => reportsLoader.load(rel.id, user),
    notes: (rel, _, { user }) => notesLoader.load(rel.id, user),
    opinions: (rel, _, { user }) => opinionsLoader.load(rel.id, user),
    editContext: (rel) => fetchEditContext(rel.id),
    status: (entity, _, { user }) => (entity.x_opencti_workflow_id ? findStatusById(user, entity.x_opencti_workflow_id) : null),
    workflowEnabled: async (entity, _, { user }) => {
      const statusesEdges = await getTypeStatuses(user, ABSTRACT_STIX_CORE_RELATIONSHIP);
      return statusesEdges.edges.length > 0;
    },
  },
  Mutation: {
    stixCoreRelationshipEdit: (_, { id }, { user }) => ({
      delete: () => stixCoreRelationshipDelete(user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixCoreRelationshipEditField(user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixCoreRelationshipEditContext(user, id, input),
      contextClean: () => stixCoreRelationshipCleanContext(user, id),
      relationAdd: ({ input }) => stixCoreRelationshipAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixCoreRelationshipDeleteRelation(user, id, toId, relationshipType),
    }),
    stixCoreRelationshipAdd: (_, { input }, { user }) => addStixCoreRelationship(user, input),
    stixCoreRelationshipsExportAsk: (_, args, { user }) => stixCoreRelationshipsExportAsk(user, args),
    stixCoreRelationshipsExportPush: (_, { type, file, listFilters }, { user }) => stixCoreRelationshipsExportPush(user, type, file, listFilters),
    stixCoreRelationshipDelete: (_, { fromId, toId, relationship_type: relationshipType }, { user }) => stixCoreRelationshipDeleteByFromAndTo(user, fromId, toId, relationshipType),
  },
  Subscription: {
    stixCoreRelationship: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
        stixCoreRelationshipEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          stixCoreRelationshipCleanContext(user, id);
        });
      },
    },
  },
};

export default stixCoreRelationshipResolvers;
