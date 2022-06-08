import * as R from 'ramda';
import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixSightingRelationship,
  findAll,
  findById,
  stixSightingRelationshipAddRelation,
  stixSightingRelationshipCleanContext,
  stixSightingRelationshipDelete,
  stixSightingRelationshipDeleteRelation,
  stixSightingRelationshipEditContext,
  stixSightingRelationshipEditField,
  stixSightingRelationshipsNumber,
  batchCreatedBy,
  batchExternalReferences,
  batchLabels,
  batchMarkingDefinitions,
  batchNotes,
  batchOpinions,
  batchReports,
} from '../domain/stixSightingRelationship';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { distributionRelations, timeSeriesRelations, batchLoader, stixLoadByIdStringify } from '../database/middleware';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import { creator } from '../domain/log';
import { buildRefRelationKey } from '../schema/general';
import { elBatchIds } from '../database/engine';
import { findById as findStatusById, getTypeStatuses } from '../domain/status';

const createdByLoader = batchLoader(batchCreatedBy);
const markingDefinitionsLoader = batchLoader(batchMarkingDefinitions);
const labelsLoader = batchLoader(batchLabels);
const externalReferencesLoader = batchLoader(batchExternalReferences);
const notesLoader = batchLoader(batchNotes);
const opinionsLoader = batchLoader(batchOpinions);
const reportsLoader = batchLoader(batchReports);

const loadByIdLoader = batchLoader(elBatchIds);

const stixSightingRelationshipResolvers = {
  Query: {
    stixSightingRelationship: (_, { id }, { user }) => findById(user, id),
    stixSightingRelationships: (_, args, { user }) => findAll(user, args),
    stixSightingRelationshipsTimeSeries: (_, args, { user }) => timeSeriesRelations(user, args),
    stixSightingRelationshipsDistribution: (_, args, { user }) => distributionRelations(
      user,
      R.pipe(R.assoc('relationship_type', 'stix-sighting-relationship'), R.assoc('isTo', true))(args)
    ),
    stixSightingRelationshipsNumber: (_, args, { user }) => stixSightingRelationshipsNumber(user, args),
  },
  StixSightingRelationshipsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
  },
  StixSightingRelationship: {
    relationship_type: () => 'stix-sighting-relationship',
    from: (rel, _, { user }) => loadByIdLoader.load(rel.fromId, user),
    to: (rel, _, { user }) => loadByIdLoader.load(rel.toId, user),
    toStix: (rel, _, { user }) => stixLoadByIdStringify(user, rel.id),
    creator: (rel, _, { user }) => creator(user, rel.id, STIX_SIGHTING_RELATIONSHIP),
    createdBy: (rel, _, { user }) => createdByLoader.load(rel.id, user),
    objectMarking: (rel, _, { user }) => markingDefinitionsLoader.load(rel.id, user),
    objectLabel: (rel, _, { user }) => labelsLoader.load(rel.id, user),
    externalReferences: (rel, _, { user }) => externalReferencesLoader.load(rel.id, user),
    reports: (rel, _, { user }) => reportsLoader.load(rel.id, user),
    notes: (rel, _, { user }) => notesLoader.load(rel.id, user),
    opinions: (rel, _, { user }) => opinionsLoader.load(rel.id, user),
    editContext: (rel) => fetchEditContext(rel.id),
    status: (entity, _, { user }) => (entity.x_opencti_workflow_id ? findStatusById(user, entity.x_opencti_workflow_id) : null),
    workflowEnabled: async (entity, _, { user }) => {
      const statusesEdges = await getTypeStatuses(user, entity.entity_type);
      return statusesEdges.edges.length > 0;
    },
  },
  Mutation: {
    stixSightingRelationshipEdit: (_, { id }, { user }) => ({
      delete: () => stixSightingRelationshipDelete(user, id),
      fieldPatch: ({ input }) => stixSightingRelationshipEditField(user, id, input),
      contextPatch: ({ input }) => stixSightingRelationshipEditContext(user, id, input),
      contextClean: () => stixSightingRelationshipCleanContext(user, id),
      relationAdd: ({ input }) => stixSightingRelationshipAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixSightingRelationshipDeleteRelation(user, id, toId, relationshipType),
    }),
    stixSightingRelationshipAdd: (_, { input }, { user }) => addStixSightingRelationship(user, input),
  },
  Subscription: {
    stixSightingRelationship: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
        stixSightingRelationshipEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS[STIX_SIGHTING_RELATIONSHIP].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          stixSightingRelationshipCleanContext(user, id);
        });
      },
    },
  },
};

export default stixSightingRelationshipResolvers;
