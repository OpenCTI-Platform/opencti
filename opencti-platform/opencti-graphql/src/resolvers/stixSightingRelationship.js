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
import {
  distributionRelations,
  timeSeriesRelations,
  REL_CONNECTED_SUFFIX,
  initBatchLoader,
} from '../database/middleware';
import { convertDataToStix } from '../database/stix';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import { creator } from '../domain/log';
import { REL_INDEX_PREFIX } from '../schema/general';
import { elBatchIds } from '../database/elasticSearch';

const createdByLoader = initBatchLoader(batchCreatedBy);
const markingDefinitionsLoader = initBatchLoader(batchMarkingDefinitions);
const labelsLoader = initBatchLoader(batchLabels);
const externalReferencesLoader = initBatchLoader(batchExternalReferences);
const notesLoader = initBatchLoader(batchNotes);
const opinionsLoader = initBatchLoader(batchOpinions);
const reportsLoader = initBatchLoader(batchReports);

const loadByIdLoader = initBatchLoader(elBatchIds);

const stixSightingRelationshipResolvers = {
  Query: {
    stixSightingRelationship: (_, { id }) => findById(id),
    stixSightingRelationships: (_, args) => findAll(args),
    stixSightingRelationshipsTimeSeries: (_, args) => timeSeriesRelations(args),
    stixSightingRelationshipsDistribution: async (_, args) => distributionRelations(args),
    stixSightingRelationshipsNumber: (_, args) => stixSightingRelationshipsNumber(args),
  },
  StixSightingRelationshipsOrdering: {
    toName: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.name`,
  },
  StixSightingRelationshipsFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
    toPatternType: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.pattern_type`,
    toMainObservableType: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.main_observable_type`,
  },
  StixSightingRelationship: {
    from: (rel) => loadByIdLoader.load(rel.fromId),
    to: (rel) => loadByIdLoader.load(rel.toId),
    toStix: (rel) => JSON.stringify(convertDataToStix(rel)),
    creator: (rel) => creator(rel.id),
    createdBy: (rel) => createdByLoader.load(rel.id),
    objectMarking: (rel) => markingDefinitionsLoader.load(rel.id),
    objectLabel: (rel) => labelsLoader.load(rel.id),
    externalReferences: (rel) => externalReferencesLoader.load(rel.id),
    reports: (rel) => reportsLoader.load(rel.id),
    notes: (rel) => notesLoader.load(rel.id),
    opinions: (rel) => opinionsLoader.load(rel.id),
    editContext: (rel) => fetchEditContext(rel.id),
  },
  Mutation: {
    stixSightingRelationshipEdit: (_, { id }, { user }) => ({
      delete: () => stixSightingRelationshipDelete(user, id),
      fieldPatch: ({ input }) => stixSightingRelationshipEditField(user, id, input),
      contextPatch: ({ input }) => stixSightingRelationshipEditContext(user, id, input),
      contextClean: () => stixSightingRelationshipCleanContext(user, id),
      relationAdd: ({ input }) => stixSightingRelationshipAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        stixSightingRelationshipDeleteRelation(user, id, toId, relationshipType),
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
