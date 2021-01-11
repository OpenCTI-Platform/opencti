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
} from '../domain/stixCoreRelationship';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import {
  distributionRelations,
  timeSeriesRelations,
  REL_CONNECTED_SUFFIX,
  initBatchLoader,
} from '../database/middleware';
import { convertDataToStix } from '../database/stix';
import { creator } from '../domain/log';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, REL_INDEX_PREFIX } from '../schema/general';
import { elBatchIds } from '../database/elasticSearch';

const loadByIdLoader = initBatchLoader(elBatchIds);
const createdByLoader = initBatchLoader(batchCreatedBy);
const markingDefinitionsLoader = initBatchLoader(batchMarkingDefinitions);
const labelsLoader = initBatchLoader(batchLabels);
const externalReferencesLoader = initBatchLoader(batchExternalReferences);
const killChainPhasesLoader = initBatchLoader(batchKillChainPhases);
const notesLoader = initBatchLoader(batchNotes);
const opinionsLoader = initBatchLoader(batchOpinions);
const reportsLoader = initBatchLoader(batchReports);

const stixCoreRelationshipResolvers = {
  Query: {
    stixCoreRelationship: (_, { id }) => findById(id),
    stixCoreRelationships: (_, args) => findAll(args),
    stixCoreRelationshipsOfElement: (_, args) => findAll(args),
    stixCoreRelationshipsTimeSeries: (_, args) => timeSeriesRelations(args),
    stixCoreRelationshipsDistribution: (_, args) => distributionRelations(args),
    stixCoreRelationshipsNumber: (_, args) => stixCoreRelationshipsNumber(args),
  },
  StixCoreRelationshipsOrdering: {
    toName: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.name`,
  },
  StixCoreRelationshipsFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
    toName: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.name`,
    toCreatedAt: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.created_at`,
    toPatternType: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.pattern_type`,
    toMainObservableType: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.x_opencti_main_observable_type`,
  },
  StixCoreRelationship: {
    from: (rel) => loadByIdLoader.load(rel.fromId),
    to: (rel) => loadByIdLoader.load(rel.toId),
    toStix: (rel) => JSON.stringify(convertDataToStix(rel)),
    creator: (rel) => creator(rel.id),
    createdBy: (rel) => createdByLoader.load(rel.id),
    objectMarking: (rel) => markingDefinitionsLoader.load(rel.id),
    objectLabel: (rel) => labelsLoader.load(rel.id),
    externalReferences: (rel) => externalReferencesLoader.load(rel.id),
    killChainPhases: (rel) => killChainPhasesLoader.load(rel.id),
    reports: (rel) => reportsLoader.load(rel.id),
    notes: (rel) => notesLoader.load(rel.id),
    opinions: (rel) => opinionsLoader.load(rel.id),
    editContext: (rel) => fetchEditContext(rel.id),
  },
  Mutation: {
    stixCoreRelationshipEdit: (_, { id }, { user }) => ({
      delete: () => stixCoreRelationshipDelete(user, id),
      fieldPatch: ({ input }) => stixCoreRelationshipEditField(user, id, input),
      contextPatch: ({ input }) => stixCoreRelationshipEditContext(user, id, input),
      contextClean: () => stixCoreRelationshipCleanContext(user, id),
      relationAdd: ({ input }) => stixCoreRelationshipAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        stixCoreRelationshipDeleteRelation(user, id, toId, relationshipType),
    }),
    stixCoreRelationshipAdd: (_, { input }, { user }) => addStixCoreRelationship(user, input),
    stixCoreRelationshipDelete: (_, { fromId, toId, relationship_type: relationshipType }, { user }) =>
      stixCoreRelationshipDeleteByFromAndTo(user, fromId, toId, relationshipType),
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
