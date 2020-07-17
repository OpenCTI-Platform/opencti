import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixCoreRelationship,
  findAll,
  findById,
  stixCoreRelationshipAddRelation,
  stixCoreRelationshipCleanContext,
  stixCoreRelationshipDelete,
  stixCoreRelationshipDeleteRelation,
  stixCoreRelationshipEditContext,
  stixCoreRelationshipEditField,
  stixCoreRelationshipsNumber,
  createdBy,
  externalReferences,
  killChainPhases,
  labels,
  markingDefinitions,
  notes,
  reports,
} from '../domain/stixCoreRelationship';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { distributionRelations, loadById, timeSeriesRelations, REL_CONNECTED_SUFFIX } from '../database/grakn';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import { convertDataToStix } from '../database/stix';
import {
  RELATION_CREATED_BY,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
} from '../utils/idGenerator';
import { creator } from '../domain/log';

const stixCoreRelationshipResolvers = {
  Query: {
    stixCoreRelationship: (_, { id }) => findById(id),
    stixCoreRelationships: (_, args) => findAll(args),
    stixCoreRelationshipsTimeSeries: (_, args) => timeSeriesRelations(args),
    stixCoreRelationshipsDistribution: async (_, args) => distributionRelations(args),
    stixCoreRelationshipsNumber: (_, args) => stixCoreRelationshipsNumber(args),
  },
  StixCoreRelationshipsOrdering: {
    objectMarking: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.definition`,
    objectLabel: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.value`,
    killChainPhase: `${REL_INDEX_PREFIX}${RELATION_KILL_CHAIN_PHASE}.phase_name`,
    toName: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.name`,
    toValidFrom: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.valid_from`,
    toValidUntil: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.valid_until`,
    toPatternType: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.pattern_type`,
    toCreatedAt: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.created_at`,
  },
  StixCoreRelationshipsFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
    toPatternType: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.pattern_type`,
    toMainObservableType: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.main_observable_type`,
  },
  StixCoreRelationship: {
    from: (rel) => loadById(rel.fromId, rel.fromType),
    to: (rel) => loadById(rel.toId, rel.toType),
    toStix: (rel) => convertDataToStix(rel).then((stixData) => JSON.stringify(stixData)),
    creator: (rel) => creator(rel.id),
    createdBy: (rel) => createdBy(rel.id),
    objectMarking: (rel) => markingDefinitions(rel.id),
    objectLabel: (rel) => labels(rel.id),
    editContext: (rel) => fetchEditContext(rel.id),
    externalReferences: (rel) => externalReferences(rel.id),
    killChainPhases: (rel) => killChainPhases(rel.id),
    reports: (rel) => reports(rel.id),
    notes: (rel) => notes(rel.id),
  },
  Mutation: {
    stixCoreRelationshipEdit: (_, { id }, { user }) => ({
      delete: () => stixCoreRelationshipDelete(user, id),
      fieldPatch: ({ input }) => stixCoreRelationshipEditField(user, id, input),
      contextPatch: ({ input }) => stixCoreRelationshipEditContext(user, id, input),
      contextClean: () => stixCoreRelationshipCleanContext(user, id),
      relationAdd: ({ input }) => stixCoreRelationshipAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixCoreRelationshipDeleteRelation(user, id, relationId),
    }),
    stixCoreRelationshipAdd: (_, { input, reversedReturn }, { user }) =>
      addStixCoreRelationship(user, input, reversedReturn),
  },
  Subscription: {
    stixCoreRelationship: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
        stixCoreRelationshipEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.StixCoreRelationship.EDIT_TOPIC),
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
