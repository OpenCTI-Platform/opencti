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
} from '../domain/stixCoreRelationship';
import { pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { killChainPhases, stixCoreRelationships } from '../domain/stixCoreObject';
import { distributionRelations, loadById, timeSeriesRelations, REL_CONNECTED_SUFFIX } from '../database/grakn';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import { convertDataToStix } from '../database/stix';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../utils/idGenerator';

const stixCoreRelationshipResolvers = {
  Query: {
    stixCoreRelationship: (_, { id }) => findById(id),
    stixCoreRelationships: (_, args) => findAll(args),
    stixCoreRelationshipsTimeSeries: (_, args) => timeSeriesRelations(args),
    stixCoreRelationshipsDistribution: async (_, args) => distributionRelations(args),
    stixCoreRelationshipsNumber: (_, args) => stixCoreRelationshipsNumber(args),
  },
  StixCoreRelationshipsFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markingDefinitions: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labels: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
    toPatternType: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.pattern_type`,
    toMainObservableType: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.main_observable_type`,
  },
  StixCoreRelationshipsOrdering: {
    toName: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.name`,
    toValidFrom: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.valid_from`,
    toValidUntil: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.valid_until`,
    toPatternType: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.pattern_type`,
    toCreatedAt: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.created_at`,
  },
  StixCoreRelationship: {
    killChainPhases: (rel) => killChainPhases(rel.id),
    from: (rel) => loadById(rel.fromId, rel.fromType),
    to: (rel) => loadById(rel.toId, rel.toType),
    toStix: (rel) => convertDataToStix(rel).then((stixData) => JSON.stringify(stixData)),
    stixCoreRelationships: (rel, args) => stixCoreRelationships(rel.id, args),
  },
  RelationEmbedded: {
    from: (rel) => loadById(rel.fromId, rel.fromType),
    to: (rel) => loadById(rel.toId, rel.toType),
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
    stixCoreRelationshipAdd: (_, { input, reversedReturn }, { user }) => addStixCoreRelationship(user, input, reversedReturn),
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
