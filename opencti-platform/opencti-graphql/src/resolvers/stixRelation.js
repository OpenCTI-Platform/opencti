import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixRelation,
  findAll,
  findById,
  stixRelationAddRelation,
  stixRelationCleanContext,
  stixRelationDelete,
  stixRelationDeleteRelation,
  stixRelationEditContext,
  stixRelationEditField,
  stixRelationsNumber,
} from '../domain/stixRelation';
import { pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { killChainPhases } from '../domain/stixEntity';
import { distributionRelations, loadByGraknId, timeSeriesRelations, REL_CONNECTED_SUFFIX } from '../database/grakn';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import { convertDataToStix } from '../database/stix';

const stixRelationResolvers = {
  Query: {
    stixRelation: (_, { id }) => findById(id),
    stixRelations: (_, args) => findAll(args),
    stixRelationsTimeSeries: (_, args) => timeSeriesRelations(args),
    stixRelationsDistribution: async (_, args) => distributionRelations(args),
    stixRelationsNumber: (_, args) => stixRelationsNumber(args),
  },
  StixRelationsFilter: {
    createdBy: `${REL_INDEX_PREFIX}created_by_ref.internal_id_key`,
    markingDefinitions: `${REL_INDEX_PREFIX}object_marking_refs.internal_id_key`,
    tags: `${REL_INDEX_PREFIX}tagged.internal_id_key`,
    toPatternType: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.pattern_type`,
    toMainObservableType: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.main_observable_type`,
  },
  StixRelationsOrdering: {
    toName: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.name`,
    toValidFrom: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.valid_from`,
    toValidUntil: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.valid_until`,
    toPatternType: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.pattern_type`,
    toCreatedAt: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.created_at`,
  },
  StixRelation: {
    killChainPhases: (rel) => killChainPhases(rel.id),
    from: (rel) => loadByGraknId(rel.fromId),
    to: (rel) => loadByGraknId(rel.toId),
    toStix: (rel) => convertDataToStix(rel).then((stixData) => JSON.stringify(stixData)),
  },
  RelationEmbedded: {
    from: (rel) => loadByGraknId(rel.fromId),
    to: (rel) => loadByGraknId(rel.toId),
  },
  Mutation: {
    stixRelationEdit: (_, { id }, { user }) => ({
      delete: () => stixRelationDelete(user, id),
      fieldPatch: ({ input }) => stixRelationEditField(user, id, input),
      contextPatch: ({ input }) => stixRelationEditContext(user, id, input),
      contextClean: () => stixRelationCleanContext(user, id),
      relationAdd: ({ input }) => stixRelationAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixRelationDeleteRelation(user, id, relationId),
    }),
    stixRelationAdd: (_, { input, reversedReturn }, { user }) => addStixRelation(user, input, reversedReturn),
  },
  Subscription: {
    stixRelation: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
        stixRelationEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.StixRelation.EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          stixRelationCleanContext(user, id);
        });
      },
    },
  },
};

export default stixRelationResolvers;
