import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addstixSighting,
  findAll,
  findById,
  stixSightingAddRelation,
  stixSightingCleanContext,
  stixSightingDelete,
  stixSightingDeleteRelation,
  stixSightingEditContext,
  stixSightingEditField,
  stixSightingsNumber,
} from '../domain/stixSightingRelationship';
import { pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { distributionRelations, loadById, timeSeriesRelations, REL_CONNECTED_SUFFIX } from '../database/grakn';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import { convertDataToStix } from '../database/stix';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../utils/idGenerator';

const stixSightingResolvers = {
  Query: {
    stixSighting: (_, { id }) => findById(id),
    stixSightings: (_, args) => findAll(args),
    stixSightingsTimeSeries: (_, args) => timeSeriesRelations(args),
    stixSightingsDistribution: async (_, args) => distributionRelations(args),
    stixSightingsNumber: (_, args) => stixSightingsNumber(args),
  },
  StixSightingsFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markingDefinitions: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labels: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
    toPatternType: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.pattern_type`,
    toMainObservableType: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.main_observable_type`,
  },
  StixSightingsOrdering: {
    toName: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.name`,
    toValidFrom: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.valid_from`,
    toValidUntil: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.valid_until`,
    toPatternType: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.pattern_type`,
    toCreatedAt: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.created_at`,
  },
  StixSighting: {
    from: (rel) => loadById(rel.fromId, rel.fromType),
    to: (rel) => loadById(rel.toId, rel.toType),
    toStix: (rel) => convertDataToStix(rel).then((stixData) => JSON.stringify(stixData)),
  },
  RelationEmbedded: {
    from: (rel) => loadById(rel.fromId, rel.fromType),
    to: (rel) => loadById(rel.toId, rel.toType),
  },
  Mutation: {
    stixSightingEdit: (_, { id }, { user }) => ({
      delete: () => stixSightingDelete(user, id),
      fieldPatch: ({ input }) => stixSightingEditField(user, id, input),
      contextPatch: ({ input }) => stixSightingEditContext(user, id, input),
      contextClean: () => stixSightingCleanContext(user, id),
      relationAdd: ({ input }) => stixSightingAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixSightingDeleteRelation(user, id, relationId),
    }),
    stixSightingAdd: (_, { input, reversedReturn }, { user }) => addstixSighting(user, input, reversedReturn),
  },
  Subscription: {
    stixSighting: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
        stixSightingEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.stixSighting.EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          stixSightingCleanContext(user, id);
        });
      },
    },
  },
};

export default stixSightingResolvers;
