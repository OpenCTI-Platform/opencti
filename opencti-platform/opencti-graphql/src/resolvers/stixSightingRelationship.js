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
} from '../domain/stixSightingRelationship';
import { pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { distributionRelations, loadById, timeSeriesRelations, REL_CONNECTED_SUFFIX } from '../database/grakn';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import { convertDataToStix } from '../database/stix';
import {
  RELATION_CREATED_BY,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
  STIX_SIGHTING_RELATIONSHIP,
} from '../utils/idGenerator';

const stixSightingRelationshipResolvers = {
  Query: {
    stixSightingRelationship: (_, { id }) => findById(id),
    stixSightingRelationships: (_, args) => findAll(args),
    stixSightingRelationshipsTimeSeries: (_, args) => timeSeriesRelations(args),
    stixSightingRelationshipsDistribution: async (_, args) => distributionRelations(args),
    stixSightingRelationshipsNumber: (_, args) => stixSightingRelationshipsNumber(args),
  },
  StixSightingRelationshipsOrdering: {
    objectMarking: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.definition`,
    objectLabel: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.value`,
    toName: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.name`,
    toValidFrom: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.valid_from`,
    toValidUntil: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.valid_until`,
    toPatternType: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.pattern_type`,
    toCreatedAt: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.created_at`,
  },
  StixSightingRelationshipsFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
    toPatternType: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.pattern_type`,
    toMainObservableType: `${REL_INDEX_PREFIX}${REL_CONNECTED_SUFFIX}to.main_observable_type`,
  },
  StixSightingRelationship: {
    from: (rel) => loadById(rel.fromId, rel.fromType),
    to: (rel) => loadById(rel.toId, rel.toType),
    toStix: (rel) => convertDataToStix(rel).then((stixData) => JSON.stringify(stixData)),
  },
  Mutation: {
    stixSightingRelationshipEdit: (_, { id }, { user }) => ({
      delete: () => stixSightingRelationshipDelete(user, id),
      fieldPatch: ({ input }) => stixSightingRelationshipEditField(user, id, input),
      contextPatch: ({ input }) => stixSightingRelationshipEditContext(user, id, input),
      contextClean: () => stixSightingRelationshipCleanContext(user, id),
      relationAdd: ({ input }) => stixSightingRelationshipAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixSightingRelationshipDeleteRelation(user, id, relationId),
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
