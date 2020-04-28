import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixObservable,
  findAll,
  findById,
  indicators,
  stixObservableAddRelation,
  stixObservableAddRelations,
  stixObservableAskEnrichment,
  stixObservableCleanContext,
  stixObservableDelete,
  stixObservableDeleteRelation,
  stixObservableEditContext,
  stixObservableEditField,
  stixObservablesNumber,
  stixObservablesTimeSeries,
} from '../domain/stixObservable';
import { pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { workForEntity } from '../domain/work';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import { connectorsForEnrichment } from '../domain/enrichment';
import { convertDataToStix } from '../database/stix';

const stixObservableResolvers = {
  Query: {
    stixObservable: (_, { id }) => findById(id),
    stixObservables: (_, args) => findAll(args),
    stixObservablesTimeSeries: (_, args) => stixObservablesTimeSeries(args),
    stixObservablesNumber: (_, args) => stixObservablesNumber(args),
  },
  StixObservablesOrdering: {
    markingDefinitions: `${REL_INDEX_PREFIX}object_marking_refs.definition`,
    tags: `${REL_INDEX_PREFIX}tagged.value`,
  },
  StixObservablesFilter: {
    createdBy: `${REL_INDEX_PREFIX}created_by_ref.internal_id_key`,
    markingDefinitions: `${REL_INDEX_PREFIX}object_marking_refs.internal_id_key`,
    tags: `${REL_INDEX_PREFIX}tagged.internal_id_key`,
    relatedTo: `${REL_INDEX_PREFIX}related-to.internal_id_key`,
    observablesContained: `${REL_INDEX_PREFIX}observable_refs.internal_id_key`,
  },
  StixObservable: {
    indicators: (stixObservable) => indicators(stixObservable.id),
    jobs: (stixObservable, args) => workForEntity(stixObservable.id, args),
    connectors: (stixObservable, { onlyAlive = false }) =>
      connectorsForEnrichment(stixObservable.entity_type, onlyAlive),
    toStix: (stixObservable) => convertDataToStix(stixObservable).then((stixData) => JSON.stringify(stixData)),
  },
  Mutation: {
    stixObservableEdit: (_, { id }, { user }) => ({
      delete: () => stixObservableDelete(user, id),
      fieldPatch: ({ input }) => stixObservableEditField(user, id, input),
      contextPatch: ({ input }) => stixObservableEditContext(user, id, input),
      contextClean: () => stixObservableCleanContext(user, id),
      relationAdd: ({ input }) => stixObservableAddRelation(user, id, input),
      relationsAdd: ({ input }) => stixObservableAddRelations(user, id, input),
      relationDelete: ({ relationId, toId, relationType }) =>
        stixObservableDeleteRelation(user, id, relationId, toId, relationType),
      askEnrichment: ({ connectorId }) => stixObservableAskEnrichment(id, connectorId),
    }),
    stixObservableAdd: (_, { input }, { user }) => addStixObservable(user, input),
  },
  Subscription: {
    stixObservable: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
        stixObservableEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.StixObservable.EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          stixObservableCleanContext(user, id);
        });
      },
    },
  },
};

export default stixObservableResolvers;
