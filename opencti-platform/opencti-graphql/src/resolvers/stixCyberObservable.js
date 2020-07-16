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
  stixObservableExportAsk,
  stixObservableExportPush,
} from '../domain/stixCyberObservable';
import { pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { workForEntity } from '../domain/work';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import { connectorsForEnrichment } from '../domain/enrichment';
import { convertDataToStix } from '../database/stix';
import { stixRelations } from '../domain/stixCoreObject';
import { filesListing } from '../database/minio';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../utils/idGenerator';

const stixObservableResolvers = {
  Query: {
    stixObservable: (_, { id }) => findById(id),
    stixObservables: (_, args) => findAll(args),
    stixObservablesTimeSeries: (_, args) => stixObservablesTimeSeries(args),
    stixObservablesNumber: (_, args) => stixObservablesNumber(args),
    stixObservablesExportFiles: (_, { first, context }) =>
      filesListing(first, 'export', 'stix-observable', null, context),
  },
  StixObservablesOrdering: {
    markingDefinitions: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.definition`,
    labels: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.value`,
  },
  StixObservablesFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markingDefinitions: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labels: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
    relatedTo: `${REL_INDEX_PREFIX}related-to.internal_id`,
    observablesContained: `${REL_INDEX_PREFIX}observable_refs.internal_id`,
  },
  StixObservable: {
    indicators: (stixObservable) => indicators(stixObservable.id),
    jobs: (stixObservable, args) => workForEntity(stixObservable.id, args),
    connectors: (stixObservable, { onlyAlive = false }) =>
      connectorsForEnrichment(stixObservable.entity_type, onlyAlive),
    stixRelations: (rel, args) => stixRelations(rel.id, args),
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
    stixObservablesExportAsk: (_, args) => stixObservableExportAsk(args),
    stixObservablesExportPush: (_, { file, context, listArgs }, { user }) =>
      stixObservableExportPush(user, null, file, context, listArgs),
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
