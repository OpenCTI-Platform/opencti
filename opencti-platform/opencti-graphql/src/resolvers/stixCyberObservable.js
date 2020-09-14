import { withFilter } from 'graphql-subscriptions';
import { assoc } from 'ramda';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixCyberObservable,
  findAll,
  findById,
  indicators,
  observableValue,
  stixCyberObservableAddRelation,
  stixCyberObservableAddRelations,
  stixCyberObservableAskEnrichment,
  stixCyberObservableCleanContext,
  stixCyberObservableDelete,
  stixCyberObservableDeleteRelation,
  stixCyberObservableEditContext,
  stixCyberObservableEditField,
  stixCyberObservablesNumber,
  stixCyberObservablesTimeSeries,
  stixCyberObservableExportAsk,
  stixCyberObservableExportPush,
  stixCyberObservableDistribution,
  stixCyberObservableDistributionByEntity,
} from '../domain/stixCyberObservable';
import { pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { workForEntity } from '../domain/work';
import { connectorsForEnrichment } from '../domain/enrichment';
import { convertDataToStix } from '../database/stix';
import { stixCoreRelationships } from '../domain/stixCoreObject';
import { filesListing } from '../database/minio';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../schema/general';
import { complexAttributeToApiFormat } from '../schema/fieldDataAdapter';
import { stixCyberObservableOptions } from '../schema/stixCyberObservableObject';

const stixCyberObservableResolvers = {
  Query: {
    stixCyberObservable: (_, { id }) => findById(id),
    stixCyberObservables: (_, args) => findAll(args),
    stixCyberObservablesTimeSeries: (_, args) => stixCyberObservablesTimeSeries(args),
    stixCyberObservablesNumber: (_, args) => stixCyberObservablesNumber(args),
    stixCyberObservablesDistribution: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return stixCyberObservableDistributionByEntity(args);
      }
      return stixCyberObservableDistribution(args);
    },
    stixCyberObservablesExportFiles: (_, { first, context }) =>
      filesListing(first, 'export', 'stix-observable', null, context),
  },
  StixCyberObservablesOrdering: stixCyberObservableOptions.StixCyberObservablesOrdering,
  StixCyberObservablesFilter: stixCyberObservableOptions.StixCyberObservablesFilter,
  HashedObservable: {
    hashes: (stixCyberObservable) => complexAttributeToApiFormat('hashes', stixCyberObservable),
  },
  StixCyberObservable: {
    // eslint-disable-next-line no-underscore-dangle
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      return 'Unknown';
    },
    observable_value: (stixCyberObservable) => observableValue(stixCyberObservable),
    indicators: (stixCyberObservable) => indicators(stixCyberObservable.id),
    jobs: (stixCyberObservable, args) => workForEntity(stixCyberObservable.id, args),
    connectors: (stixCyberObservable, { onlyAlive = false }) =>
      connectorsForEnrichment(stixCyberObservable.entity_type, onlyAlive),
    stixCoreRelationships: (rel, args) => stixCoreRelationships(rel.id, args),
    toStix: (stixCyberObservable) => JSON.stringify(convertDataToStix(stixCyberObservable)),
  },
  Mutation: {
    stixCyberObservableEdit: (_, { id }, { user }) => ({
      delete: () => stixCyberObservableDelete(user, id),
      fieldPatch: ({ input }) => stixCyberObservableEditField(user, id, input),
      contextPatch: ({ input }) => stixCyberObservableEditContext(user, id, input),
      contextClean: () => stixCyberObservableCleanContext(user, id),
      relationAdd: ({ input }) => stixCyberObservableAddRelation(user, id, input),
      relationsAdd: ({ input }) => stixCyberObservableAddRelations(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        stixCyberObservableDeleteRelation(user, id, toId, relationshipType),
      exportAsk: (args) => stixCyberObservableExportAsk(assoc('stixCyberObservableId', id, args)),
      askEnrichment: ({ connectorId }) => stixCyberObservableAskEnrichment(id, connectorId),
    }),
    stixCyberObservableAdd: (_, args, { user }) => addStixCyberObservable(user, args),
    stixCyberObservablesExportAsk: (_, args) => stixCyberObservableExportAsk(args),
    stixCyberObservablesExportPush: (_, { file, context, listArgs }, { user }) =>
      stixCyberObservableExportPush(user, null, file, context, listArgs),
  },
  Subscription: {
    stixCyberObservable: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
        stixCyberObservableEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          stixCyberObservableCleanContext(user, id);
        });
      },
    },
  },
};

export default stixCyberObservableResolvers;
