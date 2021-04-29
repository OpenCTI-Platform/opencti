import { withFilter } from 'graphql-subscriptions';
import { assoc } from 'ramda';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixCyberObservable,
  findAll,
  findById,
  batchIndicators,
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
  stixCyberObservablesExportPush,
  stixCyberObservablesExportAsk,
  promoteObservableToIndicator,
  artifactImport,
} from '../domain/stixCyberObservable';
import { pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { worksForSource } from '../domain/work';
import { connectorsForEnrichment } from '../domain/enrichment';
import { convertDataToStix } from '../database/stix';
import { stixCoreRelationships } from '../domain/stixCoreObject';
import { filesListing } from '../database/minio';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../schema/general';
import { complexAttributeToApiFormat } from '../schema/fieldDataAdapter';
import { stixCyberObservableOptions } from '../schema/stixCyberObservable';
import { batchLoader } from '../database/middleware';

const indicatorsLoader = batchLoader(batchIndicators);

const stixCyberObservableResolvers = {
  Query: {
    stixCyberObservable: (_, { id }, { user }) => findById(user, id),
    stixCyberObservables: (_, args, { user }) => findAll(user, args),
    stixCyberObservablesTimeSeries: (_, args, { user }) => stixCyberObservablesTimeSeries(user, args),
    stixCyberObservablesNumber: (_, args, { user }) => stixCyberObservablesNumber(user, args),
    stixCyberObservablesDistribution: (_, args, { user }) => {
      if (args.objectId && args.objectId.length > 0) {
        return stixCyberObservableDistributionByEntity(user, args);
      }
      return stixCyberObservableDistribution(user, args);
    },
    stixCyberObservablesExportFiles: (_, { first }, { user }) =>
      filesListing(user, first, 'export/Stix-Cyber-Observable/'),
  },
  StixCyberObservablesFilter: stixCyberObservableOptions.StixCyberObservablesFilter,
  HashedObservable: {
    hashes: (stixCyberObservable) => complexAttributeToApiFormat('hashes', stixCyberObservable),
  },
  StixCyberObservable: {
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      return 'Unknown';
    },
    observable_value: (stixCyberObservable) => observableValue(stixCyberObservable),
    indicators: (stixCyberObservable, _, { user }) => indicatorsLoader.load(stixCyberObservable.id, user),
    jobs: (stixCyberObservable, args, { user }) => worksForSource(user, stixCyberObservable.id, args),
    connectors: (stixCyberObservable, { onlyAlive = false }, { user }) =>
      connectorsForEnrichment(user, stixCyberObservable.entity_type, onlyAlive),
    stixCoreRelationships: (rel, args, { user }) => stixCoreRelationships(user, rel.id, args),
    toStix: (stixCyberObservable) => JSON.stringify(convertDataToStix(stixCyberObservable)),
  },
  Artifact: {
    importFiles: (stixCyberObservable, { first }, { user }) =>
      filesListing(user, first, `import/${stixCyberObservable.entity_type}/${stixCyberObservable.id}/`),
  },
  Mutation: {
    stixCyberObservableEdit: (_, { id }, { user }) => ({
      delete: () => stixCyberObservableDelete(user, id),
      fieldPatch: ({ input, operation }) => stixCyberObservableEditField(user, id, input, { operation }),
      contextPatch: ({ input }) => stixCyberObservableEditContext(user, id, input),
      contextClean: () => stixCyberObservableCleanContext(user, id),
      relationAdd: ({ input }) => stixCyberObservableAddRelation(user, id, input),
      relationsAdd: ({ input }) => stixCyberObservableAddRelations(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        stixCyberObservableDeleteRelation(user, id, toId, relationshipType),
      exportAsk: (args) => stixCyberObservableExportAsk(user, assoc('stixCyberObservableId', id, args)),
      exportPush: ({ file }) => stixCyberObservableExportPush(user, id, file),
      askEnrichment: ({ connectorId }) => stixCyberObservableAskEnrichment(user, id, connectorId),
      promote: () => promoteObservableToIndicator(user, id),
    }),
    stixCyberObservableAdd: (_, args, { user }) => addStixCyberObservable(user, args),
    stixCyberObservablesExportAsk: (_, args, { user }) => stixCyberObservablesExportAsk(user, args),
    stixCyberObservablesExportPush: (_, { file, listFilters }, { user }) =>
      stixCyberObservablesExportPush(user, file, listFilters),
    artifactImport: (_, args, { user }) => artifactImport(user, args),
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
