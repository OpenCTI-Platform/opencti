import { withFilter } from 'graphql-subscriptions';
import { assoc } from 'ramda';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixCyberObservable,
  findAll,
  findById,
  batchIndicators,
  stixCyberObservableAddRelation,
  stixCyberObservableAddRelations,
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
  batchVulnerabilities
} from '../domain/stixCyberObservable';
import { pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { stixCoreObjectImportPush, stixCoreRelationships } from '../domain/stixCoreObject';
import { filesListing } from '../database/file-storage';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../schema/general';
import { stixHashesToInput } from '../schema/fieldDataAdapter';
import { stixCyberObservableOptions } from '../schema/stixCyberObservable';
import { batchLoader, stixLoadByIdStringify } from '../database/middleware';
import { observableValue } from '../utils/format';

const indicatorsLoader = batchLoader(batchIndicators);
const vulnerabilitiesLoader = batchLoader(batchVulnerabilities);

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
    stixCyberObservablesExportFiles: (_, { first }, { user }) => filesListing(user, first, 'export/Stix-Cyber-Observable/'),
  },
  StixCyberObservablesFilter: stixCyberObservableOptions.StixCyberObservablesFilter,
  HashedObservable: {
    hashes: (stixCyberObservable) => stixHashesToInput(stixCyberObservable),
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
    stixCoreRelationships: (rel, args, { user }) => stixCoreRelationships(user, rel.id, args),
    toStix: (stixCyberObservable, _, { user }) => stixLoadByIdStringify(user, stixCyberObservable.id),
    importFiles: (stixCyberObservable, { first }, { user }) => filesListing(user, first, `import/${stixCyberObservable.entity_type}/${stixCyberObservable.id}/`),
    exportFiles: (stixCyberObservable, { first }, { user }) => filesListing(user, first, `export/${stixCyberObservable.entity_type}/${stixCyberObservable.id}/`),
  },
  Software: {
    vulnerabilities: (software, _, { user }) => vulnerabilitiesLoader.load(software.id, user),
  },
  Mutation: {
    stixCyberObservableEdit: (_, { id }, { user }) => ({
      delete: () => stixCyberObservableDelete(user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixCyberObservableEditField(user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixCyberObservableEditContext(user, id, input),
      contextClean: () => stixCyberObservableCleanContext(user, id),
      relationAdd: ({ input }) => stixCyberObservableAddRelation(user, id, input),
      relationsAdd: ({ input }) => stixCyberObservableAddRelations(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixCyberObservableDeleteRelation(user, id, toId, relationshipType),
      exportAsk: (args) => stixCyberObservableExportAsk(user, assoc('stixCyberObservableId', id, args)),
      exportPush: ({ file }) => stixCyberObservableExportPush(user, id, file),
      importPush: ({ file }) => stixCoreObjectImportPush(user, id, file),
      promote: () => promoteObservableToIndicator(user, id),
    }),
    stixCyberObservableAdd: (_, args, { user }) => addStixCyberObservable(user, args),
    stixCyberObservablesExportAsk: (_, args, { user }) => stixCyberObservablesExportAsk(user, args),
    stixCyberObservablesExportPush: (_, { file, listFilters }, { user }) => stixCyberObservablesExportPush(user, file, listFilters),
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
