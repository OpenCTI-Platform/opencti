import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixCyberObservable,
  artifactImport,
  batchArtifacts,
  batchCountries,
  batchIndicators,
  batchStixFiles,
  batchVulnerabilities,
  findAll,
  findById,
  promoteObservableToIndicator,
  stixCyberObservableAddRelation,
  stixCyberObservableCleanContext,
  stixCyberObservableDelete,
  stixCyberObservableDeleteRelation,
  stixCyberObservableDistribution,
  stixCyberObservableDistributionByEntity,
  stixCyberObservableEditContext,
  stixCyberObservableEditField,
  stixCyberObservableExportAsk,
  stixCyberObservablesExportAsk,
  stixCyberObservablesNumber,
  stixCyberObservablesTimeSeries
} from '../domain/stixCyberObservable';
import { pubSubAsyncIterator } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { stixCoreObjectExportPush, stixCoreObjectImportPush, stixCoreObjectsExportPush, stixCoreRelationships } from '../domain/stixCoreObject';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../schema/general';
import { stixHashesToInput } from '../schema/fieldDataAdapter';
import { stixCyberObservableOptions } from '../schema/stixCyberObservable';
import { batchLoader, stixLoadByIdStringify } from '../database/middleware';
import { observableValue } from '../utils/format';
import { paginatedForPathsWithEnrichment } from '../modules/internal/document/document-domain';

const indicatorsLoader = batchLoader(batchIndicators);
const vulnerabilitiesLoader = batchLoader(batchVulnerabilities);
const countriesLoader = batchLoader(batchCountries);
const stixFileLoader = batchLoader(batchStixFiles);
const artifactsLoader = batchLoader(batchArtifacts);

const stixCyberObservableResolvers = {
  Query: {
    stixCyberObservable: (_, { id }, context) => findById(context, context.user, id),
    stixCyberObservables: (_, args, context) => findAll(context, context.user, args),
    stixCyberObservablesTimeSeries: (_, args, context) => {
      return stixCyberObservablesTimeSeries(context, context.user, args);
    },
    stixCyberObservablesNumber: (_, args, context) => {
      return stixCyberObservablesNumber(context, context.user, args);
    },
    stixCyberObservablesDistribution: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return stixCyberObservableDistributionByEntity(context, context.user, args);
      }
      return stixCyberObservableDistribution(context, context.user, args);
    },
    stixCyberObservablesExportFiles: (_, { exportContext, first }, context) => {
      const path = `export/${exportContext.entity_type}${exportContext.entity_id ? `/${exportContext.entity_id}` : ''}`;
      return paginatedForPathsWithEnrichment(context, context.user, [path], { first });
    },
  },
  StixCyberObservablesOrdering: stixCyberObservableOptions.StixCyberObservablesOrdering,
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
    indicators: (stixCyberObservable, _, context) => indicatorsLoader.load(stixCyberObservable.id, context, context.user),
    stixCoreRelationships: (rel, args, context) => stixCoreRelationships(context, context.user, rel.id, args),
    toStix: (stixCyberObservable, _, context) => stixLoadByIdStringify(context, context.user, stixCyberObservable.id),
    importFiles: (stixCyberObservable, { first }, context) => {
      const path = `import/${stixCyberObservable.entity_type}/${stixCyberObservable.id}`;
      return paginatedForPathsWithEnrichment(context, context.user, [path], { first, entity_id: stixCyberObservable.id });
    },
    exportFiles: (stixCyberObservable, { first }, context) => {
      const path = `export/${stixCyberObservable.entity_type}/${stixCyberObservable.id}`;
      return paginatedForPathsWithEnrichment(context, context.user, [path], { first, entity_id: stixCyberObservable.id });
    },
  },
  Process: {
    serviceDlls: (process, _, { user }) => stixFileLoader.load(process.id, user),
  },
  StixFile: {
    obsContent: (stixFile, _, context) => artifactsLoader.load(stixFile.id, context, context.user),
  },
  Software: {
    vulnerabilities: (software, _, context) => vulnerabilitiesLoader.load(software.id, context, context.user),
  },
  IPv4Addr: {
    countries: (ip, _, context) => countriesLoader.load(ip.id, context, context.user),
  },
  IPv6Addr: {
    countries: (ip, _, context) => countriesLoader.load(ip.id, context, context.user),
  },
  Mutation: {
    stixCyberObservableEdit: (_, { id }, context) => ({
      delete: () => stixCyberObservableDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => {
        return stixCyberObservableEditField(context, context.user, id, input, { commitMessage, references });
      },
      contextPatch: ({ input }) => stixCyberObservableEditContext(context, context.user, id, input),
      contextClean: () => stixCyberObservableCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixCyberObservableAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => {
        return stixCyberObservableDeleteRelation(context, context.user, id, toId, relationshipType);
      },
      exportAsk: (args) => stixCyberObservableExportAsk(context, context.user, id, args),
      exportPush: ({ file }) => stixCoreObjectExportPush(context, context.user, id, file),
      importPush: ({ file }) => stixCoreObjectImportPush(context, context.user, id, file),
      promote: () => promoteObservableToIndicator(context, context.user, id),
    }),
    stixCyberObservableAdd: (_, args, context) => addStixCyberObservable(context, context.user, args),
    stixCyberObservablesExportAsk: (_, args, context) => stixCyberObservablesExportAsk(context, context.user, args),
    stixCyberObservablesExportPush: (_, { entity_id, entity_type, file, listFilters }, context) => {
      const entityType = entity_type ?? 'Stix-Cyber-Observable';
      return stixCoreObjectsExportPush(context, context.user, entity_id, entityType, file, listFilters);
    },
    artifactImport: (_, args, context) => artifactImport(context, context.user, args),
  },
  Subscription: {
    stixCyberObservable: {
      resolve: /* v8 ignore next */ (payload) => payload.instance,
      subscribe: /* v8 ignore next */ (_, { id }, context) => {
        stixCyberObservableEditContext(context, context.user, id);
        const filtering = withFilter(
          () => pubSubAsyncIterator(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== context.user.id && payload.instance.id === id;
          }
        )(_, { id }, context);
        return withCancel(filtering, () => {
          stixCyberObservableCleanContext(context, context.user, id);
        });
      },
    },
  },
};

export default stixCyberObservableResolvers;
