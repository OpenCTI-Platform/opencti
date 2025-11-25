import { BUS_TOPICS } from '../config/conf';
import {
  addStixCyberObservable,
  artifactImport,
  findStixCyberObservablePaginated,
  findById,
  indicatorsPaginated,
  promoteObservableToIndicator,
  serviceDllsPaginated,
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
  stixCyberObservablesTimeSeries,
  stixFileObsArtifact,
  vulnerabilitiesPaginated
} from '../domain/stixCyberObservable';
import { subscribeToInstanceEvents } from '../graphql/subscriptionWrapper';
import { stixCoreObjectExportPush, stixCoreObjectImportPush, stixCoreObjectsExportPush, stixCoreRelationshipsPaginated } from '../domain/stixCoreObject';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../schema/general';
import { stixHashesToInput } from '../schema/fieldDataAdapter';
import { stixCyberObservableOptions } from '../schema/stixCyberObservable';
import { stixLoadByIdStringify } from '../database/middleware';
import { observableValue } from '../utils/format';
import { paginatedForPathWithEnrichment } from '../modules/internal/document/document-domain';
import { countriesPaginated } from '../domain/region';

const stixCyberObservableResolvers = {
  Query: {
    stixCyberObservable: (_, { id }, context) => findById(context, context.user, id),
    stixCyberObservables: (_, args, context) => findStixCyberObservablePaginated(context, context.user, args),
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
      const opts = { first, entity_id: exportContext.entity_id, entity_type: exportContext.entity_type };
      return paginatedForPathWithEnrichment(context, context.user, path, exportContext.entity_id, opts);
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
    stixCoreRelationships: (rel, args, context) => stixCoreRelationshipsPaginated(context, context.user, rel.id, args),
    toStix: (stixCyberObservable, args, context) => stixLoadByIdStringify(context, context.user, stixCyberObservable.id, args),
    importFiles: (stixCyberObservable, { first }, context) => {
      const path = `import/${stixCyberObservable.entity_type}/${stixCyberObservable.id}`;
      const opts = { first, entity_type: stixCyberObservable.entity_type };
      return paginatedForPathWithEnrichment(context, context.user, path, stixCyberObservable.id, opts);
    },
    exportFiles: (stixCyberObservable, { first }, context) => {
      const path = `export/${stixCyberObservable.entity_type}/${stixCyberObservable.id}`;
      const opts = { first, entity_type: stixCyberObservable.entity_type };
      return paginatedForPathWithEnrichment(context, context.user, path, stixCyberObservable.id, opts);
    },
    indicators: (stixCyberObservable, args, context) => indicatorsPaginated(context, context.user, stixCyberObservable.id, args),
  },
  Process: {
    serviceDlls: (process, args, context) => serviceDllsPaginated(context, context.user, process.id, args),
  },
  StixFile: {
    obsContent: (stixFile, _, context) => stixFileObsArtifact(context, context.user, stixFile.id),
  },
  Software: {
    vulnerabilities: (software, args, context) => vulnerabilitiesPaginated(context, context.user, software.id, args),
  },
  IPv4Addr: {
    countries: (ip, args, context) => countriesPaginated(context, context.user, ip.id, args),
  },
  IPv6Addr: {
    countries: (ip, args, context) => countriesPaginated(context, context.user, ip.id, args),
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
      importPush: (args) => stixCoreObjectImportPush(context, context.user, id, args.file, args),
      promoteToIndicator: () => promoteObservableToIndicator(context, context.user, id)
    }),
    stixCyberObservableAdd: (_, args, context) => addStixCyberObservable(context, context.user, args),
    stixCyberObservablesExportAsk: (_, { input }, context) => stixCyberObservablesExportAsk(context, context.user, input),
    stixCyberObservablesExportPush: (_, { entity_id, entity_type, file, file_markings, listFilters }, context) => {
      const entityType = entity_type ?? 'Stix-Cyber-Observable';
      return stixCoreObjectsExportPush(context, context.user, entity_id, entityType, file, file_markings, listFilters);
    },
    artifactImport: (_, args, context) => artifactImport(context, context.user, args),
  },
  Subscription: {
    stixCyberObservable: {
      resolve: /* v8 ignore next */ (payload) => payload.instance,
      subscribe: /* v8 ignore next */ (_, { id }, context) => {
        const preFn = () => stixCyberObservableEditContext(context, context.user, id);
        const cleanFn = () => stixCyberObservableCleanContext(context, context.user, id);
        const bus = BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE];
        return subscribeToInstanceEvents(_, context, id, [bus.EDIT_TOPIC], { type: ABSTRACT_STIX_CYBER_OBSERVABLE, preFn, cleanFn });
      },
    },
  },
};

export default stixCyberObservableResolvers;
