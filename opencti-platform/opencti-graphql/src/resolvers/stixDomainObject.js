import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixDomainObject,
  findAll,
  findById,
  stixDomainObjectAddRelation,
  stixDomainObjectAvatar,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
  stixDomainObjectExportAsk,
  stixDomainObjectFileEdit,
  stixDomainObjectsDelete,
  stixDomainObjectsDistributionByEntity,
  stixDomainObjectsExportAsk,
  stixDomainObjectsNumber,
  stixDomainObjectsTimeSeries,
  stixDomainObjectsTimeSeriesByAuthor
} from '../domain/stixDomainObject';
import { findById as findStatusById, findByType } from '../domain/status';
import { pubSubAsyncIterator } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { ABSTRACT_STIX_DOMAIN_OBJECT, INPUT_ASSIGNEE } from '../schema/general';
import { stixDomainObjectOptions as StixDomainObjectsOptions } from '../schema/stixDomainObjectOptions';
import { stixCoreObjectExportPush, stixCoreObjectImportPush, stixCoreObjectsExportPush } from '../domain/stixCoreObject';
import { paginatedForPathWithEnrichment } from '../modules/internal/document/document-domain';
import { loadThroughDenormalized } from './stix';

const stixDomainObjectResolvers = {
  Query: {
    stixDomainObject: (_, { id }, context) => findById(context, context.user, id),
    stixDomainObjects: (_, args, context) => findAll(context, context.user, args),
    stixDomainObjectsTimeSeries: (_, args, context) => {
      if (args.authorId && args.authorId.length > 0) {
        return stixDomainObjectsTimeSeriesByAuthor(context, context.user, args);
      }
      return stixDomainObjectsTimeSeries(context, context.user, args);
    },
    stixDomainObjectsNumber: (_, args, context) => stixDomainObjectsNumber(context, context.user, args),
    stixDomainObjectsDistribution: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return stixDomainObjectsDistributionByEntity(context, context.user, args);
      }
      return [];
    },
    stixDomainObjectsExportFiles: (_, { exportContext, first }, context) => {
      const path = `export/${exportContext.entity_type}${exportContext.entity_id ? `/${exportContext.entity_id}` : ''}`;
      const opts = { first, entity_type: exportContext.entity_type };
      return paginatedForPathWithEnrichment(context, context.user, path, exportContext.entity_id, opts);
    },
  },
  StixDomainObjectsOrdering: StixDomainObjectsOptions.StixDomainObjectsOrdering,
  StixDomainObject: {
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      return 'Unknown';
    },
    avatar: (stixDomainObject) => stixDomainObjectAvatar(stixDomainObject),
    status: (stixDomainObject, _, context) => (stixDomainObject.x_opencti_workflow_id ? findStatusById(context, context.user, stixDomainObject.x_opencti_workflow_id) : null),
    objectAssignee: (stixDomainObject, args, context) => loadThroughDenormalized(context, context.user, stixDomainObject, INPUT_ASSIGNEE, { sortBy: 'user_email' }),
    workflowEnabled: async (stixDomainObject, _, context) => {
      const statusesType = await findByType(context, context.user, stixDomainObject.entity_type);
      return statusesType.length > 0;
    },
  },
  Mutation: {
    stixDomainObjectEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
      importPush: (args) => stixCoreObjectImportPush(context, context.user, id, args.file, args),
      exportAsk: (args) => stixDomainObjectExportAsk(context, context.user, id, args),
      exportPush: ({ file }) => stixCoreObjectExportPush(context, context.user, id, file),
      stixDomainObjectFileEdit: ({ input }) => stixDomainObjectFileEdit(context, context.user, id, input),
    }),
    stixDomainObjectsDelete: (_, { id }, context) => stixDomainObjectsDelete(context, context.user, id),
    stixDomainObjectAdd: (_, { input }, context) => addStixDomainObject(context, context.user, input),
    stixDomainObjectsExportAsk: (_, args, context) => stixDomainObjectsExportAsk(context, context.user, args),
    stixDomainObjectsExportPush: (_, { entity_id, entity_type, file, listFilters }, context) => {
      return stixCoreObjectsExportPush(context, context.user, entity_id, entity_type, file, listFilters);
    },
  },
  Subscription: {
    stixDomainObject: {
      resolve: /* v8 ignore next */ (payload) => payload.instance,
      subscribe: /* v8 ignore next */ (_, { id }, context) => {
        stixDomainObjectEditContext(context, context.user, id);
        const bus = BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT];
        const filtering = withFilter(
          () => pubSubAsyncIterator([bus.EDIT_TOPIC, bus.CONTEXT_TOPIC]),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== context.user.id && payload.instance.id === id;
          }
        )(_, { id }, context);
        return withCancel(filtering, () => {
          stixDomainObjectCleanContext(context, context.user, id);
        });
      },
    },
  },
};

export default stixDomainObjectResolvers;
