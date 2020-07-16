import { withFilter } from 'graphql-subscriptions';
import { assoc } from 'ramda';
import { BUS_TOPICS } from '../config/conf';
import {
  addstixDomainObject,
  findAll,
  findById,
  stixDomainObjectsNumber,
  stixDomainObjectsTimeSeries,
  stixDomainObjectAddRelation,
  stixDomainObjectAddRelations,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectsDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
  stixDomainObjectExportAsk,
  stixDomainObjectExportPush,
  stixDomainObjectImportPush,
  stixDomainObjectMerge,
} from '../domain/stixDomainObject';
import { pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { filesListing } from '../database/minio';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import {
  RELATION_CREATED_BY,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT,
  RELATION_OBJECT_MARKING,
} from '../utils/idGenerator';

const stixDomainObjectResolvers = {
  Query: {
    stixDomainObject: (_, { id }) => findById(id),
    stixDomainObjects: (_, args) => findAll(args),
    stixDomainObjectsTimeSeries: (_, args) => stixDomainObjectsTimeSeries(args),
    stixDomainObjectsNumber: (_, args) => stixDomainObjectsNumber(args),
    stixDomainObjectsExportFiles: (_, { type, first, context }) => filesListing(first, 'export', type, null, context),
  },
  StixDomainObjectsOrdering: {
    markingDefinitions: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.definition`,
    labels: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.value`,
  },
  StixDomainObjectsFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
    objectContains: `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`,
    hasExternalReference: `${REL_INDEX_PREFIX}${RELATION_EXTERNAL_REFERENCE}.internal_id`,
    indicates: `${REL_INDEX_PREFIX}indicates.internal_id`,
  },
  StixDomainObject: {
    // eslint-disable-next-line no-underscore-dangle
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      return 'Unknown';
    },
    importFiles: (entity, { first }) => filesListing(first, 'import', entity.entity_type, entity),
    exportFiles: (entity, { first }) => filesListing(first, 'export', entity.entity_type, entity),
  },
  Mutation: {
    stixDomainObjectEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input }) => stixDomainObjectEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationsAdd: ({ input }) => stixDomainObjectAddRelations(user, id, input),
      relationDelete: ({ relationId, toId, relationType }) =>
        stixDomainObjectDeleteRelation(user, id, relationId, toId, relationType),
      importPush: ({ file }) => stixDomainObjectImportPush(user, null, id, file),
      exportAsk: (args) => stixDomainObjectExportAsk(assoc('stixDomainObjectId', id, args)),
      exportPush: ({ file }) => stixDomainObjectExportPush(user, null, id, file),
      mergeEntities: ({ stixDomainObjectsIds, alias }) => stixDomainObjectMerge(user, id, stixDomainObjectsIds, alias),
    }),
    stixDomainObjectsDelete: (_, { id }, { user }) => stixDomainObjectsDelete(user, id),
    stixDomainObjectAdd: (_, { input }, { user }) => addstixDomainObject(user, input),
    stixDomainObjectsExportAsk: (_, args) => stixDomainObjectExportAsk(args),
    stixDomainObjectsExportPush: (_, { type, file, context, listArgs }, { user }) =>
      stixDomainObjectExportPush(user, type, null, file, context, listArgs),
  },
  Subscription: {
    stixDomainObject: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
        stixDomainObjectEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.stixDomainObject.EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          stixDomainObjectCleanContext(user, id);
        });
      },
    },
  },
};

export default stixDomainObjectResolvers;
