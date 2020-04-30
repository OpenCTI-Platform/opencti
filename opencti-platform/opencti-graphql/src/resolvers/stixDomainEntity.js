import { withFilter } from 'graphql-subscriptions';
import { assoc } from 'ramda';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixDomainEntity,
  findAll,
  findAllDuplicates,
  findById,
  stixDomainEntitiesNumber,
  stixDomainEntitiesTimeSeries,
  stixDomainEntityAddRelation,
  stixDomainEntityAddRelations,
  stixDomainEntityCleanContext,
  stixDomainEntityDelete,
  stixDomainEntitiesDelete,
  stixDomainEntityDeleteRelation,
  stixDomainEntityEditContext,
  stixDomainEntityEditField,
  stixDomainEntityExportAsk,
  stixDomainEntityExportPush,
  stixDomainEntityImportPush,
  stixDomainEntityMerge,
} from '../domain/stixDomainEntity';
import { pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { filesListing } from '../database/minio';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';

const stixDomainEntityResolvers = {
  Query: {
    stixDomainEntity: (_, { id }) => findById(id),
    stixDomainEntities: (_, args) => findAll(args),
    duplicateStixDomainEntities: (_, args) => findAllDuplicates(args),
    stixDomainEntitiesTimeSeries: (_, args) => stixDomainEntitiesTimeSeries(args),
    stixDomainEntitiesNumber: (_, args) => stixDomainEntitiesNumber(args),
    stixDomainEntitiesExportFiles: (_, { type, first, context }) => filesListing(first, 'export', type, null, context),
  },
  StixDomainEntitiesOrdering: {
    markingDefinitions: `${REL_INDEX_PREFIX}object_marking_refs.definition`,
    tags: `${REL_INDEX_PREFIX}tagged.value`,
  },
  StixDomainEntitiesFilter: {
    createdBy: `${REL_INDEX_PREFIX}created_by_ref.internal_id_key`,
    markingDefinitions: `${REL_INDEX_PREFIX}object_marking_refs.internal_id_key`,
    tags: `${REL_INDEX_PREFIX}tagged.internal_id_key`,
    knowledgeContains: `${REL_INDEX_PREFIX}object_refs.internal_id_key`,
    observablesContains: `${REL_INDEX_PREFIX}observable_refs.internal_id_key`,
    hasExternalReference: `${REL_INDEX_PREFIX}external_references.internal_id_key`,
    indicates: `${REL_INDEX_PREFIX}indicates.internal_id_key`,
  },
  StixDomainEntity: {
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
    stixDomainEntityEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(user, id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationsAdd: ({ input }) => stixDomainEntityAddRelations(user, id, input),
      relationDelete: ({ relationId, toId, relationType }) =>
        stixDomainEntityDeleteRelation(user, id, relationId, toId, relationType),
      importPush: ({ file }) => stixDomainEntityImportPush(user, null, id, file),
      exportAsk: (args) => stixDomainEntityExportAsk(assoc('stixDomainEntityId', id, args)),
      exportPush: ({ file }) => stixDomainEntityExportPush(user, null, id, file),
      mergeEntities: ({ stixDomainEntitiesIds, alias }) => stixDomainEntityMerge(user, id, stixDomainEntitiesIds, alias),
    }),
    stixDomainEntitiesDelete: (_, { id }, { user }) => stixDomainEntitiesDelete(user, id),
    stixDomainEntityAdd: (_, { input }, { user }) => addStixDomainEntity(user, input),
    stixDomainEntitiesExportAsk: (_, args) => stixDomainEntityExportAsk(args),
    stixDomainEntitiesExportPush: (_, { type, file, context, listArgs }, { user }) =>
      stixDomainEntityExportPush(user, type, null, file, context, listArgs),
  },
  Subscription: {
    stixDomainEntity: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
        stixDomainEntityEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          stixDomainEntityCleanContext(user, id);
        });
      },
    },
  },
};

export default stixDomainEntityResolvers;
