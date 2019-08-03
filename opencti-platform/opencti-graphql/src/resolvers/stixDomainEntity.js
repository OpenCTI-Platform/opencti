import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixDomainEntity,
  stixDomainEntityDelete,
  findAll,
  findById,
  findByStixId,
  findByName,
  findByExternalReference,
  markingDefinitions,
  stixDomainEntitiesTimeSeries,
  stixDomainEntitiesNumber,
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation,
  stixDomainEntityRefreshExport,
  stixDomainEntityExportPush,
  exports,
  stixRelations,
  createdByRef
} from '../domain/stixDomainEntity';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../schema/subscriptionWrapper';

const stixDomainEntityResolvers = {
  Query: {
    stixDomainEntity: (_, { id }) => findById(id),
    stixDomainEntities: (_, args) => {
      if (args.stix_id && args.stix_id.length > 0) {
        return findByStixId(args);
      }
      if (args.name && args.name.length > 0) {
        return findByName(args);
      }
      if (args.externalReferenceId && args.externalReferenceId.length > 0) {
        return findByExternalReference(args);
      }
      return findAll(args);
    },
    stixDomainEntitiesTimeSeries: (_, args) =>
      stixDomainEntitiesTimeSeries(args),
    stixDomainEntitiesNumber: (_, args) => stixDomainEntitiesNumber(args)
  },
  StixDomainEntity: {
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-)(\w)/g, (matches, letter) =>
          letter.toUpperCase()
        );
      }
      return 'Unknown';
    },
    createdByRef: (stixDomainEntity, args) =>
      createdByRef(stixDomainEntity.id, args),
    markingDefinitions: (stixDomainEntity, args) =>
      markingDefinitions(stixDomainEntity.id, args),
    stixRelations: (stixDomainEntity, args) =>
      stixRelations(stixDomainEntity.id, args),
    exports: (stixDomainEntity, args) => exports(stixDomainEntity.id, args),
    editContext: stixDomainEntity => fetchEditContext(stixDomainEntity.id)
  },
  Mutation: {
    stixDomainEntityEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId),
      refreshExport: ({ entityType, type }) =>
        stixDomainEntityRefreshExport(id, entityType, type),
      exportPush: ({ exportId, rawData }) =>
        stixDomainEntityExportPush(user, id, exportId, rawData)
    }),
    stixDomainEntityAdd: (_, { input }, { user }) =>
      addStixDomainEntity(user, input)
  },
  Subscription: {
    stixDomainEntity: {
      resolve: payload => payload.instance,
      subscribe: (_, { id }, { user }) => {
        stixDomainEntityEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          stixDomainEntityCleanContext(user, id);
        });
      }
    }
  }
};

export default stixDomainEntityResolvers;
