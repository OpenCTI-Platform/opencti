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
  search,
  markingDefinitions,
  stixDomainEntitiesTimeSeries,
  stixDomainEntitiesNumber,
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation,
  stixRelations,
  createdByRef
} from '../domain/stixDomainEntity';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../schema/subscriptionWrapper';

const stixDomainEntityResolvers = {
  Query: {
    stixDomainEntity: (_, { id }) => findById(id),
    stixDomainEntities: (_, args) => {
      if (args.search && args.search.length > 0) {
        return search(args);
      }
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
      if (obj.type) {
        return obj.type.replace(/(?:^|-)(\w)/g, (matches, letter) =>
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
        stixDomainEntityDeleteRelation(user, id, relationId)
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
