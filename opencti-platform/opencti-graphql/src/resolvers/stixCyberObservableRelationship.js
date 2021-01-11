import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixCyberObservableRelationship,
  findAll,
  findById,
  stixCyberObservableRelationshipCleanContext,
  stixCyberObservableRelationshipDelete,
  stixCyberObservableRelationshipEditContext,
  stixCyberObservableRelationshipEditField,
} from '../domain/stixCyberObservableRelationship';
import { pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { initBatchLoader } from '../database/middleware';
import { ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP } from '../schema/general';
import { elBatchIds } from '../database/elasticSearch';

const loadByIdLoader = initBatchLoader(elBatchIds);

const stixCyberObservableRelationshipResolvers = {
  Query: {
    stixCyberObservableRelationship: (_, { id }) => findById(id),
    stixCyberObservableRelationships: (_, args) => findAll(args),
    stixCyberObservableRelationshipsOfElement: (_, args) => findAll(args),
  },
  StixCyberObservableRelationship: {
    from: (rel) => loadByIdLoader.load(rel.fromId),
    to: (rel) => loadByIdLoader.load(rel.toId),
  },
  Mutation: {
    stixCyberObservableRelationshipEdit: (_, { id }, { user }) => ({
      delete: () => stixCyberObservableRelationshipDelete(user, id),
      fieldPatch: ({ input }) => stixCyberObservableRelationshipEditField(user, id, input),
      contextPatch: ({ input }) => stixCyberObservableRelationshipEditContext(user, id, input),
      contextClean: () => stixCyberObservableRelationshipCleanContext(user, id),
    }),
    stixCyberObservableRelationshipAdd: (_, { input }, { user }) => addStixCyberObservableRelationship(user, input),
  },
  Subscription: {
    stixCyberObservableRelationship: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
        stixCyberObservableRelationshipEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          stixCyberObservableRelationshipCleanContext(user, id);
        });
      },
    },
  },
};

export default stixCyberObservableRelationshipResolvers;
