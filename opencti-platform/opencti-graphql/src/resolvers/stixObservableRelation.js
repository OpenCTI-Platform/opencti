import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixObservableRelation,
  stixObservableRelationDelete,
  findAll,
  findByStixId,
  findById,
  findByIdInferred,
  findAllWithInferences,
  search,
  stixObservableRelationEditContext,
  stixObservableRelationCleanContext,
  stixObservableRelationEditField,
  stixObservableRelationAddRelation,
  stixObservableRelationDeleteRelation
} from '../domain/stixObservableRelation';
import { pubsub } from '../database/redis';
import withCancel from '../schema/subscriptionWrapper';
import { loadByGraknId } from '../database/grakn';

const stixObservableRelationResolvers = {
  Query: {
    stixObservableRelation: (_, { id }) => {
      if (id.length !== 36) {
        return findByIdInferred(id);
      }
      return findById(id);
    },
    stixObservableRelations: (_, args) => {
      if (args.search && args.search.length > 0) {
        return search(args);
      }
      if (args.stix_id_key && args.stix_id_key.length > 0) {
        return findByStixId(args);
      }
      if (args.resolveInferences && args.resolveRelationRole && args.resolveRelationType) {
        return findAllWithInferences(args);
      }
      return findAll(args);
    }
  },
  StixObservableRelation: {
    from: rel => loadByGraknId(rel.fromId),
    to: rel => loadByGraknId(rel.toId)
  },
  Mutation: {
    stixObservableRelationEdit: (_, { id }, { user }) => ({
      delete: () => stixObservableRelationDelete(id),
      fieldPatch: ({ input }) => stixObservableRelationEditField(user, id, input),
      contextPatch: ({ input }) => stixObservableRelationEditContext(user, id, input),
      contextClean: () => stixObservableRelationCleanContext(user, id),
      relationAdd: ({ input }) => stixObservableRelationAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixObservableRelationDeleteRelation(user, id, relationId)
    }),
    stixObservableRelationAdd: (_, { input }, { user }) => addStixObservableRelation(user, input)
  },
  Subscription: {
    stixObservableRelation: {
      resolve: payload => payload.instance,
      subscribe: (_, { id }, { user }) => {
        stixObservableRelationEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.StixObservableRelation.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          stixObservableRelationCleanContext(user, id);
        });
      }
    }
  }
};

export default stixObservableRelationResolvers;
