import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixRelation,
  stixRelationDelete,
  findAll,
  getFrom,
  getTo,
  findByType,
  findByToTypeAndType,
  findById,
  search,
  reports,
  markingDefinitions,
  stixRelationEditContext,
  stixRelationEditField,
  stixRelationCleanContext
} from '../domain/stixRelation';
import { fetchEditContext, pubsub } from '../database/redis';
import { auth, withCancel } from './wrapper';

const stixRelationResolvers = {
  Query: {
    stixRelation: auth((_, { id }) => findById(id)),
    stixRelations: auth((_, args) => {
      if (args.search && args.search.length > 0) {
        return search(args);
      }
      if (args.relationType && args.relationType.length > 0) {
        if( args.toType && args.toType.length > 0 ) {
          return findByToTypeAndType(args);
        }
        return findByType(args);
      }
      return findAll(args);
    })
  },
  StixRelation: {
    markingDefinitions: (stixRelation, args) =>
      markingDefinitions(stixRelation.id, args),
    reports: (stixRelation, args) => reports(stixRelation.id, args),
    from: (stixRelation, args) => getFrom(stixRelation.id, args),
    to: (stixRelation, args) => getTo(stixRelation.id, args),
    editContext: auth(stixRelation => fetchEditContext(stixRelation.id))
  },
  Mutation: {
    stixRelationEdit: auth((_, { id }, { user }) => ({
      delete: () => stixRelationDelete(id),
      fieldPatch: ({ input }) => stixRelationEditField(user, id, input),
      contextPatch: ({ input }) => stixRelationEditContext(user, id, input),
    })),
    stixRelationAdd: auth((_, { input }, { user }) => addStixRelation(user, input))
  },
  Subscription: {
    stixRelation: {
      resolve: payload => payload.instance,
      subscribe: auth((_, { id }, { user }) => {
        stixRelationEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.StixRelation.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          stixRelationCleanContext(user, id);
        });
      })
    }
  }
};

export default stixRelationResolvers;
