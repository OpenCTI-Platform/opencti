import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addAttackPattern,
  attackPatternDelete,
  findAll,
  findById,
  createdByRef,
  markingDefinitions,
  killChainPhases,
  reports,
  attackPatternEditContext,
  attackPatternEditField,
  attackPatternAddRelation,
  attackPatternDeleteRelation,
  attackPatternCleanContext
} from '../domain/attackPattern';
import { fetchEditContext, pubsub } from '../database/redis';
import { auth, withCancel } from './wrapper';

const attackPatternResolvers = {
  Query: {
    attackPattern: auth((_, { id }) => findById(id)),
    attackPatterns: auth((_, args) => findAll(args))
  },
  AttackPattern: {
    createdByRef: (attackPattern, args) => createdByRef(attackPattern.id, args),
    markingDefinitions: (attackPattern, args) =>
      markingDefinitions(attackPattern.id, args),
    killChainPhases: (attackPattern, args) =>
      killChainPhases(attackPattern.id, args),
    reports: (attackPattern, args) => reports(attackPattern.id, args),
    editContext: auth(attackPattern => fetchEditContext(attackPattern.id))
  },
  Mutation: {
    attackPatternEdit: auth((_, { id }, { user }) => ({
      delete: () => attackPatternDelete(id),
      fieldPatch: ({ input }) => attackPatternEditField(user, id, input),
      contextPatch: ({ input }) => attackPatternEditContext(user, id, input),
      relationAdd: ({ input }) => attackPatternAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        attackPatternDeleteRelation(user, id, relationId)
    })),
    attackPatternAdd: auth((_, { input }, { user }) =>
      addAttackPattern(user, input)
    )
  },
  Subscription: {
    attackPattern: {
      resolve: payload => payload.instance,
      subscribe: auth((_, { id }, { user }) => {
        attackPatternEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.AttackPattern.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          attackPatternCleanContext(user, id);
        });
      })
    }
  }
};

export default attackPatternResolvers;
