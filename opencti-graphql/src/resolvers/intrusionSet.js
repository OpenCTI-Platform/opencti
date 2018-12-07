import { withFilter } from 'graphql-subscriptions';
import { logger, BUS_TOPICS } from '../config/conf';
import {
  addIntrusionSet,
  deleteIntrusionSet,
  findAll,
  findById,
  findMarkingDef,
  intrusionSetEditContext,
  intrusionSetEditField
} from '../domain/intrusionSet';
import { pubsub } from '../database/redis';
import { admin, auth } from './wrapper';

const intrusionSetResolvers = {
  Query: {
    intrusionSet: auth((_, { id }) => findById(id)),
    intrusionSets: auth((_, args) => findAll(args))
  },
  IntrusionSet: {
    markingDefinitions: (intrusionSet, args) =>
      findMarkingDef(intrusionSet.id, args)
  },
  Mutation: {
    intrusionSetAdd: admin((_, { input }, { user }) =>
      addIntrusionSet(user, input)
    ),
    intrusionSetDelete: admin((_, { id }) => deleteIntrusionSet(id)),
    intrusionSetEditField: admin((_, { input }, { user }) =>
      intrusionSetEditField(user, input)
    ),
    intrusionSetEditContext: admin((_, { input }, { user }) =>
      intrusionSetEditContext(user, input)
    )
  },
  Subscription: {
    intrusionSetEdit: {
      resolve: payload => ({ intrusionSet: payload.data, context: [] }),
      subscribe: admin((_, args, { user }) =>
        withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.IntrusionSet.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            logger.debug(`${BUS_TOPICS.IntrusionSet.EDIT_TOPIC}-user`, user);
            logger.debug(
              `${BUS_TOPICS.IntrusionSet.EDIT_TOPIC}-payload`,
              payload
            );
            return true;
          }
        )(_, args, { user })
      )
    }
  }
};

export default intrusionSetResolvers;
