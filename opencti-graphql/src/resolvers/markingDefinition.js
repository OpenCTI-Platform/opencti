import { withFilter } from 'graphql-subscriptions';
import { logger, BUS_TOPICS } from '../config/conf';
import {
  addMarkingDefinition,
  deleteMarkingDefinition,
  findAll,
  findById,
  markingDefinitionEditContext,
  markingDefinitionEditField
} from '../domain/markingDefinition';
import { pubsub } from '../database/redis';
import { admin, auth } from './wrapper';

const markingDefinitionResolvers = {
  Query: {
    markingDefinition: auth((_, { id }) => findById(id)),
    markingDefinitions: auth((_, { first, after, orderBy, orderMode }) =>
      findAll(first, after, orderBy, orderMode)
    )
  },
  Mutation: {
    markingDefinitionAdd: admin((_, { input }, { user }) =>
      addMarkingDefinition(user, input)
    ),
    markingDefinitionDelete: admin((_, { id }) => deleteMarkingDefinition(id)),
    markingDefinitionEditField: admin((_, { input }, { user }) =>
      markingDefinitionEditField(user, input)
    ),
    markingDefinitionEditContext: admin((_, { input }, { user }) =>
      markingDefinitionEditContext(user, input)
    )
  },
  Subscription: {
    markingDefinitionEdit: {
      resolve: payload => ({ markingDefinition: payload.data, context: [] }),
      subscribe: admin((_, args, { user }) =>
        withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.MarkingDefinition.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            logger.debug(
              `${BUS_TOPICS.MarkingDefinition.EDIT_TOPIC}-user`,
              user
            );
            logger.debug(
              `${BUS_TOPICS.MarkingDefinition.EDIT_TOPIC}-payload`,
              payload
            );
            return true;
          }
        )(_, args, { user })
      )
    }
  }
};

export default markingDefinitionResolvers;
