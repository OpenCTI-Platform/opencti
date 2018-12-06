import { withFilter } from 'graphql-subscriptions';
import { logger, BUS_TOPICS } from '../config/conf';
import {
  addThreatActor,
  deleteThreatActor,
  findAll,
  findById,
  findMarkingDef,
  threatActorEditContext,
  threatActorEditField
} from '../domain/threatActor';
import { pubsub } from '../database/redis';
import { admin, auth } from './wrapper';

const threatActorResolvers = {
  Query: {
    threatActor: auth((_, { id }) => findById(id)),
    threatActors: auth((_, args) => findAll(args))
  },
  ThreatActor: {
    markingDefinitions: (threatActor, args) =>
      findMarkingDef(threatActor.id, args)
  },
  Mutation: {
    threatActorAdd: admin((_, { input }, { user }) =>
      addThreatActor(user, input)
    ),
    threatActorDelete: admin((_, { id }) => deleteThreatActor(id)),
    threatActorEditField: admin((_, { input }, { user }) =>
      threatActorEditField(user, input)
    ),
    threatActorEditContext: admin((_, { input }, { user }) =>
      threatActorEditContext(user, input)
    )
  },
  Subscription: {
    threatActorEdit: {
      resolve: payload => ({ threatActor: payload.data, context: [] }),
      subscribe: admin((_, args, { user }) =>
        withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.ThreatActor.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            logger.debug(`${BUS_TOPICS.ThreatActor.EDIT_TOPIC}-user`, user);
            logger.debug(
              `${BUS_TOPICS.ThreatActor.EDIT_TOPIC}-payload`,
              payload
            );
            return true;
          }
        )(_, args, { user })
      )
    }
  }
};

export default threatActorResolvers;
