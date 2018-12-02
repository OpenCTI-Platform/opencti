import { withFilter } from 'graphql-subscriptions';
import { sign } from 'jsonwebtoken';
import conf, { BUS_TOPICS, logger } from '../config/conf';
import {
  addUser,
  deleteUser,
  findAll,
  findById,
  login,
  setAuthenticationCookie
} from '../domain/user';
import pubsub from '../config/bus';
import { admin, anonymous, auth } from './wrapper';

const userResolvers = {
  Query: {
    users: admin((_, { first, after, orderBy }) =>
      findAll(first, after, orderBy)
    ),
    user: admin((_, { id }) => findById(id)),
    me: auth((_, args, { user }) => findById(user.id))
  },
  Mutation: {
    token: anonymous((_, { input }, context) =>
      login(input.email, input.password).then(token => {
        setAuthenticationCookie(token, context.res);
        return sign(token, conf.get('jwt:secret'));
      })
    ),
    userAdd: admin((_, { input }) => addUser(input)),
    userDelete: admin((_, { id }) => deleteUser(id))
  },
  Subscription: {
    userAdded: {
      subscribe: admin((_, args, { user }) =>
        withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.User.ADDED_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            logger.debug(`${BUS_TOPICS.User.ADDED_TOPIC}-user`, user);
            logger.debug(`${BUS_TOPICS.User.ADDED_TOPIC}-payload`, payload);
            return true;
          }
        )(_, args, { user })
      )
    }
  }
};

export default userResolvers;
