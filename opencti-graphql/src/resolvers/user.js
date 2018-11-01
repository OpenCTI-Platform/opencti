import uuid from 'uuid/v4';
import { assoc } from 'ramda';
import { withFilter } from 'graphql-subscriptions';
import { sign } from 'jsonwebtoken';
import conf, { logger, USER_ADDED_TOPIC } from '../config/conf';
import { addUser, deleteUser, findAll, findById, login } from '../domain/user';
import pubsub from '../config/bus';
import { anonymous, admin, auth } from './wrapper';

const userResolvers = {
  Query: {
    users: admin((_, { first, after, orderBy }) =>
      findAll(first, after, orderBy)
    ),
    user: admin((_, { id }) => findById(id)),
    me: auth((_, args, { user }) => findById(user.id))
  },
  Subscription: {
    userAdded: {
      subscribe: admin((_, args, { user }) =>
        withFilter(
          () => pubsub.asyncIterator(USER_ADDED_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            logger.debug(`${USER_ADDED_TOPIC}-user`, user);
            logger.debug(`${USER_ADDED_TOPIC}-payload`, payload);
            return true;
          }
        )(_, args, { user })
      )
    }
  },
  Mutation: {
    token: anonymous((_, { input }) =>
      login(input.username, input.password).then(token =>
        sign(token, conf.get('jwt:secret'))
      )
    ),
    userAdd: admin((_, { input }) => {
      const user = assoc('id', uuid(), input);
      return addUser(user);
    }),
    userDelete: admin((_, { id }) => deleteUser(id))
  }
};

export default userResolvers;
