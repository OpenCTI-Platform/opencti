import uuid from 'uuid/v4';
import { assoc } from 'ramda';
import {
  addUser,
  assertAdmin,
  deleteUser,
  findAll,
  findById,
  USER_ADDED_TOPIC
} from '../domain/user';
import pubsub from '../config/bus';

const delay = (result, delayMs) =>
  new Promise(resolve => {
    setTimeout(() => {
      resolve(result);
    }, delayMs);
  });

// noinspection JSUnusedGlobalSymbols
const userResolvers = {
  Query: {
    users: (_, { first = 25, offset = 0 }, context) => {
      assertAdmin(context.user);
      return findAll(first, offset);
    },
    user: (_, { id }, context) => {
      assertAdmin(context.user);
      return findById(id);
    },
    me: (_, args, context) => findById(context.user.id),
    // Waiting for https://github.com/apollographql/apollo-server/pull/1287
    testDefer: (_, args, context) => ({
      me: findById(context.user.id),
      users: delay(findAll(25, 0), 5000)
    })
  },
  Subscription: {
    userAdded: {
      subscribe: () => pubsub.asyncIterator(USER_ADDED_TOPIC)
    }
  },
  Mutation: {
    addUser: (_, { input }, context) => {
      assertAdmin(context.user);
      const user = assoc('id', uuid(), input);
      return addUser(user);
    },
    deleteUser: (_, { id }) => deleteUser(id)
  }
};

export default userResolvers;
