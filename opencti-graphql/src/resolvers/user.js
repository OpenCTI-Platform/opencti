import { withFilter } from 'graphql-subscriptions';
import { sign } from 'jsonwebtoken';
import conf, { BUS_TOPICS } from '../config/conf';
import {
  addUser,
  addPerson,
  userDelete,
  findAll,
  findById,
  groups,
  userEditContext,
  userEditField,
  userAddRelation,
  userDeleteRelation,
  userCleanContext,
  login,
  logout,
  setAuthenticationCookie
} from '../domain/user';
import { fetchEditContext, pubsub } from '../database/redis';
import { admin, auth, anonymous, withCancel } from './wrapper';

const userResolvers = {
  Query: {
    user: admin((_, { id }) => findById(id)),
    users: admin((_, args) => findAll(args)),
    me: auth((_, args, { user }) => findById(user.id))
  },
  User: {
    groups: (user, args) => groups(user.id, args),
    editContext: admin(user => fetchEditContext(user.id))
  },
  Mutation: {
    token: anonymous((_, { input }, context) =>
      login(input.email, input.password).then(token => {
        setAuthenticationCookie(token, context.res);
        return sign(token, conf.get('app:secret'));
      })
    ),
    logout: auth((_, args, context) => logout(context.user, context.res)),
    userEdit: admin((_, { id }, { user }) => ({
      delete: () => userDelete(id),
      fieldPatch: ({ input }) => userEditField(user, id, input),
      contextPatch: ({ input }) => userEditContext(user, id, input),
      relationAdd: ({ input }) => userAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        userDeleteRelation(user, id, relationId)
    })),
    personAdd: auth((_, { input }, { user }) => addPerson(user, input)),
    userAdd: admin((_, { input }, { user }) => addUser(user, input))
  },
  Subscription: {
    user: {
      resolve: payload => payload.instance,
      subscribe: admin((_, { id }, { user }) => {
        userEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.User.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          userCleanContext(user, id);
        });
      })
    }
  }
};

export default userResolvers;
