import { sign } from 'jsonwebtoken';
import conf from '../config/conf';
import {
  addUser,
  addPerson,
  userDelete,
  findAll,
  findById,
  groups,
  token,
  userEditContext,
  userEditField,
  userAddRelation,
  userDeleteRelation,
  login,
  logout,
  setAuthenticationCookie
} from '../domain/user';
import { fetchEditContext } from '../database/redis';
import { admin, auth, anonymous } from './wrapper';

const userResolvers = {
  Query: {
    user: auth((_, { id }) => findById(id)),
    users: auth((_, args) => findAll(args)),
    me: auth((_, args, { user }) => findById(user.id))
  },
  User: {
    groups: (user, args) => groups(user.id, args),
    token: (user, args) => token(user.id, args),
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
    meEdit: auth((_, { input }, { user }) =>
      userEditField(user, user.id, input)
    ),
    personAdd: auth((_, { input }, { user }) => addPerson(user, input)),
    userAdd: admin((_, { input }, { user }) => addUser(user, input))
  }
};

export default userResolvers;
