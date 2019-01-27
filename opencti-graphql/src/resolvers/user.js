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
  login,
  logout,
  setAuthenticationCookie
} from '../domain/user';
import {
  createdByRef,
  markingDefinitions,
  reports,
  stixRelations,
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation
} from '../domain/stixDomainEntity';
import { fetchEditContext } from '../database/redis';
import { admin, auth, anonymous } from './wrapper';

const userResolvers = {
  Query: {
    user: auth((_, { id }) => findById(id)),
    users: auth((_, args) => findAll(args)),
    me: auth((_, args, { user }) => findById(user.id))
  },
  User: {
    createdByRef: (user, args) => createdByRef(user.id, args),
    groups: (user, args) => groups(user.id, args),
    token: (user, args) => token(user.id, args),
    markingDefinitions: (user, args) => markingDefinitions(user.id, args),
    reports: (user, args) => reports(user.id, args),
    stixRelations: (user, args) => stixRelations(user.id, args),
    editContext: admin(user => fetchEditContext(user.id))
  },
  Mutation: {
    token: anonymous((_, { input }, context) =>
      login(input.email, input.password).then(tokenObject => {
        setAuthenticationCookie(tokenObject, context.res);
        return sign(tokenObject, conf.get('app:secret'));
      })
    ),
    logout: auth((_, args, context) => logout(context.user, context.res)),
    userEdit: admin((_, { id }, { user }) => ({
      delete: () => userDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    })),
    meEdit: auth((_, { input }, { user }) =>
      stixDomainEntityEditField(user, user.id, input)
    ),
    personAdd: auth((_, { input }, { user }) => addPerson(user, input)),
    userAdd: admin((_, { input }, { user }) => addUser(user, input))
  }
};

export default userResolvers;
