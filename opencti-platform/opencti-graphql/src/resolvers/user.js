import {
  addPerson,
  addUser,
  findAll,
  findById,
  login,
  logout,
  meEditField,
  setAuthenticationCookie,
  token,
  userDelete,
  userEditField,
  userRenewToken
} from '../domain/user';
import {
  stixDomainEntityAddRelation,
  stixDomainEntityCleanContext,
  stixDomainEntityDeleteRelation,
  stixDomainEntityEditContext
} from '../domain/stixDomainEntity';
import { groups } from '../domain/group';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';

const userResolvers = {
  Query: {
    user: (_, { id }) => findById(id),
    users: (_, args) => findAll(args),
    me: (_, args, { user }) => findById(user.id)
  },
  UsersOrdering: {
    markingDefinitions: `${REL_INDEX_PREFIX}object_marking_refs.definition`,
    tags: `${REL_INDEX_PREFIX}tagged.value`
  },
  UsersFilter: {
    tags: `${REL_INDEX_PREFIX}tagged.internal_id_key`
  },
  User: {
    groups: user => groups(user.id),
    token: (user, args, context) => token(user.id, args, context)
  },
  Mutation: {
    token: (_, { input }, context) =>
      login(input.email, input.password).then(tokenObject => {
        setAuthenticationCookie(tokenObject, context.res);
        return tokenObject.uuid;
      }),
    logout: (_, args, context) => logout(context.user, context.res),
    userEdit: (_, { id }, { user }) => ({
      delete: () => userDelete(id),
      fieldPatch: ({ input }) => userEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      tokenRenew: () => userRenewToken(id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixDomainEntityDeleteRelation(user, id, relationId)
    }),
    meEdit: (_, { input }, { user }) => meEditField(user, user.id, input),
    personAdd: (_, { input }, { user }) => addPerson(user, input),
    userAdd: (_, { input }, { user }) => addUser(user, input)
  }
};

export default userResolvers;
