import {
  addPerson,
  addUser,
  findAll,
  findById,
  logout,
  meEditField,
  setAuthenticationCookie,
  token,
  userDelete,
  userEditField,
  userRenewToken
} from '../domain/user';
import { logger } from '../config/conf';
import {
  stixDomainEntityAddRelation,
  stixDomainEntityCleanContext,
  stixDomainEntityDeleteRelation,
  stixDomainEntityEditContext
} from '../domain/stixDomainEntity';
import { groups } from '../domain/group';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import passport, { FORM_PROVIDERS } from '../config/security';
import { AuthenticationFailure } from '../config/errors';

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
    token: async (_, { input }, context) => {
      // We need to iterate on each provider to find one that validated the credentials
      if (FORM_PROVIDERS.length === 0) {
        logger.error('[Configuration] Cant authenticate without any local providers');
      }
      for (let index = 0; index < FORM_PROVIDERS.length; index += 1) {
        const provider = FORM_PROVIDERS[index];
        // eslint-disable-next-line no-await-in-loop
        const loginToken = await new Promise(resolve => {
          passport.authenticate(provider, (err, tokenObject) => {
            resolve(tokenObject);
          })({ body: { username: input.email, password: input.password } });
        });
        // As soon as credential is validated, set the cookie and return.
        if (loginToken) {
          setAuthenticationCookie(loginToken, context.res);
          return loginToken.uuid;
        }
      }
      // User cannot be authenticated in any providers
      throw new AuthenticationFailure();
    },
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
