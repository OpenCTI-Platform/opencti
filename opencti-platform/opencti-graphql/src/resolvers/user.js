import { filter } from 'ramda';
import {
  addPerson,
  addUser,
  findAll,
  findById,
  findCapabilities,
  findRoles,
  findRoleById,
  getCapabilities,
  getRoleCapabilities,
  getRoles,
  logout,
  meEditField,
  removeRole,
  roleRemoveCapability,
  setAuthenticationCookie,
  token,
  roleEditField,
  roleDelete,
  userDelete,
  personDelete,
  userEditField,
  personEditField,
  roleAddRelation,
  userAddRelation,
  personAddRelation,
  userDeleteRelation,
  personDeleteRelation,
  userRenewToken,
  organizations,
  groups,
  roleEditContext,
  roleCleanContext,
} from '../domain/user';
import { logger } from '../config/conf';
import { stixDomainEntityCleanContext, stixDomainEntityEditContext } from '../domain/stixDomainEntity';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import passport, { PROVIDERS } from '../config/providers';
import { AuthenticationFailure } from '../config/errors';
import { addRole } from '../domain/grant';
import { fetchEditContext } from '../database/redis';

const userResolvers = {
  Query: {
    user: (_, { id }) => findById(id, { isUser: true }),
    users: (_, args) => findAll(args, true),
    person: (_, { id }) => findById(id),
    persons: (_, args) => findAll(args),
    role: (_, { id }) => findRoleById(id),
    roles: (_, args) => findRoles(args),
    capabilities: (_, args) => findCapabilities(args),
    me: (_, args, { user }) => findById(user.id, { isUser: true }),
  },
  UsersOrdering: {
    markingDefinitions: `${REL_INDEX_PREFIX}object_marking_refs.definition`,
    tags: `${REL_INDEX_PREFIX}tagged.value`,
  },
  UsersFilter: {
    tags: `${REL_INDEX_PREFIX}tagged.internal_id_key`,
  },
  User: {
    organizations: (user) => organizations(user.id),
    groups: (user) => groups(user.id),
    roles: (user) => getRoles(user.id),
    capabilities: (user) => getCapabilities(user.id),
    token: (user, args, context) => token(user.id, args, context),
  },
  Role: {
    editContext: (role) => fetchEditContext(role.id),
    capabilities: (role) => getRoleCapabilities(role.id),
  },
  Mutation: {
    token: async (_, { input }, context) => {
      // We need to iterate on each provider to find one that validated the credentials
      const formProviders = filter((p) => p.type === 'FORM', PROVIDERS);
      if (formProviders.length === 0) {
        logger.error('[Configuration] Cant authenticate without any form providers');
      }
      for (let index = 0; index < formProviders.length; index += 1) {
        const auth = formProviders[index];
        // eslint-disable-next-line no-await-in-loop
        const loginToken = await new Promise((resolve) => {
          try {
            passport.authenticate(auth.provider, (err, tokenObject) => {
              resolve(tokenObject);
            })({ body: { username: input.email, password: input.password } });
          } catch (e) {
            logger.error(`[Configuration] Cant authenticate with ${auth.provider}`, e);
            resolve(null);
          }
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
    roleEdit: (_, { id }, { user }) => ({
      delete: () => roleDelete(id),
      fieldPatch: ({ input }) => roleEditField(user, id, input),
      contextPatch: ({ input }) => roleEditContext(user, id, input),
      contextClean: () => roleCleanContext(user, id),
      relationAdd: ({ input }) => roleAddRelation(user, id, input),
      removeCapability: ({ name }) => roleRemoveCapability(id, name),
    }),
    roleAdd: (_, { input }) => addRole(input),
    userEdit: (_, { id }, { user }) => ({
      delete: () => userDelete(id),
      fieldPatch: ({ input }) => userEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      tokenRenew: () => userRenewToken(id),
      removeRole: ({ name }) => removeRole(id, name),
      relationAdd: ({ input }) => userAddRelation(user, id, input),
      relationDelete: ({ relationId }) => userDeleteRelation(user, id, relationId),
    }),
    personEdit: (_, { id }, { user }) => ({
      delete: () => personDelete(id),
      fieldPatch: ({ input }) => personEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => personAddRelation(user, id, input),
      relationDelete: ({ relationId }) => personDeleteRelation(user, id, relationId),
    }),
    meEdit: (_, { input }, { user }) => meEditField(user, user.id, input),
    personAdd: (_, { input }, { user }) => addPerson(user, input),
    userAdd: (_, { input }, { user }) => addUser(user, input),
  },
};

export default userResolvers;
