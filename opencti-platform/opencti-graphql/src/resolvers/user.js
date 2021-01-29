import { filter } from 'ramda';
import { withFilter } from 'graphql-subscriptions';
import {
  addUser,
  findAll,
  findById,
  findCapabilities,
  findRoles,
  findRoleById,
  getCapabilities,
  batchRoleCapabilities,
  batchRoles,
  logout,
  meEditField,
  setAuthenticationCookie,
  token,
  roleEditField,
  roleDelete,
  userDelete,
  userEditField,
  roleAddRelation,
  roleDeleteRelation,
  userAddRelation,
  userDeleteRelation,
  userRenewToken,
  batchGroups,
  roleEditContext,
  roleCleanContext,
  userEditContext,
  userCleanContext,
  getMarkings,
} from '../domain/user';
import { BUS_TOPICS, logger } from '../config/conf';
import passport, { PROVIDERS } from '../config/providers';
import { AuthenticationFailure } from '../config/errors';
import { addRole } from '../domain/grant';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { ENTITY_TYPE_USER } from '../schema/internalObject';
import { initBatchLoader } from '../database/middleware';

const groupsLoader = (user) => initBatchLoader(user, batchGroups);
const rolesLoader = (user) => initBatchLoader(user, batchRoles);
const rolesCapabilitiesLoader = (user) => initBatchLoader(user, batchRoleCapabilities);

const userResolvers = {
  Query: {
    user: (_, { id }, { user }) => findById(user, id),
    users: (_, args, { user }) => findAll(user, args),
    role: (_, { id }, { user }) => findRoleById(user, id),
    roles: (_, args, { user }) => findRoles(user, args),
    capabilities: (_, args, { user }) => findCapabilities(user, args),
    me: (_, args, { user }) => findById(user, user.id),
  },
  User: {
    groups: (current, _, { user }) => groupsLoader(user).load(current.id),
    roles: (current, _, { user }) => rolesLoader(user).load(current.id),
    allowed_marking: (current, _, { user }) => getMarkings(user, current.id),
    capabilities: (current, _, { user }) => getCapabilities(user, current.id),
    token: (current, _, { user }) => token(user, current.id),
    editContext: (current) => fetchEditContext(current.id),
  },
  Role: {
    editContext: (role) => fetchEditContext(role.id),
    capabilities: (role, _, { user }) => rolesCapabilitiesLoader(user).load(role.id),
  },
  Mutation: {
    token: async (_, { input }, context) => {
      // We need to iterate on each provider to find one that validated the credentials
      const formProviders = filter((p) => p.type === 'FORM', PROVIDERS);
      if (formProviders.length === 0) {
        logger.error('[AUTH] Cant authenticate without any form providers');
      }
      for (let index = 0; index < formProviders.length; index += 1) {
        const auth = formProviders[index];
        const loginToken = await new Promise((resolve) => {
          passport.authenticate(auth.provider, { session: false }, (err, tokenAuth, info) => {
            if (err || info) {
              logger.warn(`[AUTH] ${auth.provider}`, { error: err, info });
            }
            resolve(tokenAuth);
          })({ body: { username: input.email, password: input.password } });
        });
        // As soon as credential is validated, set the cookie and return.
        if (loginToken) {
          setAuthenticationCookie(loginToken, context.res);
          return loginToken.uuid;
        }
      }
      // User cannot be authenticated in any providers
      throw AuthenticationFailure();
    },
    logout: (_, args, context) => logout(context.user, context.res),
    roleEdit: (_, { id }, { user }) => ({
      delete: () => roleDelete(user, id),
      fieldPatch: ({ input }) => roleEditField(user, id, input),
      contextPatch: ({ input }) => roleEditContext(user, id, input),
      contextClean: () => roleCleanContext(user, id),
      relationAdd: ({ input }) => roleAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        roleDeleteRelation(user, id, toId, relationshipType),
    }),
    roleAdd: (_, { input }, { user }) => addRole(user, input),
    userEdit: (_, { id }, { user }) => ({
      delete: () => userDelete(user, id),
      fieldPatch: ({ input }) => userEditField(user, id, input),
      contextPatch: ({ input }) => userEditContext(user, id, input),
      contextClean: () => userCleanContext(user, id),
      tokenRenew: () => userRenewToken(user, id),
      relationAdd: ({ input }) => userAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        userDeleteRelation(user, id, toId, relationshipType),
    }),
    meEdit: (_, { input }, { user }) => meEditField(user, user.id, input),
    userAdd: (_, { input }, { user }) => addUser(user, input),
  },
  Subscription: {
    user: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
        userEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          userCleanContext(user, id);
        });
      },
    },
  },
};

export default userResolvers;
