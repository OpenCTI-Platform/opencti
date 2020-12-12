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

const groupsLoader = initBatchLoader(batchGroups);
const rolesLoader = initBatchLoader(batchRoles);
const rolesCapabilitiesLoader = initBatchLoader(batchRoleCapabilities);

const userResolvers = {
  Query: {
    user: (_, { id }) => findById(id),
    users: (_, args) => findAll(args),
    role: (_, { id }) => findRoleById(id),
    roles: (_, args) => findRoles(args),
    capabilities: (_, args) => findCapabilities(args),
    me: (_, args, { user }) => findById(user.id),
  },
  User: {
    groups: (user) => groupsLoader.load(user.id),
    roles: (user) => rolesLoader.load(user.id),
    allowed_marking: (user) => getMarkings(user.id),
    capabilities: (user) => getCapabilities(user.id),
    token: (user, args, context) => token(user.id, args, context),
    editContext: (user) => fetchEditContext(user.id),
  },
  Role: {
    editContext: (role) => fetchEditContext(role.id),
    capabilities: (role) => rolesCapabilitiesLoader.load(role.id),
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
        // eslint-disable-next-line no-await-in-loop
        const loginToken = await new Promise((resolve) => {
          passport.authenticate(auth.provider, { session: false }, (err, tokenAuth, info) => {
            if (err || info) logger.warn(`[AUTH] ${auth.provider}`, { error: err, info });
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
